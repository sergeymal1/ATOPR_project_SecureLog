using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SecureLog.Core;

namespace SecureLog.DP;

/// <summary>
/// Порт виданого replication.py (лежить у корені репозиторію) рядок у рядок. Змінювати модель не можна,
/// тому тут немає жодної власної логіки: ті самі перевірки бюджету, ті самі ланцюги GOOD/BAD і той самий генератор
/// Python (PyRandom), тож за однакового seed послідовність відмов збігається з оригіналом (перевіряє юніт-тест).
/// Розмір batch модель не обмежує — max_batch_bytes дотримується планувальник.
/// </summary>
public sealed class Replication : IReplication
{
    private readonly Node[] _nodes;

    public Replication(TeamConfig cfg, string scenario, long seed)
    {
        Scenario sc = cfg.Scenarios[scenario];
        BudgetBytes = sc.GlobalBudgetBytes;
        MaxBatchBytes = cfg.MaxBatchBytes;
        _nodes = sc.Nodes.Select(n => new Node(n, seed)).ToArray();
    }

    public int NodeCount => _nodes.Length;
    public int MaxBatchBytes { get; }
    public long BudgetBytes { get; }
    public long UsedBytes { get; private set; }

    /// <summary>global_rejected: операції, відхилені до списання байтів.</summary>
    public int Rejected { get; private set; }

    public string Name(int node) => _nodes[node].Cfg.Name;

    public double Reliability(int node) => _nodes[node].Cfg.ReliabilityWeight;

    /// <summary>Місткість вузла мінус усі списані спроби, включно з втраченими у стані BAD.</summary>
    public long FreeBytes(int node) => _nodes[node].Cfg.CapacityBytes - _nodes[node].Used;

    public IReadOnlyList<byte[]> Read(int node) => _nodes[node].Blobs;

    /// <summary>
    /// store(): false — або відхилено через бюджет чи місткість (байти не списуються),
    /// або копію втрачено у стані BAD (байти списуються). True — копію збережено.
    /// </summary>
    public bool Write(int node, byte[] batch)
    {
        Node nd = _nodes[node];
        int size = batch.Length;
        if (UsedBytes + size > BudgetBytes || nd.Used + size > nd.Cfg.CapacityBytes)
        {
            nd.Rejected++;
            Rejected++;
            return false;
        }
        nd.Used += size;
        UsedBytes += size;
        nd.Attempts++;
        if (nd.NextIsBad())
        {
            nd.Failed++;
            return false;
        }
        nd.Stored++;
        nd.Blobs.Add((byte[])batch.Clone());
        return true;
    }

    /// <summary>_node_seed: перші 8 байтів SHA-256 від рядка "seed:вузол" як беззнакове ціле big-endian.</summary>
    public static ulong NodeSeed(long seed, string node) =>
        BinaryPrimitives.ReadUInt64BigEndian(SHA256.HashData(Encoding.UTF8.GetBytes(string.Create(CultureInfo.InvariantCulture, $"{seed}:{node}"))));

    /// <summary>Двостанний процес GOOD/BAD одного вузла з власним генератором.</summary>
    private sealed class Node(NodeConfig cfg, long seed)
    {
        private readonly PyRandom _rng = new(NodeSeed(seed, cfg.Name));
        // p_gb = loss / (loss + B·(1 − loss)): тоді в середньому частка невдалих операцій дорівнює loss
        private readonly double _pGoodToBad = cfg.FailureProbability > 0
            ? cfg.FailureProbability / (cfg.FailureProbability + cfg.MeanFailureBurst * (1.0 - cfg.FailureProbability))
            : 0.0;
        private int _inBurst;

        public NodeConfig Cfg { get; } = cfg;
        public long Used;
        public int Attempts, Stored, Failed, Rejected;
        public readonly List<byte[]> Blobs = [];

        /// <summary>Перехід у BAD означає, що саме поточна операція — перша невдала; довжина пачки геометрична із середнім B.</summary>
        public bool NextIsBad()
        {
            if (_inBurst > 0)
            {
                _inBurst--;
                return true;
            }
            if (Cfg.FailureProbability > 0 && _rng.NextDouble() < _pGoodToBad)
            {
                int length = 1;
                if (Cfg.MeanFailureBurst > 1.0)
                    while (_rng.NextDouble() > 1.0 / Cfg.MeanFailureBurst) length++;
                _inBurst = length - 1;
                return true;
            }
            return false;
        }
    }
}

/// <summary>
/// random.Random з Python: вихор Мерсенна MT19937, посів цілим числом через init_by_array
/// і random() з 53 бітів двох 32-бітних чисел. Потрібен лише для того, щоб відмови збігалися з replication.py.
/// </summary>
public sealed class PyRandom
{
    private const int N = 624, M = 397;
    private readonly uint[] _mt = new uint[N];
    private int _index = N;

    public PyRandom(ulong seed)
    {
        // Python ділить ціле на 32-бітні слова від молодшого; нуль — одне слово
        uint[] key = seed >> 32 == 0 ? [(uint)seed] : [(uint)seed, (uint)(seed >> 32)];

        _mt[0] = 19650218u;
        for (int n = 1; n < N; n++) _mt[n] = 1812433253u * (_mt[n - 1] ^ (_mt[n - 1] >> 30)) + (uint)n;

        int i = 1, j = 0;
        for (int k = Math.Max(N, key.Length); k > 0; k--)
        {
            _mt[i] = (_mt[i] ^ ((_mt[i - 1] ^ (_mt[i - 1] >> 30)) * 1664525u)) + key[j] + (uint)j;
            i++;
            j++;
            if (i >= N)
            {
                _mt[0] = _mt[N - 1];
                i = 1;
            }
            if (j >= key.Length) j = 0;
        }
        for (int k = N - 1; k > 0; k--)
        {
            _mt[i] = (_mt[i] ^ ((_mt[i - 1] ^ (_mt[i - 1] >> 30)) * 1566083941u)) - (uint)i;
            i++;
            if (i >= N)
            {
                _mt[0] = _mt[N - 1];
                i = 1;
            }
        }
        _mt[0] = 0x80000000u;
    }

    public uint NextUInt32()
    {
        if (_index >= N)
        {
            for (int k = 0; k < N; k++)
            {
                uint y = (_mt[k] & 0x80000000u) | (_mt[(k + 1) % N] & 0x7fffffffu);
                _mt[k] = _mt[(k + M) % N] ^ (y >> 1) ^ ((y & 1) != 0 ? 0x9908b0dfu : 0u);
            }
            _index = 0;
        }
        uint x = _mt[_index++];
        x ^= x >> 11;
        x ^= (x << 7) & 0x9d2c5680u;
        x ^= (x << 15) & 0xefc60000u;
        x ^= x >> 18;
        return x;
    }

    /// <summary>random.random(): число з [0, 1) із 53 випадковими бітами.</summary>
    public double NextDouble()
    {
        uint a = NextUInt32() >> 5, b = NextUInt32() >> 6;
        return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0);
    }
}
