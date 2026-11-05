using SecureLog.Core;

namespace SecureLog.DP;

/// <summary>
/// Власна модель вузлів і відмов: replication.py, на який посилається завдання, команді не видано.
/// Втрати повторюють модель із виданого CHANNEL_SPEC: двостанний ланцюг Маркова з одним кроком на кожен записаний пакет,
/// окремий для кожного вузла; пакет втрачається цілком, і той, на якому стався перехід у BAD, сам є першим втраченим у пачці.
/// </summary>
public sealed class SimReplication : IReplication
{
    private const double NodeCapacityShare = 0.5;   // місткість одного вузла як частка глобального бюджету

    private readonly double[] _reliability;
    private readonly double[] _pGoodToBad;
    private readonly double _burst;
    private readonly Random[] _rng;
    private readonly int[] _burstLeft;
    private readonly long[] _free;
    private readonly List<byte[]>[] _stored;

    public SimReplication(TeamConfig cfg, string scenario, long rawBytes, int seed)
    {
        Scenario sc = cfg.Scenarios[scenario];
        _reliability = cfg.NodeReliability;
        _burst = sc.Burst;
        // свій генератор у кожного вузла: перебіг втрат на вузлі не залежить від того, скільки писали на інші,
        // тому різні налаштування системи порівнюються на тому самому сценарії відмов
        _rng = _reliability.Select((_, k) => new Random(seed * 1000 + k)).ToArray();
        MaxBatchBytes = cfg.MaxBatchBytes;
        BudgetBytes = (long)(sc.BudgetFactor * rawBytes);

        // менш надійний вузол втрачає пропорційно частіше; у середньому по вузлах частка втрат дорівнює sc.Loss
        double meanUnreliability = _reliability.Average(r => 1 - r);
        _pGoodToBad = _reliability.Select(r =>
        {
            double loss = Math.Min(0.9, sc.Loss * (1 - r) / meanUnreliability);
            // частка втрат за цикл = B / (B + (1 − p)/p), звідси p; перехід у BAD відбувається на записі, який теж втрачається
            return loss / (loss + _burst * (1 - loss));
        }).ToArray();

        _burstLeft = new int[NodeCount];
        _free = Enumerable.Repeat((long)(BudgetBytes * NodeCapacityShare), NodeCount).ToArray();
        _stored = Enumerable.Range(0, NodeCount).Select(_ => new List<byte[]>()).ToArray();
    }

    public int NodeCount => _reliability.Length;
    public int MaxBatchBytes { get; }
    public long BudgetBytes { get; }
    public long UsedBytes { get; private set; }

    public double Reliability(int node) => _reliability[node];

    public long FreeBytes(int node) => _free[node];

    public bool Write(int node, byte[] batch)
    {
        if (batch.Length > MaxBatchBytes || batch.Length > _free[node] || UsedBytes + batch.Length > BudgetBytes) return false;
        UsedBytes += batch.Length;   // ресурс списано, навіть якщо запис буде втрачено

        bool lost;
        if (_burstLeft[node] > 0)
        {
            _burstLeft[node]--;
            lost = true;
        }
        else if (_rng[node].NextDouble() < _pGoodToBad[node])
        {
            int length = 1;   // довжина пачки — геометрична із середнім Burst
            while (_burst > 1 && _rng[node].NextDouble() > 1 / _burst) length++;
            _burstLeft[node] = length - 1;
            lost = true;
        }
        else
        {
            lost = false;
        }

        if (lost) return true;   // відправник про втрату не дізнається
        _free[node] -= batch.Length;
        _stored[node].Add(batch);
        return true;
    }

    public IReadOnlyList<byte[]> Read(int node) => _stored[node];
}
