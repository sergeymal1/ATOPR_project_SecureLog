using System.Diagnostics;
using System.Security.Cryptography;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.DP;
using SecureLog.ML;
using SecureLog.Security;

namespace SecureLog.App;

/// <summary>Перемикачі блоків для експериментів «з блоком / без блоку».</summary>
public sealed record RunOptions(Params P, bool UseMlp = true, bool UseDp = true, int MaxCopies = 3)
{
    /// <summary>Перекладати події з втраченого batch на наступний вузол того самого вікна.</summary>
    public bool Repair { get; init; } = true;

    /// <summary>Отримує кожен екземпляр рюкзака (ваги в бітах, корисності, бюджет) — для порівняння ДП із жадібним.</summary>
    public Action<int[], double[][], int>? OnKnapsack { get; init; }

    /// <summary>Отримує підсумок кожного вікна — для UI.</summary>
    public Action<WindowTrace>? OnWindow { get; init; }
}

/// <summary>
/// Що планувальник зробив з одним вікном. Classes і Copies — по записах вікна; Sent[k] — номери записів вікна,
/// реально відправлені на вузол k (після обрізання хвоста), Bytes[k] — розмір цього batch.
/// </summary>
public sealed record WindowTrace(int Start, int[] Classes, int[] Copies, int Budget, long UsedBits, int[][] Sent, int[] Bytes);

public sealed record RunResult(Quality Quality, long RawBits, long StoredBits, int CriticalTotal, int CriticalRestored,
    int Restored, int Rejected, double Seconds);

/// <summary>Повний прогін: агент журналу → планувальник реплікації → вузли → відновлювач → метрика Q.</summary>
public sealed class Pipeline(TeamConfig cfg, Mlp? model, string password)
{
    public RunResult RunSim(LogEvent[] events, string scenario, long seed, RunOptions options) =>
        Run(events, new Replication(cfg, scenario, seed), options);

    public RunResult Run(LogEvent[] events, IReplication nodes, RunOptions options)
    {
        var timer = Stopwatch.StartNew();
        Send(events, nodes, options);
        // відновлювач — окрема сторона: він знає лише пароль і сам виводить ключі із солі в заголовку
        var replicas = Enumerable.Range(0, nodes.NodeCount).SelectMany(nodes.Read);
        var (restored, rejected) = Restorer.Restore(replicas, new KeyRing(password));
        timer.Stop();

        var restoredSet = restored.ToHashSet();
        int criticalTotal = events.Count(e => e.Critical);
        int criticalRestored = events.Count(e => e.Critical && restoredSet.Contains(e));
        long rawBits = 8L * events.Length * EventCodec.RecordSize, storedBits = 8 * nodes.UsedBytes;
        var quality = Quality.Compute(cfg, rawBits, storedBits, criticalTotal, criticalRestored, timer.Elapsed.TotalSeconds);
        return new(quality, rawBits, storedBits, criticalTotal, criticalRestored, restored.Length, rejected, timer.Elapsed.TotalSeconds);
    }

    private void Send(LogEvent[] events, IReplication nodes, RunOptions options)
    {
        if (events.Length == 0) return;
        int[] classes = Classify(events, options.UseMlp);
        byte[] salt = RandomNumberGenerator.GetBytes(Crypto.SaltSize);   // одна сіль на сесію, nonce — свій у кожної репліки
        Keys keys = Crypto.DeriveKeys(password, salt);

        int nodeCount = nodes.NodeCount, size = Math.Max(1, options.P.Window);
        double[] reliability = Enumerable.Range(0, nodeCount).Select(nodes.Reliability).ToArray();
        // кумулятивні коефіцієнти з розділу 3.5: u(0) = 0, u(1) = v, u(2) = v × second, u(3) = v × third
        double[] factor = new[] { 0, 1, options.P.SecondCopyFactor, cfg.ThirdCopyFactor }[..(Math.Min(Math.Min(options.MaxCopies, 3), nodeCount) + 1)];

        int windows = (events.Length + size - 1) / size;
        uint batchSeq = 0;
        for (int w = 0; w < windows; w++)
        {
            LogEvent[] win = events[(w * size)..Math.Min(events.Length, (w + 1) * size)];
            var (weight, tableBytes) = Weights(win);
            double[] value = win.Select((e, i) => cfg.ClassPriority[classes[w * size + i]] + (e.Critical ? cfg.CriticalBonus : 0)).ToArray();
            double[][] utility = value.Select(v => factor.Select(f => v * f).ToArray()).ToArray();

            // місце в batch у бітах: власна таблиця batch не гірша за таблицю вікна, тому сума ваг плюс цей резерв — верхня межа розміру
            long Limit(int k) => Math.Min(nodes.MaxBatchBytes, nodes.FreeBytes(k));
            long[] room = Enumerable.Range(0, nodeCount).Select(k => 8 * Math.Max(0, Limit(k) - Replica.Overhead - tableBytes)).ToArray();

            // бюджет ДП — replication_budget_bits на replication_window_records записів, тобто пропорційно довжині вікна:
            // зі сталим бюджетом ГА збільшував вікно, на запис припадало менше бітів, і некритичні події відкидались.
            // Якщо глобальний бюджет моделі відмов тісніший, береться рівна частка його залишку, переведена з байтів
            // у «біти Гаффмана» за середнім стисненням вікна
            long share = (nodes.BudgetBytes - nodes.UsedBytes) / (windows - w);
            double ratio = weight.Average() / (8.0 * EventCodec.RecordSize);
            long windowBudget = (long)cfg.ReplicationBudgetBits * win.Length / cfg.ReplicationWindowRecords;
            int budget = (int)Math.Clamp((share - nodeCount * Replica.Overhead) * 8 * ratio, 0, windowBudget);

            options.OnKnapsack?.Invoke(weight, utility, budget);
            int[] copies = options.UseDp ? Knapsack.SolveDp(weight, utility, budget) : Knapsack.SolveGreedy(weight, utility, budget);
            List<int>[] batches = Placement.Assign(copies, weight, value, reliability, room);
            int[][] sent = new int[nodeCount][];
            int[] sentBytes = new int[nodeCount];

            var saved = new bool[win.Length];   // подія вже має збережену копію
            var orphans = new List<int>();      // події з неуспішних batch цього вікна, ще без жодної збереженої копії

            // спершу найнадійніший вузол: якщо частка бюджету скінчиться посеред вікна, без копії залишиться найслабший
            foreach (int k in Enumerable.Range(0, nodeCount).OrderByDescending(k => reliability[k]))
            {
                // replication.py повідомляє про втрату копії (store() → False), тому такі події переходять у batch наступного вузла,
                // де їх ще немає (копії однієї події — лише на різних вузлах). Порядок — за цінністю: обрізається найменш цінний хвіст
                List<int> ids = orphans.Count == 0 ? batches[k]
                    : orphans.Where(i => !saved[i] && !batches[k].Contains(i)).Concat(batches[k]).OrderByDescending(i => value[i]).ToList();
                while (ids.Count > 0)
                {
                    byte[] packet = Replica.Build(keys, salt, (ushort)w, batchSeq, ids.Select(i => win[i]).ToList(), options.P.MinGain);
                    if (packet.Length <= Math.Min(Limit(k), share))
                    {
                        // false буває і після списання (копію втрачено у стані BAD), тому облік — за фактично списаними байтами.
                        // Повторно в тому самому вікні на цей вузол не пишемо: не більше одного batch на вузол
                        long before = nodes.UsedBytes;
                        bool stored = nodes.Write(k, packet);
                        if (nodes.UsedBytes > before)
                        {
                            share -= packet.Length;
                            batchSeq++;
                            sent[k] = ids.ToArray();
                            sentBytes[k] = packet.Length;
                        }
                        foreach (int i in ids)
                            if (stored) saved[i] = true;
                            else if (options.Repair && !orphans.Contains(i)) orphans.Add(i);
                        break;
                    }
                    // не вмістилось у batch або в частку бюджету — відкидаємо найменш цінний хвіст
                    ids.RemoveRange(ids.Count * 9 / 10, ids.Count - ids.Count * 9 / 10);
                }
                sent[k] ??= [];
            }

            options.OnWindow?.Invoke(new(w * size, classes[(w * size)..(w * size + win.Length)], copies, budget,
                Knapsack.Cost(weight, copies), sent, sentBytes));
        }
    }

    private int[] Classify(LogEvent[] events, bool useModel)
    {
        if (!useModel || model is null) return new int[events.Length];   // без перцептрона всі події вважаються штатними
        return Features.Extract(events, cfg.HistoryMs).Select(model.Predict).ToArray();
    }

    /// <summary>
    /// Вага запису за розділом 3.5: w_i = Σ довжин кодів по його 16 байтах, де таблиця Гаффмана одна на все вікно.
    /// Друге значення — розмір цієї таблиці в байтах.
    /// </summary>
    private static (int[] Weight, int TableBytes) Weights(LogEvent[] win)
    {
        byte[] raw = EventCodec.Encode(win);
        var freq = new int[256];
        foreach (byte b in raw) freq[b]++;
        byte[] lengths = Huffman.CodeLengths(freq);

        var weight = new int[win.Length];
        for (int i = 0; i < win.Length; i++)
            for (int j = 0; j < EventCodec.RecordSize; j++)
                weight[i] += lengths[raw[i * EventCodec.RecordSize + j]];
        return (weight, 2 * lengths.Count(l => l > 0));
    }
}
