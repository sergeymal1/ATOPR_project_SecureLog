using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.DP;
using SecureLog.Security;

namespace SecureLog.App;

/// <summary>Шість обов'язкових таблиць звіту.</summary>
public static class Report
{
    // 20 seeds, які не перетинаються з seeds налаштування ГА (11–18): на п'яти різниця між варіантами тоне в шумі втрат
    private static readonly int[] Seeds = Enumerable.Range(21, 20).ToArray();

    public static void Write(TeamConfig cfg, Pipeline pipeline, LogEvent[] events)
    {
        Params tuned = Workspace.BestParams(cfg);
        var full = new RunOptions(tuned);
        var md = new StringBuilder("# Таблиці експериментів\n\n");
        md.Append($"Журнал: {events.Length} подій, критичних {events.Count(e => e.Critical)}. Параметри системи: {tuned}. ");
        md.Append($"Q = {cfg.Alpha}·S + {cfg.Beta}·R + {cfg.Gamma}·T, середнє за {Seeds.Length} seeds моделі відмов ({Seeds[0]}–{Seeds[^1]}).\n\n");

        md.Append("## 1. ДП проти жадібного\n\n| сценарій | екземплярів | корисність ДП | корисність жадібного | біти ДП | біти жадібного | час ДП, мс | час жадібного, мс |\n|---|---|---|---|---|---|---|---|\n");
        foreach (string scenario in Tuning.Scenarios)
        {
            var instances = new List<(int[] Cost, double[][] Utility, int Budget)>();
            pipeline.RunSim(events, scenario, 1, full with { OnKnapsack = (c, u, b) => instances.Add((c, u, b)) });
            var dp = Solve(instances, Knapsack.SolveDp);
            var greedy = Solve(instances, Knapsack.SolveGreedy);
            md.Append($"| {scenario} | {instances.Count} | {dp.Utility:F1} | {greedy.Utility:F1} | {dp.Bits} | {greedy.Bits} | {dp.Ms:F1} | {greedy.Ms:F1} |\n");
            if (scenario != "emergency") continue;

            // мікрозміна умови із захисту: ті самі вікна, але бюджет менший на 30 %
            var tight = instances.Select(x => (x.Cost, x.Utility, (int)(x.Budget * 0.7))).ToList();
            dp = Solve(tight, Knapsack.SolveDp);
            greedy = Solve(tight, Knapsack.SolveGreedy);
            md.Append($"| emergency, бюджет −30 % | {tight.Count} | {dp.Utility:F1} | {greedy.Utility:F1} | {dp.Bits} | {greedy.Bits} | {dp.Ms:F1} | {greedy.Ms:F1} |\n");
        }

        md.Append("\n## 2. Вплив кількості копій\n\n| сценарій | макс. копій | S | R | Q | збережено, кбіт |\n|---|---|---|---|---|---|\n");
        foreach (string scenario in Tuning.Scenarios)
            for (int copies = 1; copies <= 3; copies++)
            {
                var m = Mean(pipeline, events, scenario, full with { MaxCopies = copies });
                md.Append($"| {scenario} | {copies} | {m.S:F3} | {m.R:F3} | {m.Q:F3} | {m.StoredBits / 1000:F0} |\n");
            }

        md.Append("\n## 3. Вплив блоків (Q)\n\n| конфігурація | normal | degraded | emergency | середнє |\n|---|---|---|---|---|\n");
        var variants = new (string Name, RunOptions Options)[]
        {
            ("без перцептрона", full with { UseMlp = false }),
            ("без ДП (жадібний вибір копій)", full with { UseDp = false }),
            ("без ГА (параметри з team_config.json)", new RunOptions(cfg.DefaultParams())),
            ("повна система", full),
        };
        foreach (var (name, options) in variants)
        {
            double[] q = Tuning.Scenarios.Select(s => Mean(pipeline, events, s, options).Q).ToArray();
            md.Append($"| {name} | {q[0]:F4} | {q[1]:F4} | {q[2]:F4} | {q.Average():F4} |\n");
        }

        byte[] raw = EventCodec.Encode(events);
        byte[] encrypted = Crypto.AesCtr(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(Crypto.NonceSize), raw);
        md.Append("\n## 4. Стиснення до і після шифрування\n\n| порядок | вхід, байт | Гаффман примусово, байт | обране навантаження, байт | обраний режим |\n|---|---|---|---|---|\n");
        foreach (var (name, bytes) in new[] { ("стиснути → зашифрувати", raw), ("зашифрувати → стиснути", encrypted) })
        {
            byte[] chosen = Payload.Pack(bytes);
            string mode = (chosen[2] & Payload.NoCompression) != 0 ? "NO_COMPRESSION" : "Гаффман";
            md.Append($"| {name} | {bytes.Length} | {Payload.Pack(bytes, -10).Length} | {chosen.Length} | {mode} |\n");
        }

        md.Append("\n## 5. Поведінка у трьох сценаріях\n\n| сценарій | S | R | T | Q | використано бюджету, % | відновлено подій | відхилено реплік |\n|---|---|---|---|---|---|---|---|\n");
        foreach (string scenario in Tuning.Scenarios)
        {
            var m = Mean(pipeline, events, scenario, full);
            double budgetBits = 8 * cfg.Scenarios[scenario].BudgetFactor * raw.Length;
            md.Append($"| {scenario} | {m.S:F3} | {m.R:F3} | {m.T:F3} | {m.Q:F3} | {100 * m.StoredBits / budgetBits:F0} | {m.Restored:F0} | {m.Rejected:F0} |\n");
        }

        md.Append("\n## 6. Збіжність ГА проти випадкового пошуку\n\n");
        string gaLog = Workspace.PathOf("docs", "results", "ga_log.csv");
        if (File.Exists(gaLog))
        {
            md.Append("| покоління | найкращий Q, ГА | найкращий Q, випадковий пошук |\n|---|---|---|\n");
            foreach (string line in File.ReadLines(gaLog).Skip(1)) md.Append($"| {line.Replace(",", " | ")} |\n");
        }
        else
        {
            md.Append("Журнал ГА відсутній: спершу запустіть команду `ga`.\n");
        }

        Directory.CreateDirectory(Workspace.PathOf("docs", "results"));
        File.WriteAllText(Workspace.PathOf("docs", "results", "tables.md"), md.ToString());
        Console.WriteLine(md);
    }

    private static (double S, double R, double T, double Q, double StoredBits, double Restored, double Rejected) Mean(
        Pipeline pipeline, LogEvent[] events, string scenario, RunOptions options)
    {
        var runs = Seeds.Select(seed => pipeline.RunSim(events, scenario, seed, options)).ToArray();
        return (runs.Average(r => r.Quality.S), runs.Average(r => r.Quality.R), runs.Average(r => r.Quality.T), runs.Average(r => r.Quality.Q),
            runs.Average(r => r.StoredBits), runs.Average(r => r.Restored), runs.Average(r => r.Rejected));
    }

    private static (double Utility, long Bits, double Ms) Solve(
        List<(int[] Cost, double[][] Utility, int Budget)> instances, Func<int[], double[][], int, int[]> solver)
    {
        double utility = 0;
        long bits = 0;
        var timer = Stopwatch.StartNew();
        foreach (var (cost, u, budget) in instances)
        {
            int[] copies = solver(cost, u, budget);
            utility += Knapsack.Utility(u, copies);
            bits += Knapsack.Cost(cost, copies);
        }
        return (utility, bits, timer.Elapsed.TotalMilliseconds);
    }
}
