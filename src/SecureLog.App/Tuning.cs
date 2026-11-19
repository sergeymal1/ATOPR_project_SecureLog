using System.Globalization;
using System.Text.Json;
using SecureLog.Core;
using SecureLog.ML;

namespace SecureLog.App;

/// <summary>ГА налаштовує три параметри системи; пристосованість — середній Q за трьома сценаріями.</summary>
public static class Tuning
{
    public static readonly string[] Scenarios = ["normal", "degraded", "emergency"];
    // не перетинаються із seeds, на яких система оцінюється (тести — 427243 і 1–5, звіт — 21–40): так видно, чи узагальнюються параметри
    private static readonly int[] FitnessSeeds = [11, 12, 13, 14, 15, 16, 17, 18];

    /// <summary>
    /// Хромосома — три гени в [0, 1]: розмір вікна (логарифмічна шкала 16..256 записів), поріг NO_COMPRESSION (0..0.3),
    /// коефіцієнт другої копії (від 1 до third_copy_factor, щоб третя копія не стала гіршою за другу).
    /// </summary>
    public static Params Decode(double[] genes, TeamConfig cfg) =>
        new((int)Math.Round(16 * Math.Pow(16, genes[0])), 0.3 * genes[1], 1 + genes[2] * (cfg.ThirdCopyFactor - 1));

    /// <summary>
    /// Середній Q за сценаріями і вісьмома seeds: на малій кількості ГА підганяє розмір вікна під випадковий перебіг відмов.
    /// Прогони незалежні, тому рахуються паралельно.
    /// </summary>
    public static double Fitness(Pipeline pipeline, TeamConfig cfg, LogEvent[] events, Params p)
    {
        var runs = Scenarios.SelectMany(s => FitnessSeeds.Select(seed => (Scenario: s, Seed: seed))).AsParallel()
            .Select(x => (x.Scenario, Result: pipeline.RunSim(events, x.Scenario, x.Seed, new RunOptions(p)))).ToArray();

        // пороги втрати критичних подій з team_config.json (штатний 0, деградований 0.1, аварійний 0.45) — жорсткі умови,
        // а не доданок Q: кожен прогін, що їх порушує, знімає 1. Без них ГА збільшує вікно до ~250 записів —
        // Q росте, бо batch упирається в max_batch_bytes і некритичні події не зберігаються, але тоді на вузол іде
        // лише 5 batch, і одна пачка відмов забирає чверть журналу
        int violations = runs.Count(r => 1 - r.Result.Quality.R > cfg.CriticalLossMax[r.Scenario] + 1e-12);
        return runs.Average(r => r.Result.Quality.Q) - violations;
    }

    public static double[] Create(Random rng) => [rng.NextDouble(), rng.NextDouble(), rng.NextDouble()];

    /// <summary>Арифметичний кросовер: кожен ген дитини лежить між генами батьків.</summary>
    public static double[] Crossover(double[] a, double[] b, Random rng) =>
        a.Select((x, i) => x + rng.NextDouble() * (b[i] - x)).ToArray();

    /// <summary>Мутація: кожен ген з імовірністю 0.3 зсувається на нормально розподілену величину.</summary>
    public static double[] Mutate(double[] genes, Random rng) =>
        genes.Select(x => rng.NextDouble() < 0.3 ? Math.Clamp(x + 0.15 * Gauss(rng), 0, 1) : x).ToArray();

    /// <summary>Запускає ГА і випадковий пошук з однаковим числом обчислень; пише журнал збіжності та найкращі параметри.</summary>
    public static void Run(Pipeline pipeline, TeamConfig cfg, LogEvent[] events, int population = 12, int generations = 10)
    {
        double Fit(double[] g) => Fitness(pipeline, cfg, events, Decode(g, cfg));
        var ga = Ga.Run(Create, Crossover, Mutate, Fit, new Random(1), population, generations);
        var random = Ga.RandomSearch(Create, Fit, new Random(1), population, generations);

        var inv = CultureInfo.InvariantCulture;
        var log = new List<string> { "generation,ga_best_q,random_best_q" };
        for (int g = 0; g < ga.History.Count; g++)
            log.Add(string.Create(inv, $"{g},{ga.History[g]:F5},{random.History[g]:F5}"));
        Directory.CreateDirectory(Workspace.PathOf("docs", "results"));
        File.WriteAllLines(Workspace.PathOf("docs", "results", "ga_log.csv"), log);

        Params best = Decode(ga.Best, cfg);
        File.WriteAllText(Workspace.PathOf("data", "ga_params.json"), JsonSerializer.Serialize(best, TeamConfig.Json));
        Console.WriteLine($"ГА:               Q = {ga.Fitness:F4} за {ga.Evaluations} обчислень, {best}");
        Console.WriteLine($"випадковий пошук: Q = {random.Fitness:F4} за {random.Evaluations} обчислень, {Decode(random.Best, cfg)}");
        Console.WriteLine("журнал збіжності: docs/results/ga_log.csv; параметри: data/ga_params.json");
    }

    private static double Gauss(Random rng) =>
        Math.Sqrt(-2 * Math.Log(1 - rng.NextDouble())) * Math.Cos(2 * Math.PI * rng.NextDouble());
}
