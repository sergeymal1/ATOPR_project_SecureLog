using System.Text.Json;

namespace SecureLog.Core;

/// <summary>Параметри, які налаштовує ГА: розмір вікна реплікації, поріг NO_COMPRESSION, коефіцієнт другої копії.</summary>
public sealed record Params(int Window, double MinGain, double SecondCopyFactor);

/// <summary>Вузол сценарію replication.py: місткість, імовірність відмови операції, середня довжина пачки відмов, вага надійності.</summary>
public sealed record NodeConfig(string Name, long CapacityBytes, double FailureProbability, double MeanFailureBurst, double ReliabilityWeight);

/// <summary>Сценарій replication.py: глобальний байтовий бюджет і вузли A, B, C.</summary>
public sealed record Scenario(long GlobalBudgetBytes, NodeConfig[] Nodes);

/// <summary>
/// Виданий викладачем team_config.json (команда T01). Файл не змінюється, тому читається за його власними ключами.
/// Командні параметри, яких у ньому немає (ознаки й шари перцептрона, поріг NO_COMPRESSION), мають значення за замовчуванням.
/// </summary>
public sealed class TeamConfig
{
    /// <summary>Для data/ga_params.json і model.json — власних файлів команди.</summary>
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true,
    };

    /// <summary>Внутрішні назви сценаріїв (CLI, тести, звіт) → ключі сценаріїв у team_config.json.</summary>
    public static readonly IReadOnlyDictionary<string, string> ScenarioKeys = new Dictionary<string, string>
    {
        ["normal"] = "штатний",
        ["degraded"] = "деградований",
        ["emergency"] = "аварійний",
    };

    public string Team { get; init; } = "";
    public int Seed { get; init; }
    public string Password { get; init; } = "";

    public double Alpha { get; init; }
    public double Beta { get; init; }
    public double Gamma { get; init; }
    public double TRef { get; init; }

    // задача реплікації, FORMAT_SPEC_P3 розділ 3.5
    public int ReplicationWindowRecords { get; init; }
    public int MaxBatchBytes { get; init; }
    public int ReplicationBudgetBits { get; init; }
    public double SecondCopyFactor { get; init; }
    public double ThirdCopyFactor { get; init; }
    /// <summary>Відкритий seed replication.py для налагодження; офіційний Q викладач рахує на прихованих seeds.</summary>
    public int ReplicationSeed { get; init; }
    public Dictionary<string, Scenario> Scenarios { get; init; } = [];

    /// <summary>ClassPriority[c] — пріоритет класу c (0 штатна, 1 аномальна, 2 перехід до інциденту).</summary>
    public double[] ClassPriority { get; init; } = [];
    public double CriticalBonus { get; init; }
    /// <summary>Допустима частка невідновлених критичних подій у кожному сценарії.</summary>
    public Dictionary<string, double> CriticalLossMax { get; init; } = [];
    public double TimeLimitS { get; init; }
    public double F1Min { get; init; }

    // командні параметри: у виданому конфігу їх немає
    /// <summary>Ширина ковзного вікна часу для ознак перцептрона, мс.</summary>
    public int HistoryMs { get; init; } = 800;
    public int[] Hidden { get; init; } = [24];
    public double NoCompressionMinGain { get; init; } = 0;

    /// <summary>Параметри без налаштування ГА — прямо з конфігу.</summary>
    public Params DefaultParams() => new(ReplicationWindowRecords, NoCompressionMinGain, SecondCopyFactor);

    public static TeamConfig Load(string path)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        JsonElement root = doc.RootElement, q = root.GetProperty("метрика_Q"), rep = root.GetProperty("реплікація");
        JsonElement scenarios = rep.GetProperty("сценарії"), classifier = root.GetProperty("класифікатор");
        JsonElement classNames = classifier.GetProperty("класи"), priority = root.GetProperty("пріоритети_класів");
        JsonElement lossMax = root.GetProperty("пороги_втрати_критичних_подій");

        return new TeamConfig
        {
            Team = root.GetProperty("команда").GetString()!,
            Seed = root.GetProperty("seed").GetInt32(),
            Password = root.GetProperty("пароль_сеансу").GetString()!,
            Alpha = q.GetProperty("alpha").GetDouble(),
            Beta = q.GetProperty("beta").GetDouble(),
            Gamma = q.GetProperty("gamma").GetDouble(),
            TRef = q.GetProperty("t_ref_секунд").GetDouble(),
            ReplicationWindowRecords = rep.GetProperty("replication_window_records").GetInt32(),
            MaxBatchBytes = rep.GetProperty("max_batch_bytes").GetInt32(),
            ReplicationBudgetBits = rep.GetProperty("replication_budget_bits").GetInt32(),
            SecondCopyFactor = rep.GetProperty("second_copy_factor").GetDouble(),
            ThirdCopyFactor = rep.GetProperty("third_copy_factor").GetDouble(),
            ReplicationSeed = rep.GetProperty("seed_моделі_реплікації").GetInt32(),
            Scenarios = ScenarioKeys.ToDictionary(s => s.Key, s => ReadScenario(scenarios.GetProperty(s.Value))),
            // класи названо словами: "0" → "штатна подія" → пріоритет 1
            ClassPriority = classNames.EnumerateObject().OrderBy(c => int.Parse(c.Name))
                .Select(c => priority.GetProperty(c.Value.GetString()!).GetDouble()).ToArray(),
            CriticalBonus = root.GetProperty("critical_bonus").GetDouble(),
            CriticalLossMax = ScenarioKeys.ToDictionary(s => s.Key, s => lossMax.GetProperty(s.Value).GetDouble()),
            TimeLimitS = root.GetProperty("ліміт_часу_повного_прогону_секунд").GetDouble(),
            F1Min = classifier.GetProperty("F1_min").GetDouble(),
        };
    }

    private static Scenario ReadScenario(JsonElement s) => new(
        s.GetProperty("global_replication_budget_bytes").GetInt64(),
        s.GetProperty("вузли").EnumerateObject().Select(n => new NodeConfig(
            n.Name,
            n.Value.GetProperty("capacity_bytes").GetInt64(),
            n.Value.GetProperty("failure_probability").GetDouble(),
            n.Value.GetProperty("mean_failure_burst").GetDouble(),
            n.Value.GetProperty("reliability_weight").GetDouble())).ToArray());
}
