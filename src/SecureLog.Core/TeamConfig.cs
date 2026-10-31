using System.Text.Json;

namespace SecureLog.Core;

/// <summary>Параметри, які налаштовує ГА: розмір вікна реплікації, поріг NO_COMPRESSION, коефіцієнт другої копії.</summary>
public sealed record Params(int Window, double MinGain, double SecondCopyFactor);

/// <summary>Сценарій моделі відмов: глобальний бюджет як частка сирого журналу, частка втрачених записів, середня довжина пачки втрат.</summary>
public sealed record Scenario(double BudgetFactor, double Loss, double Burst);

/// <summary>team_config.json. Значення за замовчуванням збігаються з файлом у корені репозиторію.</summary>
public sealed class TeamConfig
{
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true,
    };

    public int HistoryWindow { get; init; } = 16;
    public int[] Hidden { get; init; } = [24];
    public double F1Min { get; init; } = 0.8;

    // задача реплікації, FORMAT_SPEC_P3 розділ 3.5
    public int ReplicationWindowRecords { get; init; } = 48;
    public int MaxBatchBytes { get; init; } = 1024;
    public int ReplicationBudgetBits { get; init; } = 5000;
    public double[] ClassPriority { get; init; } = [1, 3, 6];
    public double CriticalBonus { get; init; } = 20;
    public double SecondCopyFactor { get; init; } = 1.55;
    public double ThirdCopyFactor { get; init; } = 1.85;
    public double NoCompressionMinGain { get; init; } = 0;

    public double Alpha { get; init; } = 0.2;
    public double Beta { get; init; } = 0.7;
    public double Gamma { get; init; } = 0.1;
    public double TRef { get; init; } = 2;
    public double DegradedLossMax { get; init; } = 0.1;
    public double TimeLimitS { get; init; } = 30;

    public double[] NodeReliability { get; init; } = [0.95, 0.90, 0.80];
    public Dictionary<string, Scenario> Scenarios { get; init; } = new()
    {
        ["normal"] = new(2.0, 0, 1),
        ["degraded"] = new(1.2, 0.03, 1),
        ["emergency"] = new(0.7, 0.15, 3),
    };

    /// <summary>Параметри без налаштування ГА — прямо з конфігу.</summary>
    public Params DefaultParams() => new(ReplicationWindowRecords, NoCompressionMinGain, SecondCopyFactor);

    public static TeamConfig Load(string path) =>
        JsonSerializer.Deserialize<TeamConfig>(File.ReadAllText(path), Json)
        ?? throw new InvalidDataException($"порожній конфіг: {path}");
}
