using System.Text.Json;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.ML;

namespace SecureLog.App;

/// <summary>Шляхи до файлів репозиторію та завантаження даних — спільне для CLI й тестів.</summary>
public static class Workspace
{
    public static readonly string Root = FindRoot();

    public static string PathOf(params string[] parts) => Path.Combine([Root, .. parts]);

    /// <summary>Пароль береться зі змінної середовища; запасне значення — лише для навчальних прогонів.</summary>
    public static string Password => Environment.GetEnvironmentVariable("SECURELOG_PASSWORD") ?? "securelog-demo";

    public static TeamConfig Config() => TeamConfig.Load(PathOf("team_config.json"));

    public static (LogEvent[] Events, int[] Labels) Csv(string name) => EventCodec.ReadCsv(PathOf("data", name));

    public static LogEvent[] Session() => Csv("session.csv").Events;

    public static Mlp? Model() => File.Exists(PathOf("data", "model.json")) ? Mlp.Load(PathOf("data", "model.json")) : null;

    /// <summary>Параметри, знайдені ГА (data/ga_params.json), а якщо ГА ще не запускали — значення з конфігу.</summary>
    public static Params BestParams(TeamConfig cfg)
    {
        string path = PathOf("data", "ga_params.json");
        return File.Exists(path) ? JsonSerializer.Deserialize<Params>(File.ReadAllText(path), TeamConfig.Json)! : cfg.DefaultParams();
    }

    private static string FindRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "SecureLog.slnx"))) return dir.FullName;
        return Directory.GetCurrentDirectory();
    }
}
