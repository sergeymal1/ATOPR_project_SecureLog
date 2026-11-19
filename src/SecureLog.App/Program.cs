using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SecureLog.App;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.ML;
using SecureLog.Security;

Console.OutputEncoding = Encoding.UTF8;
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;   // десяткова крапка у всіх таблицях і CSV

TeamConfig cfg = Workspace.Config();
string password = Option("--password") ?? Workspace.Password;
try
{
    Dispatch();
}
catch (ReplicaException e)
{
    // зіпсований чи чужий файл — очікувана ситуація, а не аварія: код із розділу 5 і код виходу 1
    Console.Error.WriteLine($"ВІДХИЛЕНО {e.Code}: {e.Detail}. Вихідний файл не записано.");
    Environment.ExitCode = 1;
}
catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or FormatException or ArgumentException)
{
    Console.Error.WriteLine($"помилка: {e.Message}");
    Environment.ExitCode = 2;
}

void Dispatch()
{
switch (args.FirstOrDefault())
{
    case "pack":
        PackFile();
        break;
    case "unpack":
        UnpackFile();
        break;
    case "check":
        CheckReference();
        break;
    case "train":
        Train();
        break;
    case "run":
        foreach (string scenario in args.Length > 1 ? [KnownScenario(args[1])] : Tuning.Scenarios)
        {
            var r = NewPipeline().RunSim(Workspace.Session(), scenario, args.Length > 2 ? long.Parse(args[2]) : cfg.ReplicationSeed, new RunOptions(Workspace.BestParams(cfg)));
            Console.WriteLine($"{scenario,-10} S={r.Quality.S:F3} R={r.Quality.R:F3} T={r.Quality.T:F3} Q={r.Quality.Q:F4} | критичних {r.CriticalRestored}/{r.CriticalTotal}, подій відновлено {r.Restored}, збережено {r.StoredBits / 8} байт, {r.Seconds:F2} с");
        }
        break;
    case "ga":
        Tuning.Run(NewPipeline(), cfg, Workspace.Session());
        break;
    case "attack":
        AttackDemo();
        break;
    case "report":
        Report.Write(cfg, NewPipeline(), Workspace.Session());
        break;
    default:
        Console.WriteLine("""
            SecureLog — пріоритетна реплікація журналів подій
              pack <вхід> <репліка> [--raw]   записи (.bin по 16 байтів або .csv) → файл реплік LOG3; --raw — NO_COMPRESSION
              unpack <репліка> <вихід>        файл реплік LOG3 → записи (.bin побайтово або .csv); помилка — код E_*
              check [каталог]                 звірити еталонні пакети викладача (типово reference/)
                                              pack, unpack, check: --password <пароль>, типово пароль сеансу з team_config.json
              train                           навчити перцептрон (3 ініціалізації), зберегти data/model.json
              run [сценарій] [seed]           повний прогін: normal | degraded | emergency (без аргументів — усі три; seed — відкритий із конфігу)
              ga                              ГА проти випадкового пошуку, зберегти data/ga_params.json
              attack                          атака ГА на слабкий шифр і перевірка цілісності репліки
              report                          таблиці експериментів у docs/results/tables.md
            """);
        break;
}
}

// --password <значення>; позиційні аргументи — усе інше після назви команди
string? Option(string name)
{
    int i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

string[] Positional() =>
    args.Skip(1).Where((a, i) => !a.StartsWith("--") && (i == 0 || args[i] != "--password")).ToArray();

(string In, string Out) TwoPaths(string command)
{
    string[] p = Positional();
    if (p.Length != 2) throw new ArgumentException($"потрібно два шляхи: {command} <вхід> <вихід>");
    return (p[0], p[1]);
}

void PackFile()
{
    var (input, output) = TwoPaths("pack");
    byte[] records = ReplicaFile.ReadRecords(input);
    byte[] file = ReplicaFile.Pack(records, password, args.Contains("--raw"));
    File.WriteAllBytes(output, file);
    int count = records.Length / EventCodec.RecordSize;
    Console.WriteLine($"{input}: {count} записів ({records.Length} байтів) → {output}: {file.Length} байтів, реплік {Math.Max(1, (count + ReplicaFile.MaxRecords - 1) / ReplicaFile.MaxRecords)}");
}

void UnpackFile()
{
    var (input, output) = TwoPaths("unpack");
    var (records, parts) = ReplicaFile.Unpack(File.ReadAllBytes(input), password);
    ReplicaFile.WriteRecords(output, records);
    string modes = string.Join(", ", parts.Select(p => (p.Compressed ? "Гаффман" : "NO_COMPRESSION") + (p.HasClassTable ? " + class_table" : "")).Distinct());
    Console.WriteLine($"OK: реплік {parts.Count} ({modes}), записів {records.Length / EventCodec.RecordSize} ({records.Length} байтів) → {output}");
}

Pipeline NewPipeline()
{
    Mlp? model = Workspace.Model();
    if (model is null) Console.WriteLine("увага: data/model.json відсутній — усі події вважаються класом 0 (спершу `train`)");
    return new Pipeline(cfg, model, Workspace.Password);
}

void Train()
{
    var (train, trainY) = Workspace.Csv("train.csv");
    var (valid, validY) = Workspace.Csv("valid.csv");
    double[][] trainX = Features.Extract(train, cfg.HistoryMs), validX = Features.Extract(valid, cfg.HistoryMs);
    var (model, f1) = Mlp.TrainBest(trainX, trainY, validX, validY, cfg.Hidden, log: Console.WriteLine);
    model.Save(Workspace.PathOf("data", "model.json"));

    // holdout.csv викладач не видає: матриця — на valid.csv, за яким обрано модель з трьох, тому оцінка трохи оптимістична
    int[,] cm = model.Confusion(validX, validY);
    var md = new StringBuilder($"# Перцептрон: матриця помилок на valid.csv\n\nmacro-F1 на valid = {f1:F4} (поріг F1_min = {cfg.F1Min}; базові лінії: мажоритарний клас 0.293, випадковий вибір 0.312). ");
    md.Append($"Підсумковий macro-F1 викладач рахує на прихованому holdout.csv. Шари: {string.Join(" → ", model.Sizes)}, вікно історії {cfg.HistoryMs} мс\n\n");
    md.Append("| справжній \\ передбачений | 0 | 1 | 2 |\n|---|---|---|---|\n");
    for (int c = 0; c < 3; c++) md.Append($"| {c} | {cm[c, 0]} | {cm[c, 1]} | {cm[c, 2]} |\n");
    Directory.CreateDirectory(Workspace.PathOf("docs", "results"));
    File.WriteAllText(Workspace.PathOf("docs", "results", "confusion.md"), md.ToString());
    Console.WriteLine(md);
}

void CheckReference()
{
    string[] p = Positional();
    var verdicts = Reference.Check(p.Length > 0 ? p[0] : Workspace.PathOf("reference"), password);
    foreach (var (name, ok, detail) in verdicts)
        Console.WriteLine($"{name,-28} {(ok ? "OK     " : "ПОМИЛКА")} {detail}");
    Console.WriteLine($"пройдено {verdicts.Count(v => v.Ok)} з {verdicts.Count}");
    if (verdicts.Any(v => !v.Ok)) Environment.ExitCode = 1;
}

void AttackDemo()
{
    // 1. ГА відновлює ключ слабкого шифру за шифротекстом і статистикою окремого навчального набору
    var (key, result) = Attack.Demo(Workspace.Session(), Workspace.Csv("train.csv").Events);
    int matched = key.Where((b, i) => b == result.Best[i]).Count();
    Console.WriteLine($"справжній ключ:   {Convert.ToHexString(key)}");
    Console.WriteLine($"відновлений ключ: {Convert.ToHexString(result.Best)} — збіглося {matched}/{key.Length} байтів за {result.Evaluations} обчислень пристосованості");

    // 2. перевірка цілісності: зміна будь-якого байта репліки має бути відхилена за HMAC
    byte[] salt = RandomNumberGenerator.GetBytes(Crypto.SaltSize);
    byte[] replica = Replica.Build(Crypto.DeriveKeys(Workspace.Password, salt), salt, 0, 0, Workspace.Session()[..50]);
    replica[Log3.HeaderSize + 3] ^= 0x01;
    var (events, rejected) = Restorer.Restore([replica], new KeyRing(Workspace.Password));
    Console.WriteLine($"змінено 1 біт шифротексту: відхилено реплік {rejected}, прийнято подій {events.Length}");
}

// невідома назва — зрозуміле повідомлення і код виходу 2, а не KeyNotFoundException зі стеком
string KnownScenario(string name) =>
    cfg.Scenarios.ContainsKey(name) ? name : throw new ArgumentException($"невідомий сценарій {name}: normal | degraded | emergency");
