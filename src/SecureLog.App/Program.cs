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
switch (args.FirstOrDefault())
{
    case "gen":
        Gen.All();
        break;
    case "train":
        Train();
        break;
    case "run":
        foreach (string scenario in args.Length > 1 ? [args[1]] : Tuning.Scenarios)
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
              gen                     згенерувати дані й еталонні репліки (data/, reference/)
              train                   навчити перцептрон (3 ініціалізації), зберегти data/model.json
              run [сценарій] [seed]   повний прогін: normal | degraded | emergency (без аргументів — усі три; seed — відкритий із конфігу)
              ga                      ГА проти випадкового пошуку, зберегти data/ga_params.json
              attack                  атака ГА на слабкий шифр і перевірка цілісності репліки
              report                  таблиці експериментів у docs/results/tables.md
            """);
        break;
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
    var (holdout, holdoutY) = Workspace.Csv("holdout.csv");
    double[][] trainX = Features.Extract(train, cfg.HistoryWindow), validX = Features.Extract(valid, cfg.HistoryWindow);
    var (model, f1) = Mlp.TrainBest(trainX, trainY, validX, validY, cfg.Hidden, log: Console.WriteLine);
    model.Save(Workspace.PathOf("data", "model.json"));

    // holdout не брав участі ні в навчанні, ні у виборі моделі, тому оцінка на ньому не завищена
    int[,] cm = model.Confusion(Features.Extract(holdout, cfg.HistoryWindow), holdoutY);
    var md = new StringBuilder($"# Перцептрон: матриця помилок на holdout.csv\n\nmacro-F1 на holdout = {Mlp.MacroF1(cm):F4} (поріг F1_min = {cfg.F1Min}); на valid, за яким обрано модель, — {f1:F4}. Шари: {string.Join(" → ", model.Sizes)}\n\n");
    md.Append("| справжній \\ передбачений | 0 | 1 | 2 |\n|---|---|---|---|\n");
    for (int c = 0; c < 3; c++) md.Append($"| {c} | {cm[c, 0]} | {cm[c, 1]} | {cm[c, 2]} |\n");
    Directory.CreateDirectory(Workspace.PathOf("docs", "results"));
    File.WriteAllText(Workspace.PathOf("docs", "results", "confusion.md"), md.ToString());
    Console.WriteLine(md);
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
