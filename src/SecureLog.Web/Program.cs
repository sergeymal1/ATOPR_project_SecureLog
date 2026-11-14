using System.Buffers.Binary;
using System.Globalization;
using SecureLog.App;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.DP;
using SecureLog.ML;
using SecureLog.Security;

// Вебконсоль: та сама система, що й CLI, лише результат показано як журнал інфраструктури.
// Прогін виконується повністю на сервері, сторінка відтворює його вікно за вікном.
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

TeamConfig cfg = Workspace.Config();
Mlp? model = Workspace.Model();
LogEvent[] session = Workspace.Session();
Params best = Workspace.BestParams(cfg);
LogEvent[]? training = null;

var gate = new Lock();
Replication? nodes = null;   // вузли останнього прогону: їх можна зіпсувати й відновити ще раз
string runPassword = Workspace.Password;

var app = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = Workspace.PathOf("src", "SecureLog.Web", "wwwroot"),
}).Build();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/info", () => new
{
    events = session.Length,
    critical = session.Count(e => e.Critical),
    model = model is null ? null : string.Join(" → ", model.Sizes),
    best.Window,
    best.MinGain,
    best.SecondCopyFactor,
    seed = cfg.ReplicationSeed,
    cfg.Scenarios,
});

app.MapPost("/api/run", (RunRequest req) =>
{
    if (!cfg.Scenarios.ContainsKey(req.Scenario)) return Results.BadRequest($"невідомий сценарій {req.Scenario}");
    string password = string.IsNullOrEmpty(req.Password) ? Workspace.Password : req.Password;
    var traces = new List<WindowTrace>();
    var sim = new Replication(cfg, req.Scenario, req.Seed);
    RunResult r = new Pipeline(cfg, model, password).Run(session, sim, new RunOptions(best) { OnWindow = traces.Add });
    lock (gate) (nodes, runPassword) = (sim, password);

    var restored = Restorer.Restore(Packets(sim), new KeyRing(password)).Events.ToHashSet();
    var classOf = new int[session.Length];
    var nodesOf = session.Select(_ => new List<int>()).ToArray();
    foreach (WindowTrace t in traces)
    {
        t.Classes.CopyTo(classOf, t.Start);
        for (int k = 0; k < t.Sent.Length; k++)
            foreach (int i in t.Sent[k]) nodesOf[t.Start + i].Add(k);
    }

    return Results.Ok(new
    {
        result = new
        {
            r.Quality.S, r.Quality.R, r.Quality.T, r.Quality.Q, r.CriticalTotal, r.CriticalRestored, r.Restored, r.Rejected,
            rawBytes = r.RawBits / 8, storedBytes = r.StoredBits / 8, budgetBytes = sim.BudgetBytes, r.Seconds,
        },
        nodes = Enumerable.Range(0, sim.NodeCount).Select(k => new
        {
            reliability = sim.Reliability(k),
            capacity = cfg.Scenarios[req.Scenario].Nodes[k].CapacityBytes,
            stored = sim.Read(k).Count,
        }),
        windows = traces.Select(t => new
        {
            t.Start, count = t.Classes.Length, t.Budget, t.UsedBits, t.Bytes,
            copies = Enumerable.Range(0, 4).Select(c => t.Copies.Count(x => x == c)),
            sent = t.Sent.Select(s => s.Length),
        }),
        events = session.Select((e, i) => new
        {
            t = e.Time, src = e.Source, code = e.Code, metric = e.Metric, cat = e.Category, sev = e.Severity,
            crit = e.Critical, cls = classOf[i], nodes = nodesOf[i], ok = restored.Contains(e),
        }),
    });
});

app.MapPost("/api/tamper", (TamperRequest req) =>
{
    Replication? sim;
    lock (gate) sim = nodes;
    if (sim is null || req.Node < 0 || req.Node >= sim.NodeCount) return Results.BadRequest("немає прогону або такого вузла");
    var stored = sim.Read(req.Node);
    if (stored.Count == 0) return Results.BadRequest("на вузлі немає пакетів");

    byte[] packet = stored[Random.Shared.Next(stored.Count)];
    // біт у шифротексті: заголовок перевіряється раніше, а шифротекст захищає лише HMAC
    int offset = Random.Shared.Next(Log3.HeaderSize, packet.Length - Crypto.MacSize), bit = Random.Shared.Next(8);
    packet[offset] ^= (byte)(1 << bit);
    return Results.Ok(new { node = req.Node, seq = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(Log3.SeqOffset)), offset, bit });
});

app.MapPost("/api/restore", (RestoreRequest req) =>
{
    Replication? sim;
    string password;
    lock (gate) (sim, password) = (nodes, runPassword);
    if (sim is null) return Results.BadRequest("спершу запустіть прогін");

    var ring = new KeyRing(string.IsNullOrEmpty(req.Password) ? password : req.Password);
    var perNode = Enumerable.Range(0, sim.NodeCount).Select(k =>
    {
        var codes = new Dictionary<string, int>();
        foreach (byte[] packet in sim.Read(k))
        {
            string code = "OK";
            try { Replica.Open(packet, ring); }
            catch (ReplicaException e) { code = e.Code; }
            codes[code] = codes.GetValueOrDefault(code) + 1;
        }
        return codes;
    }).ToList();

    var (events, rejected) = Restorer.Restore(Packets(sim), ring);
    var set = events.ToHashSet();
    return Results.Ok(new
    {
        restored = events.Length,
        total = session.Length,
        critical = session.Count(e => e.Critical && set.Contains(e)),
        criticalTotal = session.Count(e => e.Critical),
        rejected,
        nodes = perNode,
        lost = Enumerable.Range(0, session.Length).Where(i => !set.Contains(session[i])),
    });
});

app.MapPost("/api/attack", () =>
{
    training ??= Workspace.Csv("train.csv").Events;
    var (key, result) = Attack.Demo(session, training);
    return new
    {
        key = Convert.ToHexString(key),
        recovered = Convert.ToHexString(result.Best),
        matched = key.Where((b, i) => b == result.Best[i]).Count(),
        result.Evaluations,
        result.History,
    };
});

app.Run(Environment.GetEnvironmentVariable("SECURELOG_URL") ?? "http://localhost:5080");

static IEnumerable<byte[]> Packets(Replication sim) => Enumerable.Range(0, sim.NodeCount).SelectMany(sim.Read);

record RunRequest(string Scenario, long Seed, string? Password);
record TamperRequest(int Node);
record RestoreRequest(string? Password);
