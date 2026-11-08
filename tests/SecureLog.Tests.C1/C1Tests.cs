using System.Security.Cryptography;
using System.Text.Json;
using SecureLog.App;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.DP;
using SecureLog.ML;
using SecureLog.Security;

namespace SecureLog.Tests.C1;

/// <summary>12 базових приймальних кейсів C1 (розділ 9.1 завдання). Потребують data/ і reference/: команди gen і train.</summary>
public class C1Tests
{
    private const string Password = "c1-password";
    private static readonly int[] Seeds = [1, 2, 3, 4, 5];
    private static readonly TeamConfig Cfg = Workspace.Config();
    private static readonly LogEvent[] Session = Workspace.Session();
    private static readonly Mlp Model = Workspace.Model() ?? throw new InvalidOperationException("немає data/model.json — запустіть gen і train");
    private static readonly Pipeline Pipe = new(Cfg, Model, Password);
    private static readonly RunOptions Options = new(Workspace.BestParams(Cfg));
    private static readonly byte[] Salt = new byte[Crypto.SaltSize];
    private static readonly Keys Keys = Crypto.DeriveKeys(Password, Salt);
    private static readonly KeyRing Ring = new(Password);

    private static byte[] Build(IReadOnlyList<LogEvent> batch, double minGain = 0) => Replica.Build(Keys, Salt, 1, 0, batch, minGain);

    private static byte[] Seal(byte[] payload) => Log3.Seal(Keys, Salt, 1, 0, payload);

    private static string CodeOf(byte[] packet, KeyRing? ring = null) =>
        Assert.Throws<ReplicaException>(() => Replica.Open(packet, ring ?? Ring)).Code;

    [Fact]
    public void C01_SingleRecordIsRestoredByteForByte()
    {
        LogEvent[] one = [new(123456, 3, 140, -5150, 2, 4, true, 1)];
        byte[] raw = EventCodec.Encode(one);
        Assert.Equal(EventCodec.RecordSize, raw.Length);
        Assert.Equal(raw, EventCodec.Encode(Replica.Open(Build(one), Ring)));
    }

    [Fact]
    public void C02_EmptyLogDoesNotCrash()
    {
        Assert.Empty(Payload.Unpack(Payload.Pack([])).Records);
        Assert.Empty(Replica.Open(Build([]), Ring));
        foreach (string scenario in Tuning.Scenarios) Assert.Equal(0, Pipe.RunSim([], scenario, 1, Options).Restored);
    }

    [Fact]
    public void C03_NoCompressionRestoresRawRecordsExactly()
    {
        byte[] raw = EventCodec.Encode(Session[..30]);
        byte[] payload = Payload.Pack(raw, minGain: 1);   // виграш 100 % недосяжний → NO_COMPRESSION
        Assert.NotEqual(0, payload[2] & Payload.NoCompression);
        Assert.Equal(raw, payload[^raw.Length..]);        // у потоці — сирі байти записів
        Assert.Equal(raw, EventCodec.Encode(Replica.Open(Build(Session[..30], minGain: 1), Ring)));

        // дані без надлишковості: Гаффман лише додав би таблицю, тому режим обирається автоматично
        byte[] noise = RandomNumberGenerator.GetBytes(4096);
        byte[] packed = Payload.Pack(noise);
        Assert.NotEqual(0, packed[2] & Payload.NoCompression);
        Assert.Equal(noise, Payload.Unpack(packed).Records);
    }

    [Fact]
    public void C04_CanonicalCodesAreRestoredFromLengthsOnly()
    {
        // приклад, який легко перевірити вручну: довжини 1, 2, 3, 3 → коди 0, 10, 110, 111
        var manual = new byte[256];
        (manual['a'], manual['b'], manual['c'], manual['d']) = (1, 2, 3, 3);
        uint[] codes = Huffman.CanonicalCodes(manual);
        Assert.Equal(new uint[] { 0b0, 0b10, 0b110, 0b111 }, new[] { codes['a'], codes['b'], codes['c'], codes['d'] });

        byte[] raw = EventCodec.Encode(Session[..500]);
        var freq = new int[256];
        foreach (byte b in raw) freq[b]++;
        byte[] lengths = Huffman.CodeLengths(freq);
        Assert.Equal(raw, Huffman.Decode(lengths, Huffman.Encode(raw, lengths), raw.Length));

        // у навантаженні — лише пари (символ, довжина) за зростанням символу, без структури дерева
        byte[] payload = Payload.Pack(raw, minGain: -10);
        int nsym = (payload[4] << 8) | payload[5];
        byte[] expectedTable = Enumerable.Range(0, 256).Where(s => lengths[s] > 0).SelectMany(s => new[] { (byte)s, lengths[s] }).ToArray();
        Assert.Equal(expectedTable, payload[6..(6 + 2 * nsym)]);
        Assert.Equal(raw, Payload.Unpack(payload).Records);
    }

    [Fact]
    public void C05_DegenerateAlphabetHasCodeLengthOne()
    {
        // запис, усі 16 байтів якого дорівнюють 0x01 (як ref_03_degenerate)
        byte[] raw = Enumerable.Repeat((byte)0x01, EventCodec.RecordSize).ToArray();
        byte[] payload = Payload.Pack(raw);
        Assert.Equal(0, payload[2] & Payload.NoCompression);
        Assert.Equal(new byte[] { 0, 1, 0x01, 1 }, payload[4..8]);                 // table_nsym = 1, пара (0x01, довжина 1)
        Assert.Equal(new byte[] { 0, 0 }, payload[^2..]);                          // 16 кодів «0» — два нульові байти
        Assert.Equal(raw, Payload.Unpack(payload).Records);
        Assert.Equal(raw, EventCodec.Encode(Replica.Open(Build(EventCodec.Decode(raw)), Ring)));
    }

    [Theory]
    [InlineData("normal")]
    [InlineData("degraded")]
    [InlineData("emergency")]
    public void C06_DpIsNotWorseThanGreedyOnEveryWindow(string scenario)
    {
        int instances = 0;
        // вікно і коефіцієнти — з конфігу, як у постановці 3.5
        var options = new RunOptions(Cfg.DefaultParams())
        {
            OnKnapsack = (weight, utility, budget) =>
            {
                int[] dp = Knapsack.SolveDp(weight, utility, budget), greedy = Knapsack.SolveGreedy(weight, utility, budget);
                Assert.True(Knapsack.Cost(weight, dp) <= budget);
                Assert.True(Knapsack.Cost(weight, greedy) <= budget);
                Assert.True(Knapsack.Utility(utility, dp) >= Knapsack.Utility(utility, greedy) - 1e-9);
                instances++;
            },
        };
        foreach (int seed in Seeds) Pipe.RunSim(Session, scenario, seed, options);
        Assert.True(instances > 0);
    }

    [Fact]
    public void C07_NormalScenarioRestoresAllCriticalEvents()
    {
        foreach (int seed in Seeds)
        {
            RunResult r = Pipe.RunSim(Session, "normal", seed, Options);
            Assert.True(r.CriticalTotal > 0);
            Assert.Equal(r.CriticalTotal, r.CriticalRestored);
        }
    }

    [Fact]
    public void C08_DegradedScenarioLossIsWithinThreshold()
    {
        double loss = Seeds.Average(seed => 1 - Pipe.RunSim(Session, "degraded", seed, Options).Quality.R);
        Assert.True(loss <= Cfg.DegradedLossMax, $"втрачено {loss:P2} критичних подій, поріг {Cfg.DegradedLossMax:P0}");
    }

    [Fact]
    public void C09_PerceptronReachesMacroF1()
    {
        // holdout.csv не використовується ні в навчанні, ні у виборі моделі (її обирають за valid.csv)
        var (holdout, labels) = Workspace.Csv("holdout.csv");
        double f1 = Mlp.MacroF1(Model.Confusion(Features.Extract(holdout, Cfg.HistoryWindow), labels));
        Assert.True(f1 >= Cfg.F1Min, $"macro-F1 = {f1:F4}, потрібно ≥ {Cfg.F1Min}");
    }

    [Fact]
    public void C10_AnyModifiedByteIsRejected()
    {
        byte[] packet = Build(Session[..20]);
        Assert.Equal(20, Replica.Open(packet, Ring).Length);
        for (int i = 0; i < packet.Length; i++)
        {
            byte[] bad = (byte[])packet.Clone();
            bad[i] ^= 0x01;
            string code = CodeOf(bad);
            // шифротекст і сам HMAC захищені лише HMAC; у заголовку раніше можуть спрацювати перевірки magic і довжини
            if (i >= Log3.HeaderSize) Assert.Equal(ErrorCode.Hmac, code);
        }
    }

    [Fact]
    public void C11_BadInputsAreRejectedWithoutCrash()
    {
        byte[] good = Build(Session[..20]);
        byte[] badMagic = (byte[])good.Clone();
        badMagic[0] = (byte)'X';

        // reserved лежить усередині зашифрованого навантаження, тому зіпсовані варіанти запечатуються правильним HMAC
        byte[] payload = Payload.Pack(EventCodec.Encode(Session[..20]));
        byte[] reservedByte = (byte[])payload.Clone(), reservedFlags = (byte[])payload.Clone(), extension = (byte[])payload.Clone();
        reservedByte[3] = 1;
        reservedFlags[2] |= 0x40;
        extension[2] |= 0x01;

        Assert.Equal(ErrorCode.Hmac, CodeOf(good, new KeyRing("wrong password")));
        Assert.Equal(ErrorCode.Magic, CodeOf(badMagic));
        Assert.Equal(ErrorCode.Payload, CodeOf(Seal(reservedByte)));
        Assert.Equal(ErrorCode.Payload, CodeOf(Seal(reservedFlags)));
        Assert.Equal(ErrorCode.Payload, CodeOf(Seal(extension)));
        for (int length = 0; length < good.Length; length += 7)
            Assert.Equal(length < Log3.Overhead ? ErrorCode.Short : ErrorCode.Length, CodeOf(good[..length]));

        // відновлювач пропускає зіпсовані копії й бере записи з цілої
        var (events, rejected) = Restorer.Restore([badMagic, Seal(reservedByte), good[..50], [], good], Ring);
        Assert.Equal(4, rejected);
        Assert.Equal(20, events.Length);
    }

    [Fact]
    public void C12_ReferencePacketsAreReadAndRunFitsTimeLimit()
    {
        // назви — з розділу 6 FORMAT_SPEC_P3
        string[] references = ["ref_01_single_record", "ref_02_empty", "ref_03_degenerate", "ref_04_session", "ref_05_no_compression", "ref_06_class_table"];
        string dir = Workspace.PathOf("reference");
        foreach (string name in references)
        {
            using var meta = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, name + ".json")));
            LogEvent[] events = Replica.Open(File.ReadAllBytes(Path.Combine(dir, name + ".bin")), new KeyRing(meta.RootElement.GetProperty("password").GetString()!));
            Assert.Equal(meta.RootElement.GetProperty("records").GetInt32(), events.Length);
            Assert.Equal(meta.RootElement.GetProperty("sha256").GetString(), Convert.ToHexString(SHA256.HashData(EventCodec.Encode(events))));
        }

        using var failures = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "expected_failures.json")));
        var ring = new KeyRing(failures.RootElement.GetProperty("password").GetString()!);
        var expected = failures.RootElement.GetProperty("files").EnumerateObject().ToList();
        Assert.Equal(7, expected.Count);
        foreach (JsonProperty file in expected)
            Assert.Equal(file.Value.GetString(), CodeOf(File.ReadAllBytes(Path.Combine(dir, file.Name)), ring));

        foreach (string scenario in Tuning.Scenarios)
            Assert.True(Pipe.RunSim(Session, scenario, 1, Options).Seconds <= Cfg.TimeLimitS);
    }
}
