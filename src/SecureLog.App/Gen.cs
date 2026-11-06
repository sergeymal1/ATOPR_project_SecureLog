using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.Security;

namespace SecureLog.App;

/// <summary>
/// Власні дані й еталонні репліки: train/valid/holdout/session.csv і reference/ команді не видано.
/// Каталог, у якому немає позначки STANDIN, вважається чужим і не перезаписується.
/// </summary>
public static class Gen
{
    private const string Marker = "STANDIN";

    public static void All()
    {
        if (Claim(Workspace.PathOf("data")))
        {
            foreach (var (name, n, seed) in new[] { ("train.csv", 20000, 11), ("valid.csv", 5000, 12), ("session.csv", 6000, 13), ("holdout.csv", 5000, 14) })
            {
                var (events, labels) = Events(n, seed);
                EventCodec.WriteCsv(Workspace.PathOf("data", name), events, name == "session.csv" ? null : labels);
                Console.WriteLine($"data/{name}: {n} подій, критичних {events.Count(e => e.Critical)}, класи 0/1/2 = {string.Join('/', Enumerable.Range(0, 3).Select(c => labels.Count(l => l == c)))}");
            }
        }
        if (Claim(Workspace.PathOf("reference"))) References(Workspace.PathOf("reference"));
    }

    /// <summary>true, якщо каталог порожній або вже позначений як згенерований; видані викладачем файли не чіпаємо.</summary>
    private static bool Claim(string dir)
    {
        Directory.CreateDirectory(dir);
        string marker = Path.Combine(dir, Marker);
        if (!File.Exists(marker) && Directory.EnumerateFileSystemEntries(dir).Any())
        {
            Console.WriteLine($"{Path.GetFileName(dir)}/ містить файли без позначки {Marker} — вважаю їх чужими й не перезаписую");
            return false;
        }
        File.WriteAllText(marker, "Файли в цьому каталозі згенеровано командою gen.\n");
        return true;
    }

    /// <summary>Потік подій трьох класів: 0 — штатні, 1 — поодинокі аномалії, 2 — серії «переходу до інциденту».</summary>
    public static (LogEvent[] Events, int[] Labels) Events(int n, int seed)
    {
        var rng = new Random(seed);
        var events = new LogEvent[n];
        var labels = new int[n];
        uint time = 0;
        int incidentLeft = 0, incidentCode = 0;
        for (int i = 0; i < n; i++)
        {
            int source = rng.Next(1, 9), category = source % 4, code = 100 + source * 10 + rng.Next(3), severity = rng.Next(3);
            double metric = 50 + 8 * Gauss(rng);
            int gap = rng.Next(200, 1500);

            if (incidentLeft == 0 && rng.NextDouble() < 0.004)
            {
                incidentLeft = rng.Next(15, 40);
                incidentCode = rng.Next(300, 900);
            }
            if (incidentLeft > 0)
            {
                // інцидент видно не з окремої події, а з серії: короткі інтервали, різні джерела й категорії, сусідні коди
                incidentLeft--;
                labels[i] = 2;
                gap = rng.Next(5, 120);
                source = rng.Next(1, 41);
                category = rng.Next(8);
                code = incidentCode + rng.Next(4);
                severity = rng.Next(1, 4);
                metric = 50 + 12 * Gauss(rng);
            }
            else if (rng.NextDouble() < 0.06)
            {
                labels[i] = 1;
                severity = rng.Next(3, 6);
                metric = 50 + (rng.Next(2) == 0 ? 1 : -1) * (30 + 20 * rng.NextDouble());
            }
            else if (rng.NextDouble() < 0.03)
            {
                severity = 3;   // шум: штатна подія з підвищеною severity
            }
            time += (uint)gap;   // gap ≥ 5, тому timestamp_ms унікальний, як вимагає специфікація

            // critical задається правилами, не пов'язаними з класом
            bool critical = code % 7 == 0 || (severity >= 3 && source % 3 == 0) || rng.NextDouble() < 0.03;
            byte flags = (byte)(rng.NextDouble() < 0.1 ? rng.Next(1, 4) : 0);
            events[i] = new LogEvent(time, (ushort)source, (ushort)code, (int)Math.Round(100 * metric), (byte)category, (byte)severity, critical, flags);
        }
        return (events, labels);
    }

    /// <summary>Еталонні й навмисно зіпсовані репліки з тими самими назвами, що в розділі 6 специфікації.</summary>
    private static void References(string dir)
    {
        const string password = "reference-password";
        byte[] salt = SHA256.HashData("securelog-reference"u8)[..Crypto.SaltSize];
        Keys keys = Crypto.DeriveKeys(password, salt);
        uint seq = 0;
        byte[] Seal(byte[] payload) => Log3.Seal(keys, salt, 1, seq++, payload);

        var (events, labels) = Events(48, 21);
        LogEvent degenerate = EventCodec.Decode(Enumerable.Repeat((byte)0x01, EventCodec.RecordSize).ToArray())[0];
        var good = new (string Name, LogEvent[] Batch, double MinGain, byte[]? Classes)[]
        {
            ("ref_01_single_record", events[..1], 0, null),
            ("ref_02_empty", [], 0, null),
            ("ref_03_degenerate", [degenerate], 0, null),
            ("ref_04_session", events, -1, null),              // від'ємний поріг — примусовий Гаффман
            ("ref_05_no_compression", events[..10], 1, null),
            ("ref_06_class_table", events[..10], 0, labels[..10].Select(l => (byte)l).ToArray()),
        };
        foreach (var (name, batch, minGain, classes) in good)
        {
            byte[] raw = EventCodec.Encode(batch);
            File.WriteAllBytes(Path.Combine(dir, name + ".bin"), Seal(Payload.Pack(raw, minGain, classes)));
            File.WriteAllText(Path.Combine(dir, name + ".json"),
                JsonSerializer.Serialize(new { password, records = batch.Length, sha256 = Convert.ToHexString(SHA256.HashData(raw)) }, TeamConfig.Json));
        }

        byte[] payload = Payload.Pack(EventCodec.Encode(events), -1);
        byte[] packet = Seal(payload);
        int counts = 6 + 2 * ((payload[4] << 8) | payload[5]);   // зсув symbol_count: одразу за таблицею довжин

        byte[] extra = [.. payload, 0];   // зайвий нульовий байт у бітовому потоці, довжина в полі збільшена відповідно
        BinaryPrimitives.WriteUInt32BigEndian(extra.AsSpan(counts + 4), BinaryPrimitives.ReadUInt32BigEndian(extra.AsSpan(counts + 4)) + 1);

        var bad = new (string Name, byte[] Bytes, string Code)[]
        {
            ("bad_01_short.bin", packet[..40], ErrorCode.Short),
            ("bad_02_magic.bin", Patch(packet, 0, (byte)'X'), ErrorCode.Magic),
            ("bad_03_length.bin", packet[..^5], ErrorCode.Length),
            ("bad_04_hmac.bin", Patch(packet, packet.Length - 1, (byte)(packet[^1] ^ 0x80)), ErrorCode.Hmac),
            ("bad_05_payload.bin", Seal(Patch(payload, counts + 3, (byte)(payload[counts + 3] ^ 1))), ErrorCode.Payload),
            ("bad_06_kraft.bin", Seal(Patch(payload, 7, (byte)(payload[7] + 1))), ErrorCode.Code),
            ("bad_07_extra_bitstream.bin", Seal(extra), ErrorCode.Code),
        };
        foreach (var (name, bytes, _) in bad) File.WriteAllBytes(Path.Combine(dir, name), bytes);
        File.WriteAllText(Path.Combine(dir, "expected_failures.json"),
            JsonSerializer.Serialize(new { password, files = bad.ToDictionary(b => b.Name, b => b.Code) }, TeamConfig.Json));
        Console.WriteLine($"reference/: {good.Length} еталонних і {bad.Length} зіпсованих реплік");
    }

    private static byte[] Patch(byte[] source, int index, byte value)
    {
        var copy = (byte[])source.Clone();
        copy[index] = value;
        return copy;
    }

    private static double Gauss(Random rng) =>
        Math.Sqrt(-2 * Math.Log(1 - rng.NextDouble())) * Math.Cos(2 * Math.PI * rng.NextDouble());
}
