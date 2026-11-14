using System.Buffers.Binary;
using System.Text.Json;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.Security;

namespace SecureLog.App;

/// <summary>
/// Звірка з еталонними пакетами викладача (reference/). Для ref_* відновлювач має дати ті самі записи, flags, таблицю,
/// коди й бітовий потік, що в .json, а наш передавач — зібрати з тих самих записів, солі й nonce байт у байт той самий пакет.
/// Для bad_* відновлювач має відхилити пакет з кодом з expected_failures.json.
/// </summary>
public static class Reference
{
    public sealed record Verdict(string Name, bool Ok, string Detail);

    public static List<Verdict> Check(string dir, string password)
    {
        var res = new List<Verdict>();
        foreach (string json in Directory.GetFiles(dir, "ref_*.json").Order())
        {
            string name = Path.GetFileNameWithoutExtension(json);
            string? error;
            try
            {
                error = Compare(File.ReadAllText(json), File.ReadAllBytes(Path.ChangeExtension(json, ".bin")));
            }
            catch (ReplicaException e)
            {
                error = $"еталонний пакет відхилено: {e.Message}";
            }
            res.Add(new(name, error is null, error ?? "записи, таблиця, коди й потік збігаються; наш передавач збирає той самий пакет байт у байт"));
        }

        string expectedPath = Path.Combine(dir, "expected_failures.json");
        if (!File.Exists(expectedPath)) return res;
        using var failures = JsonDocument.Parse(File.ReadAllText(expectedPath));
        var ring = new KeyRing(password);
        foreach (JsonProperty file in failures.RootElement.EnumerateObject())
        {
            string expected = file.Value.GetProperty("очікуваний_код").GetString()!, actual;
            try
            {
                Replica.Open(File.ReadAllBytes(Path.Combine(dir, file.Name)), ring);
                actual = "прийнято";
            }
            catch (ReplicaException e)
            {
                actual = e.Code;
            }
            res.Add(new(file.Name, actual == expected, $"очікувано {expected}, отримано {actual}"));
        }
        return res;
    }

    /// <summary>null — пакет повністю відповідає опису; інакше — що саме не збіглося.</summary>
    private static string? Compare(string json, byte[] packet)
    {
        using var doc = JsonDocument.Parse(json);
        JsonElement meta = doc.RootElement;
        var keys = new KeyRing(meta.GetProperty("пароль").GetString()!);

        var (groupId, batchSeq, payload) = Log3.Open(packet, keys);
        var (records, classTable) = Payload.Unpack(payload);
        LogEvent[] events = EventCodec.Decode(records);
        LogEvent[] expected = meta.GetProperty("записи").EnumerateArray().Select(r => new LogEvent(
            r.GetProperty("timestamp_ms").GetUInt32(), r.GetProperty("source_id").GetUInt16(), r.GetProperty("event_code").GetUInt16(),
            r.GetProperty("metric_value").GetInt32(), r.GetProperty("category").GetByte(), r.GetProperty("severity").GetByte(),
            r.GetProperty("critical").GetInt32() == 1, r.GetProperty("record_flags").GetByte())).ToArray();
        if (!events.SequenceEqual(expected)) return "записи відрізняються";
        JsonElement classes = meta.GetProperty("class_table");
        byte[]? expectedClasses = classes.ValueKind == JsonValueKind.Null ? null : classes.EnumerateArray().Select(c => c.GetByte()).ToArray();
        if (!(classTable ?? []).SequenceEqual(expectedClasses ?? []) || (classTable is null) != (expectedClasses is null)) return "class_table відрізняється";

        // поля навантаження за розділом 3: таблиця пар (символ, довжина), далі symbol_count, bitstream_len, потік, class_table
        byte flags = payload[2];
        int nsym = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(4)), pos = 6 + 2 * nsym;
        int bitstreamLength = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(pos + 4));
        byte[] bitstream = payload[(pos + 8)..(pos + 8 + bitstreamLength)];
        if (flags != meta.GetProperty("flags").GetInt32()) return "flags відрізняються";
        if (Convert.ToHexString(bitstream) != meta.GetProperty("bitstream_hex").GetString()!.ToUpperInvariant()) return "бітовий потік відрізняється";

        var lengths = new byte[256];
        var codes = new List<(int Symbol, int Length, string Code)>();
        foreach (JsonElement row in meta.GetProperty("таблиця_кодів").EnumerateArray())
        {
            int symbol = row.GetProperty("символ").GetInt32(), length = row.GetProperty("довжина").GetInt32();
            lengths[symbol] = (byte)length;
            codes.Add((symbol, length, row.GetProperty("код").GetString()!));
        }
        if (!payload[6..pos].SequenceEqual(codes.SelectMany(c => new[] { (byte)c.Symbol, (byte)c.Length }))) return "таблиця довжин відрізняється";

        // коди відновлюються лише з довжин — і мають збігтися з кодами викладача
        uint[] canonical = Huffman.CanonicalCodes(lengths);
        foreach (var (symbol, length, code) in codes)
            if (Convert.ToString(canonical[symbol], 2).PadLeft(length, '0') != code) return $"канонічний код символу {symbol} відрізняється";

        // наш передавач з тих самих записів; режим — як у викладача: −10 примушує Гаффмана, 1 — NO_COMPRESSION
        byte[] ours = Payload.Pack(EventCodec.Encode(events), (flags & Payload.NoCompression) != 0 ? 1 : -10, classTable);
        if (!ours.SequenceEqual(payload)) return "наш кодер дав інше навантаження (інші довжини кодів або потік)";

        byte[] salt = Convert.FromHexString(meta.GetProperty("salt_hex").GetString()!), nonce = Convert.FromHexString(meta.GetProperty("nonce_hex").GetString()!);
        byte[] sealedAgain = Log3.Seal(keys.Get(salt), salt, groupId, batchSeq, ours, nonce);
        return sealedAgain.SequenceEqual(packet) ? null : "повторно зібраний пакет відрізняється (шифрування або HMAC)";
    }
}
