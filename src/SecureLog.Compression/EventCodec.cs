using System.Buffers.Binary;
using System.Globalization;
using SecureLog.Core;

namespace SecureLog.Compression;

/// <summary>
/// Парсер журналу: CSV ↔ записи ↔ 16 байтів (FORMAT_SPEC_P3, розділ 1, big-endian):
/// timestamp_ms u32 | source_id u16 | event_code u16 | metric_value i32 | category u8 | severity u8 | critical u8 | record_flags u8.
/// </summary>
public static class EventCodec
{
    public const int RecordSize = 16;
    private const string CsvHeader = "timestamp_ms,source_id,event_code,metric_value,category,severity,critical,record_flags";

    public static byte[] Encode(IReadOnlyList<LogEvent> events)
    {
        var raw = new byte[events.Count * RecordSize];
        for (int i = 0; i < events.Count; i++)
        {
            var e = events[i];
            var s = raw.AsSpan(i * RecordSize, RecordSize);
            BinaryPrimitives.WriteUInt32BigEndian(s, e.Time);
            BinaryPrimitives.WriteUInt16BigEndian(s[4..], e.Source);
            BinaryPrimitives.WriteUInt16BigEndian(s[6..], e.Code);
            BinaryPrimitives.WriteInt32BigEndian(s[8..], e.Metric);
            s[12] = e.Category;
            s[13] = e.Severity;
            s[14] = (byte)(e.Critical ? 1 : 0);
            s[15] = e.Flags;
        }
        return raw;
    }

    public static LogEvent[] Decode(ReadOnlySpan<byte> raw)
    {
        if (raw.Length % RecordSize != 0) throw new ReplicaException(ErrorCode.Payload, "довжина журналу не кратна розміру запису");
        var events = new LogEvent[raw.Length / RecordSize];
        for (int i = 0; i < events.Length; i++)
        {
            var s = raw.Slice(i * RecordSize, RecordSize);
            // інакше запис не відтворився б байт у байт: bool зберігає лише 0 або 1
            if (s[14] > 1) throw new ReplicaException(ErrorCode.Payload, "поле critical має бути 0 або 1");
            events[i] = new LogEvent(
                BinaryPrimitives.ReadUInt32BigEndian(s),
                BinaryPrimitives.ReadUInt16BigEndian(s[4..]),
                BinaryPrimitives.ReadUInt16BigEndian(s[6..]),
                BinaryPrimitives.ReadInt32BigEndian(s[8..]),
                s[12], s[13], s[14] == 1, s[15]);
        }
        return events;
    }

    /// <summary>Читає CSV за назвами стовпців; label (якщо є) повертається окремо, інакше −1.</summary>
    public static (LogEvent[] Events, int[] Labels) ReadCsv(string path)
    {
        string[] lines = File.ReadAllLines(path);
        var events = new List<LogEvent>();
        var labels = new List<int>();
        if (lines.Length == 0) return ([], []);

        var column = lines[0].Split(',').Select((name, i) => (Name: name.Trim(), i)).ToDictionary(x => x.Name, x => x.i);
        var inv = CultureInfo.InvariantCulture;
        foreach (string line in lines.Skip(1))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            string[] f = line.Split(',');
            events.Add(new LogEvent(
                uint.Parse(f[column["timestamp_ms"]], inv),
                ushort.Parse(f[column["source_id"]], inv),
                ushort.Parse(f[column["event_code"]], inv),
                int.Parse(f[column["metric_value"]], inv),
                byte.Parse(f[column["category"]], inv),
                byte.Parse(f[column["severity"]], inv),
                f[column["critical"]].Trim() == "1",
                byte.Parse(f[column["record_flags"]], inv)));
            labels.Add(column.TryGetValue("label", out int li) ? int.Parse(f[li], inv) : -1);
        }
        return (events.ToArray(), labels.ToArray());
    }

    public static void WriteCsv(string path, IReadOnlyList<LogEvent> events, IReadOnlyList<int>? labels = null)
    {
        var inv = CultureInfo.InvariantCulture;
        var lines = new List<string> { CsvHeader + (labels is null ? "" : ",label") };
        for (int i = 0; i < events.Count; i++)
        {
            var e = events[i];
            string row = string.Create(inv, $"{e.Time},{e.Source},{e.Code},{e.Metric},{e.Category},{e.Severity},{(e.Critical ? 1 : 0)},{e.Flags}");
            lines.Add(labels is null ? row : $"{row},{labels[i]}");
        }
        File.WriteAllLines(path, lines);
    }
}
