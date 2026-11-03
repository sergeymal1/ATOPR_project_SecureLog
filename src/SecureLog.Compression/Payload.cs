using System.Buffers.Binary;
using SecureLog.Core;

namespace SecureLog.Compression;

/// <summary>
/// Навантаження репліки до шифрування (FORMAT_SPEC_P3, розділ 3):
/// record_count u16 | flags u8 | reserved u8 | table_nsym u16 | table 2×nsym | symbol_count u32 | bitstream_len u32 | bitstream | class_table.
/// </summary>
public static class Payload
{
    public const int FixedSize = 14;
    public const byte ClassTable = 0x04, NoCompression = 0x08;
    private const byte Extensions = 0x03, Reserved = 0xF0;   // PREDICTION і MULTI_COPY_META не підтримуються

    /// <summary>
    /// Пакує записи. Гаффман обирається, якщо таблиця разом із бітовим потоком коротша за сирі байти
    /// щонайменше на частку minGain; minGain ≥ 1 примусово дає NO_COMPRESSION, від'ємне дозволяє Гаффмана, навіть коли він довший за сирі байти.
    /// </summary>
    public static byte[] Pack(ReadOnlySpan<byte> records, double minGain = 0, byte[]? classTable = null)
    {
        int recordCount = records.Length / EventCodec.RecordSize;
        if (records.Length % EventCodec.RecordSize != 0 || recordCount > ushort.MaxValue) throw new ArgumentException("довжина записів некоректна");
        if (classTable is not null && classTable.Length != recordCount) throw new ArgumentException("class_table має містити байт на запис");

        var freq = new int[256];
        foreach (byte b in records) freq[b]++;
        byte[] lengths = Huffman.CodeLengths(freq);
        byte[] table = Enumerable.Range(0, 256).Where(s => lengths[s] > 0).SelectMany(s => new[] { (byte)s, lengths[s] }).ToArray();
        byte[] bitstream = Huffman.Encode(records, lengths);

        byte flags = classTable is null ? (byte)0 : ClassTable;
        if (table.Length + bitstream.Length > records.Length * (1 - minGain))
        {
            flags |= NoCompression;
            table = [];
            bitstream = records.ToArray();
        }

        var payload = new byte[FixedSize + table.Length + bitstream.Length + (classTable?.Length ?? 0)];
        var s = payload.AsSpan();
        BinaryPrimitives.WriteUInt16BigEndian(s, (ushort)recordCount);
        s[2] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(s[4..], (ushort)(table.Length / 2));
        table.CopyTo(s[6..]);
        int pos = 6 + table.Length;
        BinaryPrimitives.WriteUInt32BigEndian(s[pos..], (uint)records.Length);
        BinaryPrimitives.WriteUInt32BigEndian(s[(pos + 4)..], (uint)bitstream.Length);
        bitstream.CopyTo(s[(pos + 8)..]);
        classTable?.CopyTo(s[(pos + 8 + bitstream.Length)..]);
        return payload;
    }

    /// <summary>Строгий розбір: будь-яке порушення структури — E_PAYLOAD, помилка таблиці чи бітового потоку Гаффмана — E_CODE.</summary>
    public static (byte[] Records, byte[]? ClassTable) Unpack(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < FixedSize) throw Bad("навантаження коротше за обов'язкові поля");
        int recordCount = BinaryPrimitives.ReadUInt16BigEndian(payload);
        byte flags = payload[2];
        if (payload[3] != 0 || (flags & Reserved) != 0) throw Bad("зарезервовані поля не нульові");
        if ((flags & Extensions) != 0) throw Bad("невідоме розширення формату");

        int tableBytes = 2 * BinaryPrimitives.ReadUInt16BigEndian(payload[4..]);
        if (payload.Length < FixedSize + tableBytes) throw Bad("таблиця довжин виходить за межі навантаження");
        ReadOnlySpan<byte> table = payload.Slice(6, tableBytes);
        int pos = 6 + tableBytes;
        long symbolCount = BinaryPrimitives.ReadUInt32BigEndian(payload[pos..]);
        long bitstreamLength = BinaryPrimitives.ReadUInt32BigEndian(payload[(pos + 4)..]);
        if (symbolCount != (long)EventCodec.RecordSize * recordCount) throw Bad("symbol_count ≠ 16 × record_count");

        bool hasClasses = (flags & ClassTable) != 0;
        if (payload.Length != FixedSize + tableBytes + bitstreamLength + (hasClasses ? recordCount : 0)) throw Bad("довжини полів не збігаються з розміром навантаження");
        ReadOnlySpan<byte> bitstream = payload.Slice(pos + 8, (int)bitstreamLength);

        byte[] records;
        if ((flags & NoCompression) != 0)
        {
            if (bitstreamLength != symbolCount) throw Bad("у режимі NO_COMPRESSION bitstream_len має дорівнювати symbol_count");
            records = bitstream.ToArray();
        }
        else
        {
            records = Huffman.Decode(ReadTable(table), bitstream, (int)symbolCount);
        }

        byte[]? classes = hasClasses ? payload[^recordCount..].ToArray() : null;
        if (classes is not null && classes.Any(c => c > 2)) throw Bad("зарезервоване значення в class_table");
        return (records, classes);
    }

    /// <summary>Пари (символ, довжина) мають іти за строгим зростанням символу з довжинами 1…15.</summary>
    private static byte[] ReadTable(ReadOnlySpan<byte> table)
    {
        var lengths = new byte[256];
        for (int i = 0; i < table.Length; i += 2)
        {
            byte symbol = table[i], length = table[i + 1];
            if (i > 0 && symbol <= table[i - 2]) throw new ReplicaException(ErrorCode.Code, "символи таблиці не за зростанням");
            if (length is 0 or > Huffman.MaxLength) throw new ReplicaException(ErrorCode.Code, "довжина коду поза межами 1…15");
            lengths[symbol] = length;
        }
        return lengths;
    }

    private static ReplicaException Bad(string message) => new(ErrorCode.Payload, message);
}
