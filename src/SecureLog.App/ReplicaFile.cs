using System.Buffers.Binary;
using System.Security.Cryptography;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.Security;

namespace SecureLog.App;

/// <summary>
/// Файли для обміну з рецензентами та іншими командами (команди pack і unpack).
/// Вхід — записи по 16 байтів (як data/session.bin) або CSV журналу. Вихід pack — репліки LOG3 поспіль:
/// одна, якщо записів не більше 65535 (record_count — u16), інакше кілька, кожна зі своїм nonce і batch_seq.
/// Файл з однією реплікою — звичайна репліка за FORMAT_SPEC_P3, її прочитає будь-яка сумісна система.
/// </summary>
public static class ReplicaFile
{
    public const int MaxRecords = ushort.MaxValue;

    /// <summary>Одна прочитана репліка файлу.</summary>
    public sealed record Part(int Records, bool Compressed, bool HasClassTable);

    /// <summary>Записи з .csv (рядки журналу) або з будь-якого іншого файлу (сирі записи по 16 байтів) з перевіркою розділу 1.</summary>
    public static byte[] ReadRecords(string path)
    {
        byte[] raw;
        if (IsCsv(path))
        {
            try
            {
                raw = EventCodec.Encode(EventCodec.ReadCsv(path).Events);
            }
            catch (Exception e) when (e is FormatException or OverflowException or KeyNotFoundException or IndexOutOfRangeException)
            {
                throw new InvalidDataException($"CSV не розібрано: {e.Message}");
            }
        }
        else
        {
            raw = File.ReadAllBytes(path);
        }

        if (raw.Length % EventCodec.RecordSize != 0)
            throw new InvalidDataException($"довжина {raw.Length} байтів не кратна 16: вхід — записи по 16 байтів (FORMAT_SPEC_P3, розділ 1)");
        try
        {
            EventCodec.Decode(raw);
        }
        catch (ReplicaException e)
        {
            throw new InvalidDataException($"вхід не відповідає FORMAT_SPEC_P3, розділ 1: {e.Detail}");
        }
        return raw;
    }

    /// <summary>.csv — рядки журналу без мітки, інакше — сирі записи, які можна порівняти з входом побайтово.</summary>
    public static void WriteRecords(string path, byte[] records)
    {
        if (IsCsv(path)) EventCodec.WriteCsv(path, EventCodec.Decode(records));
        else File.WriteAllBytes(path, records);
    }

    /// <param name="noCompression">Примусовий NO_COMPRESSION; інакше Гаффман, якщо він коротший за сирі байти.</param>
    /// <param name="maxRecords">Записів на репліку; менше за 65535 — лише для тестів із кількома репліками.</param>
    public static byte[] Pack(byte[] records, string password, bool noCompression = false, int maxRecords = MaxRecords)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(Crypto.SaltSize);   // одна сіль на файл, PBKDF2 — один раз
        Keys keys = Crypto.DeriveKeys(password, salt);
        int chunk = maxRecords * EventCodec.RecordSize;
        using var file = new MemoryStream();
        uint seq = 0;
        int pos = 0;
        do   // порожній вхід дає одну порожню репліку, як ref_02_empty
        {
            int length = Math.Min(chunk, records.Length - pos);
            byte[] payload = Payload.Pack(records.AsSpan(pos, length), noCompression ? 1 : 0);
            file.Write(Log3.Seal(keys, salt, 0, seq++, payload));
            pos += length;
        } while (pos < records.Length);
        return file.ToArray();
    }

    public static (byte[] Records, List<Part> Parts) Unpack(byte[] file, string password) => Unpack(file, new KeyRing(password));

    /// <summary>
    /// Читає репліки поспіль за порядком приймання з розділу 5. Будь-яка помилка — ReplicaException з номером репліки,
    /// і жодних записів не повертається: частково прочитаний файл не видається за цілий.
    /// </summary>
    public static (byte[] Records, List<Part> Parts) Unpack(byte[] file, KeyRing keys)
    {
        using var records = new MemoryStream();
        var parts = new List<Part>();
        int pos = 0;
        do
        {
            int length = Boundary(file.AsSpan(pos));
            try
            {
                byte[] payload = Log3.Open(file.AsSpan(pos, length), keys).Payload;
                var (raw, classes) = Payload.Unpack(payload);
                EventCodec.Decode(raw);   // поля записів у межах розділу 1
                records.Write(raw);
                parts.Add(new(raw.Length / EventCodec.RecordSize, (payload[2] & Payload.NoCompression) == 0, classes is not null));
            }
            catch (ReplicaException e)
            {
                string where = length > 0 ? $"байти {pos}…{pos + length - 1}" : "порожньо";
                throw new ReplicaException(e.Code, $"репліка {parts.Count + 1} ({where}): {e.Detail}");
            }
            pos += length;
        } while (pos < file.Length);
        return (records.ToArray(), parts);
    }

    /// <summary>
    /// Довжина першої репліки: 43 + ciphertext_len + 32, якщо одразу за нею починається наступна ("LOG3").
    /// Інакше — увесь залишок, і Log3.Open сам відхилить зайві чи відсутні байти кодом E_LENGTH, як у файлі з однією реплікою.
    /// </summary>
    private static int Boundary(ReadOnlySpan<byte> rest)
    {
        if (rest.Length < Log3.HeaderSize) return rest.Length;
        long declared = Log3.Overhead + (long)BinaryPrimitives.ReadUInt32BigEndian(rest[Log3.LengthOffset..]);
        return declared + 4 <= rest.Length && rest.Slice((int)declared, 4).SequenceEqual("LOG3"u8) ? (int)declared : rest.Length;
    }

    private static bool IsCsv(string path) => Path.GetExtension(path).Equals(".csv", StringComparison.OrdinalIgnoreCase);
}
