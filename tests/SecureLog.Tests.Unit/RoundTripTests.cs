using SecureLog.App;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.Security;

namespace SecureLog.Tests.Unit;

/// <summary>
/// Round-trip і негативні тести файлів реплік — те саме, що рецензент робить командами pack і unpack:
/// власні дані, крайні випадки, пошкоджені файли. Пошкодження ніколи не дає ні аварії, ні хибних записів.
/// </summary>
public class RoundTripTests
{
    private const string Password = "round-trip";
    private static readonly KeyRing Ring = new(Password);

    /// <summary>Випадкові записи з полями в межах розділу 1 — майже нестисні, тож зазвичай NO_COMPRESSION.</summary>
    private static byte[] RandomRecords(int count, int seed)
    {
        var rng = new Random(seed);
        return EventCodec.Encode(Enumerable.Range(0, count).Select(i => new LogEvent(
            (uint)rng.Next(), (ushort)rng.Next(1, 4096), (ushort)rng.Next(65536), rng.Next(int.MinValue, int.MaxValue),
            (byte)rng.Next(16), (byte)rng.Next(8), rng.Next(2) == 1, (byte)rng.Next(4))).ToArray());
    }

    /// <summary>Записи сесії по колу — добре стискаються, тож Гаффман.</summary>
    private static byte[] SessionRecords(int count)
    {
        LogEvent[] session = Workspace.Session();
        return EventCodec.Encode(Enumerable.Range(0, count).Select(i => session[i % session.Length] with { Time = (uint)i }).ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(48)]
    [InlineData(1200)]
    [InlineData(65535)]   // рівно одна повна репліка
    [InlineData(65536)]   // record_count — u16, тому вже дві репліки
    [InlineData(150000)]  // 2.4 МБ, три репліки
    public void RestoresRecordsByteForByte(int count)
    {
        foreach (byte[] records in new[] { RandomRecords(count, count), SessionRecords(count) })
            foreach (bool raw in new[] { false, true })
            {
                byte[] file = ReplicaFile.Pack(records, Password, raw);
                var (restored, parts) = ReplicaFile.Unpack(file, Ring);
                Assert.Equal(records, restored);
                Assert.Equal(Math.Max(1, (count + ReplicaFile.MaxRecords - 1) / ReplicaFile.MaxRecords), parts.Count);
                if (raw) Assert.All(parts, p => Assert.False(p.Compressed));
            }
    }

    [Fact]
    public void SessionWindowIsCompressedByHuffman()
    {
        byte[] records = SessionRecords(48);
        byte[] file = ReplicaFile.Pack(records, Password);
        Assert.True(file.Length < records.Length);
        Assert.True(ReplicaFile.Unpack(file, Ring).Parts.Single().Compressed);
    }

    [Theory]   // один повторюваний байт; 0x01 дає поля в межах розділу 1, як ref_03_degenerate
    [InlineData(1)]
    [InlineData(1000)]
    public void SingleRepeatedByteUsesOneCodeOfLengthOne(int count)
    {
        byte[] records = Enumerable.Repeat((byte)0x01, count * EventCodec.RecordSize).ToArray();
        var (restored, parts) = ReplicaFile.Unpack(ReplicaFile.Pack(records, Password), Ring);
        Assert.Equal(records, restored);
        Assert.True(parts.Single().Compressed);
    }

    [Fact]
    public void FilesAndCsvRoundTrip()
    {
        string dir = Directory.CreateTempSubdirectory("securelog-").FullName;
        try
        {
            LogEvent[] events = Workspace.Session()[..100];
            string csv = Path.Combine(dir, "in.csv"), replica = Path.Combine(dir, "out.bin"), back = Path.Combine(dir, "back.csv");
            EventCodec.WriteCsv(csv, events, Enumerable.Repeat(0, events.Length).ToArray());   // з колонкою label, як у виданих CSV

            File.WriteAllBytes(replica, ReplicaFile.Pack(ReplicaFile.ReadRecords(csv), Password));
            ReplicaFile.WriteRecords(back, ReplicaFile.Unpack(File.ReadAllBytes(replica), Password).Records);

            Assert.Equal(events, EventCodec.ReadCsv(back).Events);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void InputOutsideFormatIsRejectedWithMessage()
    {
        string dir = Directory.CreateTempSubdirectory("securelog-").FullName;
        try
        {
            string Write(string name, byte[] bytes)
            {
                string path = Path.Combine(dir, name);
                File.WriteAllBytes(path, bytes);
                return path;
            }

            Assert.Throws<InvalidDataException>(() => ReplicaFile.ReadRecords(Write("short.bin", new byte[15])));          // не кратне 16
            Assert.Throws<InvalidDataException>(() => ReplicaFile.ReadRecords(Write("letters.bin", "AAAAAAAAAAAAAAAA"u8.ToArray())));   // source_id 0x4141 > 4095
            byte[] badCategory = RandomRecords(3, 1);
            badCategory[16 + 12] = 16;
            Assert.Throws<InvalidDataException>(() => ReplicaFile.ReadRecords(Write("category.bin", badCategory)));
            File.WriteAllText(Path.Combine(dir, "bad.csv"), "timestamp_ms,source_id,event_code,metric_value,category,severity,critical,record_flags\n1,2,3,4,5,6,7,0\n");
            Assert.Throws<InvalidDataException>(() => ReplicaFile.ReadRecords(Path.Combine(dir, "bad.csv")));   // critical = 7
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void AnyCorruptionIsRejectedWithCode()
    {
        byte[] records = SessionRecords(30);
        byte[] file = ReplicaFile.Pack(records, Password, maxRecords: 10);   // три репліки поспіль
        Assert.Equal(records, ReplicaFile.Unpack(file, Ring).Records);

        string CodeOf(byte[] bad) => Assert.Throws<ReplicaException>(() => ReplicaFile.Unpack(bad, Ring)).Code;

        for (int i = 0; i < file.Length; i++)   // будь-який змінений байт
        {
            byte[] bad = (byte[])file.Clone();
            bad[i] ^= 0x01;
            CodeOf(bad);
        }
        for (int length = 0; length < file.Length; length++) CodeOf(file[..length]);   // обрізаний файл
        Assert.Equal(ErrorCode.Length, CodeOf([.. file, 0x00]));                      // зайвий байт у кінці

        // неможливі значення в полі ciphertext_len першої репліки
        foreach (uint value in new uint[] { 0, 1, 0x7FFFFFFF, 0xFFFFFFFF })
        {
            byte[] bad = (byte[])file.Clone();
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bad.AsSpan(Log3.LengthOffset), value);
            CodeOf(bad);
        }

        Assert.Equal(ErrorCode.Hmac, Assert.Throws<ReplicaException>(() => ReplicaFile.Unpack(file, new KeyRing("wrong"))).Code);
    }

    [Fact]
    public void BrokenPayloadWithValidHmacNeverCrashes()
    {
        // власник пароля може запечатати будь-яке навантаження; розбір має завершитися або записами, або ReplicaException
        byte[] payload = Payload.Pack(SessionRecords(20), -10);
        var rng = new Random(7);
        for (int trial = 0; trial < 3000; trial++)
        {
            byte[] bad = (byte[])payload.Clone();
            for (int k = rng.Next(1, 4); k > 0; k--) bad[rng.Next(bad.Length)] = (byte)rng.Next(256);
            if (rng.Next(4) == 0) bad = bad[..rng.Next(bad.Length)];
            try
            {
                EventCodec.Decode(Payload.Unpack(bad).Records);
            }
            catch (ReplicaException)
            {
                // очікувано: E_PAYLOAD або E_CODE
            }
        }
    }
}
