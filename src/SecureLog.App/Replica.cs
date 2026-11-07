using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.Security;

namespace SecureLog.App;

/// <summary>Одна репліка LOG3 від записів до байтів і назад: записи → навантаження (стиснення) → шифрування → HMAC.</summary>
public static class Replica
{
    /// <summary>Байти одного batch понад самі записи: заголовок, HMAC і обов'язкові поля навантаження.</summary>
    public const int Overhead = Log3.Overhead + Payload.FixedSize;

    public static byte[] Build(Keys keys, ReadOnlySpan<byte> salt, ushort groupId, uint batchSeq, IReadOnlyList<LogEvent> batch,
        double minGain = 0, byte[]? classTable = null) =>
        Log3.Seal(keys, salt, groupId, batchSeq, Payload.Pack(EventCodec.Encode(batch), minGain, classTable));

    /// <summary>Кидає ReplicaException з кодом E_*, якщо репліка пошкоджена, підроблена або пароль невірний.</summary>
    public static LogEvent[] Open(ReadOnlySpan<byte> packet, KeyRing keys) =>
        EventCodec.Decode(Payload.Unpack(Log3.Open(packet, keys).Payload).Records);
}

/// <summary>Відновлювач: перевіряє й розшифровує всі вцілілі копії, усуває дублікати, повертає журнал за часом подій.</summary>
public static class Restorer
{
    public static (LogEvent[] Events, int Rejected) Restore(IEnumerable<byte[]> replicas, KeyRing keys)
    {
        var unique = new HashSet<LogEvent>();   // однакові 16 байтів = той самий запис, отриманий з іншого вузла
        int rejected = 0;
        foreach (byte[] packet in replicas)
        {
            try
            {
                unique.UnionWith(Replica.Open(packet, keys));
            }
            catch (ReplicaException)
            {
                rejected++;   // зіпсована копія не зупиняє відновлення: запис може вціліти на іншому вузлі
            }
        }
        return (unique.OrderBy(e => e.Time).ToArray(), rejected);
    }
}
