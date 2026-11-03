using System.Buffers.Binary;
using System.Security.Cryptography;
using SecureLog.Core;

namespace SecureLog.Security;

/// <summary>
/// Репліка LOG3 (FORMAT_SPEC_P3, розділ 2, big-endian):
/// "LOG3" 4 | version 1 | replica_group_id 2 | batch_seq 4 | salt 16 | nonce 12 | ciphertext_len 4 | шифротекст | HMAC-SHA256 32.
/// Порядок: стиснути → зашифрувати → HMAC над заголовком і шифротекстом (Encrypt-then-MAC).
/// </summary>
public static class Log3
{
    public const byte Version = 1;
    public const int HeaderSize = 43, GroupOffset = 5, SeqOffset = 7, SaltOffset = 11, NonceOffset = 27, LengthOffset = 39;
    public const int Overhead = HeaderSize + Crypto.MacSize;

    private static ReadOnlySpan<byte> Magic => "LOG3"u8;

    public static byte[] Seal(Keys keys, ReadOnlySpan<byte> salt, ushort groupId, uint batchSeq, ReadOnlySpan<byte> payload)
    {
        var packet = new byte[Overhead + payload.Length];
        var s = packet.AsSpan();
        Magic.CopyTo(s);
        s[4] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(s[GroupOffset..], groupId);
        BinaryPrimitives.WriteUInt32BigEndian(s[SeqOffset..], batchSeq);
        salt.CopyTo(s[SaltOffset..]);
        // nonce не повинен повторюватися з тим самим ключем: інакше XOR двох шифротекстів дає XOR відкритих текстів
        var nonce = s.Slice(NonceOffset, Crypto.NonceSize);
        RandomNumberGenerator.Fill(nonce);
        BinaryPrimitives.WriteUInt32BigEndian(s[LengthOffset..], (uint)payload.Length);

        Crypto.AesCtr(keys.Enc, nonce, payload).CopyTo(s[HeaderSize..]);
        Crypto.Hmac(keys.Mac, s[..^Crypto.MacSize]).CopyTo(s[^Crypto.MacSize..]);
        return packet;
    }

    /// <summary>
    /// Порядок приймання з розділу 5: мінімальна довжина → magic/version → точна довжина → HMAC за сталий час →
    /// і лише після цього розшифрування. Повертає відкрите навантаження; його розбирає Payload.Unpack.
    /// </summary>
    public static (ushort GroupId, uint BatchSeq, byte[] Payload) Open(ReadOnlySpan<byte> packet, KeyRing keys)
    {
        if (packet.Length < Overhead) throw new ReplicaException(ErrorCode.Short, "репліка коротша за заголовок і HMAC");
        if (!packet[..4].SequenceEqual(Magic) || packet[4] != Version) throw new ReplicaException(ErrorCode.Magic, "невірний magic або версія");
        if (Overhead + (long)BinaryPrimitives.ReadUInt32BigEndian(packet[LengthOffset..]) != packet.Length)
            throw new ReplicaException(ErrorCode.Length, "довжина репліки не дорівнює 43 + ciphertext_len + 32");

        Keys k = keys.Get(packet.Slice(SaltOffset, Crypto.SaltSize));
        byte[] mac = Crypto.Hmac(k.Mac, packet[..^Crypto.MacSize]);
        // порівняння за сталий час, щоб час відповіді не видавав, скільки байтів HMAC збіглося
        if (!CryptographicOperations.FixedTimeEquals(mac, packet[^Crypto.MacSize..]))
            throw new ReplicaException(ErrorCode.Hmac, "HMAC не збігається: репліку змінено або пароль невірний");

        byte[] payload = Crypto.AesCtr(k.Enc, packet.Slice(NonceOffset, Crypto.NonceSize), packet[HeaderSize..^Crypto.MacSize]);
        return (BinaryPrimitives.ReadUInt16BigEndian(packet[GroupOffset..]), BinaryPrimitives.ReadUInt32BigEndian(packet[SeqOffset..]), payload);
    }
}
