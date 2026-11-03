using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SecureLog.Security;

/// <summary>Два незалежні ключі з одного пароля: для шифрування і для HMAC.</summary>
public sealed record Keys(byte[] Enc, byte[] Mac);

public static class Crypto
{
    public const int SaltSize = 16, NonceSize = 12, MacSize = 32;

    /// <summary>PBKDF2-HMAC-SHA256, 100000 ітерацій, dkLen = 64: K_enc = master[0:32], K_mac = master[32:64].</summary>
    public static Keys DeriveKeys(string password, ReadOnlySpan<byte> salt)
    {
        byte[] master = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 64);
        return new(master[..32], master[32..]);
    }

    /// <summary>
    /// AES-256-CTR: гама = AES_K(nonce(12) || uint32_BE(i)), i починається з 1.
    /// Шифрування і розшифрування — одна й та сама операція XOR із гамою.
    /// </summary>
    public static byte[] AesCtr(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> data)
    {
        if (key.Length != 32 || nonce.Length != NonceSize) throw new ArgumentException("потрібен ключ 32 байти і nonce 12 байтів");
        int blocks = (data.Length + 15) / 16;
        var counters = new byte[blocks * 16];
        for (int i = 0; i < blocks; i++)
        {
            nonce.CopyTo(counters.AsSpan(i * 16));
            BinaryPrimitives.WriteUInt32BigEndian(counters.AsSpan(i * 16 + NonceSize), (uint)(i + 1));
        }

        using var aes = Aes.Create();
        aes.Key = key;
        // ECB тут лише як «один блок AES на один лічильник»; сам режим CTR зібрано вручну
        byte[] stream = aes.EncryptEcb(counters, PaddingMode.None);

        var res = new byte[data.Length];
        for (int i = 0; i < res.Length; i++) res[i] = (byte)(data[i] ^ stream[i]);
        return res;
    }

    public static byte[] Hmac(byte[] key, ReadOnlySpan<byte> data) => HMACSHA256.HashData(key, data);
}

/// <summary>Кеш ключів за сіллю: PBKDF2 навмисно повільний, тому для однієї солі ключі виводяться один раз.</summary>
public sealed class KeyRing(string password)
{
    private readonly Dictionary<string, Keys> _cache = [];

    public Keys Get(ReadOnlySpan<byte> salt)
    {
        string id = Convert.ToHexString(salt);
        if (!_cache.TryGetValue(id, out Keys? keys)) _cache[id] = keys = Crypto.DeriveKeys(password, salt);
        return keys;
    }
}
