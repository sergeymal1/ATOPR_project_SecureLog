namespace SecureLog.Security;

/// <summary>
/// Навмисно слабкий шифр для навчальної атаки: XOR із коротким ключем, що повторюється.
/// У робочому форматі LOG3 не використовується.
/// </summary>
public static class WeakCipher
{
    public static byte[] Apply(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
    {
        var res = new byte[data.Length];
        for (int i = 0; i < res.Length; i++) res[i] = (byte)(data[i] ^ key[i % key.Length]);
        return res;
    }
}
