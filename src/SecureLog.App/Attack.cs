using System.Security.Cryptography;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.ML;
using SecureLog.Security;

namespace SecureLog.App;

/// <summary>Модуль атаки на навмисно слабкий шифр (XOR із коротким ключем). AES не атакується.</summary>
public static class Attack
{
    /// <summary>Демонстрація для CLI й UI: перші 16384 байти журналу шифруються випадковим ключем, ГА його відновлює.</summary>
    public static (byte[] Key, Ga.Result<byte[]> Result) Demo(LogEvent[] session, LogEvent[] training)
    {
        // 7 взаємно просте з 16 байтами запису: кожен байт ключа зустрічає всі поля, і частоти його видають.
        // За довжини 8 байт ключа, що припадає лише на молодші байти часу й показника, з частот не відновлюється.
        byte[] key = RandomNumberGenerator.GetBytes(7);
        byte[] plain = EventCodec.Encode(session)[..16384];
        return (key, RecoverKey(WeakCipher.Apply(plain, key), EventCodec.Encode(training), key.Length));
    }

    /// <summary>
    /// ГА відновлює ключ лише за шифротекстом. Пристосованість ключа — наскільки розшифрований ним текст
    /// схожий на журнал: середній логарифм імовірності байтів за частотами окремого навчального набору.
    /// </summary>
    public static Ga.Result<byte[]> RecoverKey(byte[] cipher, byte[] training, int keyLength, int seed = 1)
    {
        var logP = new double[256];
        var count = new int[256];
        foreach (byte b in training) count[b]++;
        for (int b = 0; b < 256; b++) logP[b] = Math.Log((count[b] + 1.0) / (training.Length + 256));   // згладжування Лапласа

        double Fitness(byte[] key)
        {
            double sum = 0;
            for (int i = 0; i < cipher.Length; i++) sum += logP[cipher[i] ^ key[i % keyLength]];
            return sum / cipher.Length;
        }

        return Ga.Run(
            create: rng =>
            {
                var key = new byte[keyLength];
                rng.NextBytes(key);
                return key;
            },
            crossover: (a, b, rng) => a.Select((x, i) => rng.Next(2) == 0 ? x : b[i]).ToArray(),
            mutate: (key, rng) =>
            {
                var copy = (byte[])key.Clone();
                if (rng.NextDouble() < 0.6) copy[rng.Next(keyLength)] = (byte)rng.Next(256);
                return copy;
            },
            Fitness, new Random(seed), population: 100, generations: 300);
    }
}
