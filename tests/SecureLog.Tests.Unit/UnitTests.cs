using SecureLog.App;
using SecureLog.Compression;
using SecureLog.Core;
using SecureLog.DP;
using SecureLog.ML;
using SecureLog.Security;

namespace SecureLog.Tests.Unit;

/// <summary>Малі перевірки окремих алгоритмів; файлів даних не потребують.</summary>
public class UnitTests
{
    [Theory]   // RFC 3686, тест-вектори 7 і 9: блок лічильника nonce(4) || IV(8) || uint32_BE, що починається з 1
    [InlineData("776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104", "00000060DB5672C97AA8F0B2",
        "53696E676C6520626C6F636B206D7367", "145AD01DBF824EC7560863DC71E3E0C0")]
    [InlineData("FF7A617CE69148E4F1726E2F43581DE2AA62D9F805532EDFF1EED687FB54153D", "001CC5B751A51D70A1C11148",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223",
        "EB6C52821D0BBBF7CE7594462ACA4FAAB407DF866569FD07F48CC0B583D6071F1EC0E6B8")]
    public void AesCtr_MatchesRfc3686(string key, string nonce, string plain, string cipher)
    {
        byte[] k = Convert.FromHexString(key), n = Convert.FromHexString(nonce);
        Assert.Equal(cipher, Convert.ToHexString(Crypto.AesCtr(k, n, Convert.FromHexString(plain))));
        Assert.Equal(plain, Convert.ToHexString(Crypto.AesCtr(k, n, Convert.FromHexString(cipher))));
    }

    [Fact]
    public void Huffman_RoundTripsSkewedRandomData()
    {
        var rng = new Random(1);
        for (int trial = 0; trial < 200; trial++)
        {
            int alphabet = rng.Next(1, 257);
            byte[] data = Enumerable.Range(0, rng.Next(1, 3000)).Select(_ => (byte)(rng.Next(alphabet) * rng.Next(alphabet) / alphabet)).ToArray();
            byte[] lengths = Lengths(data);
            Assert.Equal(data, Huffman.Decode(lengths, Huffman.Encode(data, lengths), data.Length));
        }
    }

    [Fact]
    public void Huffman_LimitsCodeLengthTo15AndKeepsTreeComplete()
    {
        // частоти Фібоначчі дають найглибше можливе дерево: без обмеження 25 символів отримали б коди до 24 бітів
        var freq = new int[256];
        for (int i = 0, a = 1, b = 1; i < 25; i++, (a, b) = (b, a + b)) freq[i] = a;

        byte[] lengths = Huffman.CodeLengths(freq);

        Assert.True(lengths.Max() <= Huffman.MaxLength);
        Huffman.Validate(lengths);   // сума Крафта = 1, інакше виняток
        byte[] data = Enumerable.Range(0, 25).SelectMany(s => Enumerable.Repeat((byte)s, Math.Min(freq[s], 50))).ToArray();
        Assert.Equal(data, Huffman.Decode(lengths, Huffman.Encode(data, lengths), data.Length));
    }

    [Fact]
    public void Huffman_RejectsBadTablesAndBitstreams()
    {
        byte[] data = "abracadabra abracadabra"u8.ToArray();
        byte[] lengths = Lengths(data);
        byte[] bits = Huffman.Encode(data, lengths);
        string Code(Action action) => Assert.Throws<ReplicaException>(action).Code;

        var incomplete = (byte[])lengths.Clone();
        incomplete['a']++;   // сума Крафта < 1: дерево неповне
        Assert.Equal(ErrorCode.Code, Code(() => Huffman.Decode(incomplete, bits, data.Length)));

        var oversubscribed = (byte[])lengths.Clone();
        oversubscribed['z'] = 1;   // сума Крафта > 1: такого префіксного коду не існує
        Assert.Equal(ErrorCode.Code, Code(() => Huffman.Decode(oversubscribed, bits, data.Length)));

        var single = new byte[256];
        single['a'] = 2;   // єдиний символ мусить мати довжину 1
        Assert.Equal(ErrorCode.Code, Code(() => Huffman.Decode(single, [0], 1)));

        Assert.Equal(ErrorCode.Code, Code(() => Huffman.Decode(lengths, [.. bits, 0], data.Length)));     // зайвий повний байт
        Assert.Equal(ErrorCode.Code, Code(() => Huffman.Decode(lengths, bits[..^1], data.Length)));       // потік обірвано
    }

    [Fact]
    public void Payload_RejectsBrokenInvariants()
    {
        byte[] raw = EventCodec.Encode(Gen.Events(20, 7).Events);
        byte[] payload = Payload.Pack(raw, minGain: -10);
        int counts = 6 + 2 * ((payload[4] << 8) | payload[5]);
        string Code(byte[] p) => Assert.Throws<ReplicaException>(() => Payload.Unpack(p)).Code;
        byte[] With(int index, byte value)
        {
            var copy = (byte[])payload.Clone();
            copy[index] = value;
            return copy;
        }

        Assert.Equal(raw, Payload.Unpack(payload).Records);
        Assert.Equal(ErrorCode.Payload, Code(With(counts + 3, (byte)(payload[counts + 3] ^ 1))));   // symbol_count ≠ 16 × record_count
        Assert.Equal(ErrorCode.Payload, Code(With(1, (byte)(payload[1] + 1))));                     // record_count змінено
        Assert.Equal(ErrorCode.Payload, Code([.. payload, 0]));                                     // зайвий байт після навантаження
        Assert.Equal(ErrorCode.Payload, Code(payload[..10]));
        Assert.Equal(ErrorCode.Code, Code(With(7, 0)));                                             // довжина коду 0
        Assert.Equal(ErrorCode.Code, Code(With(8, payload[6])));                                    // символи не за зростанням

        byte[] classes = Enumerable.Repeat((byte)2, 20).ToArray();
        Assert.Equal(classes, Payload.Unpack(Payload.Pack(raw, classTable: classes)).ClassTable);
        classes[5] = 3;   // 3…255 зарезервовано
        Assert.Equal(ErrorCode.Payload, Code(Payload.Pack(raw, classTable: classes)));
    }

    private static byte[] Lengths(byte[] data)
    {
        var freq = new int[256];
        foreach (byte b in data) freq[b]++;
        return Huffman.CodeLengths(freq);
    }

    [Fact]
    public void Knapsack_GreedyCounterExample()
    {
        // бюджет 10: жадібний бере A (7/6 — найкраще відношення) і більше нічого не вміщується; оптимум — B + C
        int[] cost = [6, 5, 5];
        double[][] utility = [[0, 7], [0, 5], [0, 5]];
        Assert.Equal(7, Knapsack.Utility(utility, Knapsack.SolveGreedy(cost, utility, 10)));
        Assert.Equal(10, Knapsack.Utility(utility, Knapsack.SolveDp(cost, utility, 10)));
    }

    [Fact]
    public void Knapsack_DpMatchesBruteForce()
    {
        var rng = new Random(2);
        for (int trial = 0; trial < 200; trial++)
        {
            int n = rng.Next(1, 7), budget = rng.Next(0, 40);
            int[] cost = Enumerable.Range(0, n).Select(_ => rng.Next(1, 12)).ToArray();
            // корисність зі зменшуваною віддачею v·(1, 1+k, 1+k+k²) мінус ціна зберігання: у системі ціни немає,
            // але з нею прирости бувають від'ємними, і ДП має вміти взяти менше копій, ніж дозволяє бюджет
            double[][] utility = cost.Select(c =>
            {
                double v = rng.Next(1, 30), k = rng.NextDouble(), price = rng.NextDouble();
                return new[] { 0, v - price * c, v * (1 + k) - 2 * price * c, v * (1 + k + k * k) - 3 * price * c };
            }).ToArray();

            double best = 0;
            for (int mask = 0; mask < 1 << (2 * n); mask++)
            {
                int[] copies = Enumerable.Range(0, n).Select(i => (mask >> (2 * i)) & 3).ToArray();
                if (Knapsack.Cost(cost, copies) <= budget) best = Math.Max(best, Knapsack.Utility(utility, copies));
            }

            int[] dp = Knapsack.SolveDp(cost, utility, budget);
            Assert.True(Knapsack.Cost(cost, dp) <= budget);
            Assert.Equal(best, Knapsack.Utility(utility, dp), 9);
        }
    }

    [Fact]
    public void Placement_PutsCopiesOnDistinctNodesWithinRoom()
    {
        var rng = new Random(3);
        int n = 200;
        int[] copies = Enumerable.Range(0, n).Select(_ => rng.Next(0, 4)).ToArray();
        int[] cost = Enumerable.Range(0, n).Select(_ => rng.Next(8, 20)).ToArray();
        double[] value = Enumerable.Range(0, n).Select(_ => (double)rng.Next(1, 30)).ToArray();
        long[] room = [1500, 1500, 900];

        List<int>[] batches = Placement.Assign(copies, cost, value, [0.95, 0.9, 0.8], room);

        for (int k = 0; k < 3; k++)
        {
            Assert.Equal(batches[k].Count, batches[k].Distinct().Count());
            Assert.True(batches[k].Sum(i => cost[i]) <= room[k]);
        }
        for (int i = 0; i < n; i++) Assert.True(batches.Count(b => b.Contains(i)) <= copies[i]);
        Assert.True(batches.Sum(b => b.Count) > 0);
    }

    [Fact]
    public void Mlp_LearnsXor()
    {
        // XOR не розділяється лінійно: без прихованого шару і правильного backpropagation його не вивчити
        var rng = new Random(4);
        double[][] x = Enumerable.Range(0, 200).Select(i => new[] { i % 2 + 0.1 * rng.NextDouble(), i / 2 % 2 + 0.1 * rng.NextDouble() }).ToArray();
        int[] y = Enumerable.Range(0, 200).Select(i => i % 2 ^ (i / 2 % 2)).ToArray();

        var (model, f1) = Mlp.TrainBest(x, y, x, y, hidden: [8], seeds: 3, epochs: 400);

        Assert.Equal(1.0, f1, 6);
        Assert.Equal(0, model.Predict([0, 0]));
        Assert.Equal(1, model.Predict([1, 0]));
    }

    [Fact]
    public void Attack_GaRecoversWeakCipherKey()
    {
        byte[] training = EventCodec.Encode(Gen.Events(3000, 6).Events);
        byte[] plain = EventCodec.Encode(Gen.Events(1000, 5).Events);
        // довжина ключа взаємно проста з розміром запису (16): так кожен байт ключа зустрічає всі поля запису
        byte[] key = [0x3A, 0xC1, 0x07, 0xEE, 0x52, 0x99, 0x10];

        var result = Attack.RecoverKey(WeakCipher.Apply(plain, key), training, key.Length);

        Assert.Equal(key, result.Best);
        Assert.True(result.History[^1] >= result.History[0]);
    }
}
