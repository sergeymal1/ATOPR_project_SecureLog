using SecureLog.App;
using SecureLog.Compression;
using SecureLog.Core;
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
}
