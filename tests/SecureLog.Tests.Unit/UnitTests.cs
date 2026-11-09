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
}
