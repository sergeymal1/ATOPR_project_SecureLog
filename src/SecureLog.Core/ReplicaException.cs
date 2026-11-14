namespace SecureLog.Core;

/// <summary>Коди відхилення репліки (FORMAT_SPEC_P3, розділ 5).</summary>
public static class ErrorCode
{
    public const string Short = "E_SHORT";
    public const string Magic = "E_MAGIC";
    public const string Length = "E_LENGTH";
    public const string Hmac = "E_HMAC";
    public const string Payload = "E_PAYLOAD";
    public const string Code = "E_CODE";
}

/// <summary>Репліку відхилено. Окремий тип — щоб відновлювач ловив лише «погані дані», а не помилки самої програми.</summary>
public sealed class ReplicaException(string code, string message) : Exception($"{code}: {message}")
{
    public string Code { get; } = code;

    /// <summary>Пояснення без коду — щоб доповнити його, наприклад, номером репліки у файлі.</summary>
    public string Detail { get; } = message;
}
