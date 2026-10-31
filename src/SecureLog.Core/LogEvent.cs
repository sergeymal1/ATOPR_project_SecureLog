namespace SecureLog.Core;

/// <summary>
/// Запис журналу (FORMAT_SPEC_P3, розділ 1). Окремого номера запис не має:
/// ідентичність — це його точне 16-байтове подання, тому копії з різних вузлів зливаються порівнянням усіх полів.
/// </summary>
public readonly record struct LogEvent(
    uint Time, ushort Source, ushort Code, int Metric, byte Category, byte Severity, bool Critical, byte Flags);
