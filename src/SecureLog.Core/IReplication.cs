namespace SecureLog.Core;

/// <summary>
/// Те, що планувальнику й відновлювачу потрібно від моделі вузлів.
/// Реалізує SimReplication. Інтерфейс відокремлює модель від системи: її можна замінити іншою, не чіпаючи планувальник.
/// </summary>
public interface IReplication
{
    int NodeCount { get; }
    int MaxBatchBytes { get; }
    long BudgetBytes { get; }

    /// <summary>global_used_bytes: усі списані спроби запису, включно з втраченими через стан BAD.</summary>
    long UsedBytes { get; }

    double Reliability(int node);
    long FreeBytes(int node);

    /// <summary>false — запис відхилено до списання (бюджет, місткість або розмір batch). Втрата через BAD відправнику не видна.</summary>
    bool Write(int node, byte[] batch);

    /// <summary>Копії, що вціліли на вузлі після сценарію відмов.</summary>
    IReadOnlyList<byte[]> Read(int node);
}
