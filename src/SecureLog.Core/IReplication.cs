namespace SecureLog.Core;

/// <summary>
/// Те, що планувальнику й відновлювачу потрібно від моделі вузлів.
/// Реалізує Replication — порт виданого replication.py. Інтерфейс відокремлює модель від системи.
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

    /// <summary>true — копію збережено; false — відхилено до списання (бюджет, місткість) або втрачено у стані BAD (байти списано).</summary>
    bool Write(int node, byte[] batch);

    /// <summary>Копії, що вціліли на вузлі після сценарію відмов.</summary>
    IReadOnlyList<byte[]> Read(int node);
}
