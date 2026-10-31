namespace SecureLog.Core;

/// <summary>Єдина метрика: S — ефективність ресурсу, R — частка відновлених критичних подій, T — швидкодія.</summary>
public readonly record struct Quality(double S, double R, double T, double Q)
{
    public static Quality Compute(TeamConfig c, long rawBits, long storedBits, int critTotal, int critRestored, double seconds)
    {
        double s = rawBits == 0 ? 0 : (double)rawBits / (rawBits + storedBits);
        double r = critTotal == 0 ? 1 : (double)critRestored / critTotal;
        double t = c.TRef / (c.TRef + seconds);
        // за умовою: не відновлено жодної критичної події — Q = 0
        double q = critTotal > 0 && critRestored == 0 ? 0 : c.Alpha * s + c.Beta * r + c.Gamma * t;
        return new(s, r, t, q);
    }
}
