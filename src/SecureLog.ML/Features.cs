using SecureLog.Core;

namespace SecureLog.ML;

/// <summary>Ознаки для класифікації подій: миттєві та часові, пораховані за вікном історії.</summary>
public static class Features
{
    public const int Count = 13;

    /// <summary>
    /// Для події t береться вікно [t−window+1, t]. Клас 1 видно з миттєвих ознак (severity, стрибок metric),
    /// клас 2 — лише з часових: потік частішає, category і джерела стрибають, коди йдуть спорідненою серією.
    /// </summary>
    public static double[][] Extract(IReadOnlyList<LogEvent> events, int window)
    {
        var res = new double[events.Count][];
        var categories = new HashSet<int>();
        var sources = new HashSet<int>();
        var codes = new HashSet<int>();
        for (int t = 0; t < events.Count; t++)
        {
            var cur = events[t];
            int from = Math.Max(0, t - window + 1), n = t - from + 1;
            categories.Clear();
            sources.Clear();
            codes.Clear();
            double sum = 0, sumSq = 0, severitySum = 0;
            int switches = 0, nearCodes = 0;
            for (int j = from; j <= t; j++)
            {
                var e = events[j];
                categories.Add(e.Category);
                sources.Add(e.Source);
                codes.Add(e.Code);
                sum += e.Metric;
                sumSq += (double)e.Metric * e.Metric;
                severitySum += e.Severity;
                if (j > from && e.Category != events[j - 1].Category) switches++;
                if (Math.Abs(e.Code - cur.Code) <= 3) nearCodes++;
            }
            double mean = sum / n, std = Math.Sqrt(Math.Max(0, sumSq / n - mean * mean));

            // середній інтервал між подіями за все вікно і за його останню чверть: їхня різниця показує прискорення потоку
            int quarter = Math.Max(from, t - Math.Max(1, window / 4));
            double gapLong = n > 1 ? ((double)cur.Time - events[from].Time) / (n - 1) : 0;
            double gapShort = t > quarter ? ((double)cur.Time - events[quarter].Time) / (t - quarter) : gapLong;

            res[t] =
            [
                cur.Severity,
                cur.Metric,
                t > 0 ? Math.Abs(cur.Metric - events[t - 1].Metric) : 0,
                Math.Abs(cur.Metric - mean) / (std + 1e-9),
                Math.Log(1 + Math.Max(0, gapLong)),
                Math.Log(1 + Math.Max(0, gapShort)) - Math.Log(1 + Math.Max(0, gapLong)),
                (double)categories.Count / n,
                (double)switches / n,
                (double)sources.Count / n,
                (double)codes.Count / n,
                (double)nearCodes / n,
                severitySum / n,
                cur.Critical ? 1 : 0,
            ];
        }
        return res;
    }
}
