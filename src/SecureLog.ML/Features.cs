using SecureLog.Core;

namespace SecureLog.ML;

/// <summary>Ознаки для класифікації подій: мінімальний набір часових ознак із team_config.json і кілька допоміжних.</summary>
public static class Features
{
    /// <summary>
    /// Для події t вікно історії — події за останні windowMs мілісекунд, включно з нею (лише минуле: агент класифікує потік).
    /// Клас 1 видно з severity і стрибка metric_value, клас 2 — з часової структури: потік частішає,
    /// category і джерела змінюються, event_code іде серією сусідніх кодів.
    /// </summary>
    public static double[][] Extract(IReadOnlyList<LogEvent> events, int windowMs)
    {
        var res = new double[events.Count][];
        var lastMetric = new Dictionary<ushort, int>();   // попередній metric_value кожного джерела
        var sources = new HashSet<ushort>();
        int from = 0;
        for (int t = 0; t < events.Count; t++)
        {
            var cur = events[t];
            while (cur.Time - events[from].Time >= windowMs) from++;
            int n = t - from + 1;

            sources.Clear();
            int categoryChanges = 0, nearCodes = 0, severitySum = 0;
            for (int j = from; j <= t; j++)
            {
                var e = events[j];
                sources.Add(e.Source);
                severitySum += e.Severity;
                if (j == from) continue;
                if (e.Category != events[j - 1].Category) categoryChanges++;
                if (Math.Abs(e.Code - events[j - 1].Code) == 1) nearCodes++;
            }

            double gap = t > 0 ? cur.Time - events[t - 1].Time : windowMs;
            double metricJump = lastMetric.TryGetValue(cur.Source, out int previous) ? Math.Abs(cur.Metric - previous) : 0;
            lastMetric[cur.Source] = cur.Metric;

            res[t] =
            [
                // сім обов'язкових ознак у порядку team_config.json
                Math.Log(1 + gap),                       // інтервал до попередньої події
                n,                                       // кількість подій у ковзному вікні часу
                categoryChanges,                         // кількість змін category у вікні
                sources.Count,                           // кількість різних source_id у вікні
                n > 1 ? (double)nearCodes / (n - 1) : 0, // частка пар сусідніх подій із event_code, що різняться на 1
                Math.Log(1 + metricJump),                // зміна metric_value відносно попередньої події того самого джерела
                cur.Severity,
                // допоміжні
                (double)severitySum / n,                 // аномалії йдуть короткими серіями з високою severity
                Math.Abs(cur.Code - (t > 0 ? events[t - 1].Code : cur.Code)) == 1 ? 1 : 0,
            ];
        }
        return res;
    }
}
