namespace SecureLog.DP;

/// <summary>
/// Багатоваріантний рюкзак: для події i обирається r_i ∈ {0..R} копій, вартість r·cost[i], корисність utility[i][r].
/// maximize Σ utility[i][r_i]  за умови  Σ r_i·cost[i] ≤ budget.
/// </summary>
public static class Knapsack
{
    public static double Utility(double[][] utility, int[] copies) => copies.Select((r, i) => utility[i][r]).Sum();

    public static long Cost(int[] cost, int[] copies) => copies.Select((r, i) => (long)r * cost[i]).Sum();

    /// <summary>Точний розв'язок ДП за O(n·W·R): f[c] — найкраща корисність уже розглянутих подій за бюджету c.</summary>
    public static int[] SolveDp(int[] cost, double[][] utility, int budget)
    {
        int n = cost.Length;

        // якщо найкращі варіанти всіх подій разом вміщуються в бюджет, обмеження не діє і таблиця не потрібна
        var free = new int[n];
        for (int i = 0; i < n; i++)
            for (int r = 1; r < utility[i].Length; r++)
                if (utility[i][r] > utility[i][free[i]]) free[i] = r;
        if (Cost(cost, free) <= budget) return free;

        var f = new double[budget + 1];
        var next = new double[budget + 1];
        var choice = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            // локальні посилання: це найгарячіший цикл системи, n·W·R кроків на вікно
            int w = cost[i];
            double[] u = utility[i];
            byte[] ch = choice[i] = new byte[budget + 1];
            for (int c = 0; c <= budget; c++)
            {
                double best = f[c];
                byte bestR = 0;
                for (int r = 1, used = w; r < u.Length && used <= c; r++, used += w)
                {
                    double value = f[c - used] + u[r];
                    if (value > best)
                    {
                        best = value;
                        bestR = (byte)r;
                    }
                }
                next[c] = best;
                ch[c] = bestR;
            }
            (f, next) = (next, f);
        }

        var copies = new int[n];
        for (int i = n - 1, c = budget; i >= 0; i--)
        {
            copies[i] = choice[i][c];
            c -= copies[i] * cost[i];
        }
        return copies;
    }

    /// <summary>Жадібний baseline: щоразу додає ту наступну копію, що дає найбільший приріст корисності на одиницю вартості.</summary>
    public static int[] SolveGreedy(int[] cost, double[][] utility, int budget)
    {
        var copies = new int[cost.Length];
        var queue = new PriorityQueue<int, double>();
        double Ratio(int i) => (utility[i][copies[i] + 1] - utility[i][copies[i]]) / cost[i];

        for (int i = 0; i < cost.Length; i++)
            if (utility[i].Length > 1) queue.Enqueue(i, -Ratio(i));
        while (queue.TryDequeue(out int i, out double negRatio))
        {
            if (negRatio >= 0) break;            // далі лише недодатні прирости
            if (cost[i] > budget) continue;      // ця копія не вміщується; дешевші ще можуть
            budget -= cost[i];
            copies[i]++;
            if (copies[i] + 1 < utility[i].Length) queue.Enqueue(i, -Ratio(i));
        }
        return copies;
    }
}
