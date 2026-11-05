namespace SecureLog.DP;

/// <summary>Порядок реплікації: на який вузол і в якій черзі писати вже обрані копії.</summary>
public static class Placement
{
    /// <summary>
    /// Жадібна евристика. Першою береться подія з найбільшим приростом очікуваної відновлюваності на біт ваги
    /// (цінність × імовірність, що попередні копії не вціліли), і кладеться на найнадійніший вузол,
    /// у batch якого ще є місце. Копії однієї події потрапляють лише на різні вузли.
    /// Повертає для кожного вузла номери подій у порядку запису.
    /// </summary>
    public static List<int>[] Assign(int[] copies, int[] cost, double[] value, double[] reliability, long[] room)
    {
        int nodes = reliability.Length;
        var batches = new List<int>[nodes];
        for (int k = 0; k < nodes; k++) batches[k] = [];

        var free = (long[])room.Clone();
        var left = (int[])copies.Clone();
        var miss = Enumerable.Repeat(1.0, copies.Length).ToArray();
        var placed = new bool[copies.Length, nodes];
        var queue = new PriorityQueue<int, double>();
        for (int i = 0; i < copies.Length; i++)
            if (left[i] > 0) queue.Enqueue(i, -value[i] / cost[i]);

        while (queue.TryDequeue(out int i, out _))
        {
            // вирівнювати заповнення вузлів не варто: кожен зайвий batch — це ще один заголовок і таблиця довжин
            int best = -1;
            for (int k = 0; k < nodes; k++)
                if (!placed[i, k] && free[k] >= cost[i] && (best < 0 || reliability[k] > reliability[best])) best = k;
            if (best < 0) continue;   // місця на вільних для події вузлах немає — решта її копій відкидається

            batches[best].Add(i);
            placed[i, best] = true;
            free[best] -= cost[i];
            miss[i] *= 1 - reliability[best];
            if (--left[i] > 0) queue.Enqueue(i, -value[i] * miss[i] / cost[i]);
        }
        return batches;
    }
}
