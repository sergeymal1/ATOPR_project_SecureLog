namespace SecureLog.ML;

/// <summary>Генетичний алгоритм загального вигляду: хромосома будь-якого типу, оператори передаються ззовні.</summary>
public static class Ga
{
    /// <param name="History">Найкраща пристосованість після покоління g (History[0] — початкова популяція).</param>
    public sealed record Result<T>(T Best, double Fitness, List<double> History, int Evaluations);

    /// <summary>Турнірна селекція, кросовер, мутація, елітизм.</summary>
    public static Result<T> Run<T>(Func<Random, T> create, Func<T, T, Random, T> crossover, Func<T, Random, T> mutate,
        Func<T, double> fitness, Random rng, int population = 12, int generations = 10, int elite = 2, int tournament = 3)
    {
        var pop = new List<(T Chromosome, double Fitness)>();
        while (pop.Count < population)
        {
            T c = create(rng);
            pop.Add((c, fitness(c)));
        }
        var history = new List<double>();
        int evaluations = population;
        for (int g = 0; ; g++)
        {
            pop.Sort((a, b) => b.Fitness.CompareTo(a.Fitness));
            history.Add(pop[0].Fitness);
            if (g == generations) break;

            // елітизм: найкращі переходять без змін і без повторного оцінювання, тому найкраща пристосованість не падає
            var next = pop.Take(elite).ToList();
            while (next.Count < population)
            {
                T child = mutate(crossover(Select(), Select(), rng), rng);
                next.Add((child, fitness(child)));
                evaluations++;
            }
            pop = next;
        }
        return new(pop[0].Chromosome, pop[0].Fitness, history, evaluations);

        // турнір: найкращий із tournament випадково взятих особин
        T Select()
        {
            var best = pop[rng.Next(pop.Count)];
            for (int i = 1; i < tournament; i++)
            {
                var rival = pop[rng.Next(pop.Count)];
                if (rival.Fitness > best.Fitness) best = rival;
            }
            return best.Chromosome;
        }
    }

    /// <summary>Випадковий пошук із тим самим числом обчислень пристосованості, що й у ГА з такими параметрами.</summary>
    public static Result<T> RandomSearch<T>(Func<Random, T> create, Func<T, double> fitness, Random rng,
        int population = 12, int generations = 10, int elite = 2)
    {
        var history = new List<double>();
        T best = default!;
        double bestFitness = double.NegativeInfinity;
        int evaluations = 0;
        for (int g = 0; g <= generations; g++)
        {
            for (int k = g == 0 ? population : population - elite; k > 0; k--, evaluations++)
            {
                T c = create(rng);
                double f = fitness(c);
                if (f > bestFitness) (best, bestFitness) = (c, f);
            }
            history.Add(bestFitness);
        }
        return new(best, bestFitness, history, evaluations);
    }
}
