using SecureLog.App;
using SecureLog.Core;
using SecureLog.ML;

namespace SecureLog.Tests.D1;

/// <summary>Додаткові перевірки D1, що стосуються базового рівня: кейси 4 (ГА) і 5 (вплив копій).</summary>
public class D1Tests
{
    private static readonly int[] Seeds = [1, 2, 3, 4, 5];

    [Fact]
    public void D4_ElitismNeverLosesBestAndRandomSearchGetsSameBudget()
    {
        // дешева функція в тому самому просторі трьох генів; справжня пристосованість (Q) логується командою `ga`
        static double Fitness(double[] g) => -(Math.Pow(g[0] - 0.3, 2) + Math.Pow(g[1] - 0.7, 2) + Math.Pow(g[2] - 0.5, 2));

        var ga = Ga.Run(Tuning.Create, Tuning.Crossover, Tuning.Mutate, Fitness, new Random(1), population: 12, generations: 20);
        var random = Ga.RandomSearch(Tuning.Create, Fitness, new Random(1), population: 12, generations: 20);

        for (int g = 1; g < ga.History.Count; g++) Assert.True(ga.History[g] >= ga.History[g - 1]);
        Assert.True(ga.Fitness >= ga.History[0]);
        Assert.Equal(ga.Evaluations, random.Evaluations);
        Assert.Equal(ga.History.Count, random.History.Count);
        Assert.True(ga.Fitness > -0.01, "ГА має підійти близько до максимуму");
    }

    [Fact]
    public void D5_ExtraCopiesRaiseRInEmergencyAndCostBits()
    {
        TeamConfig cfg = Workspace.Config();
        var pipeline = new Pipeline(cfg, Workspace.Model(), "d1-password");
        LogEvent[] session = Workspace.Session();
        var options = new RunOptions(Workspace.BestParams(cfg));

        (double R, double Bits) Mean(int copies)
        {
            var runs = Seeds.Select(seed => pipeline.RunSim(session, "emergency", seed, options with { MaxCopies = copies })).ToArray();
            return (runs.Average(r => r.Quality.R), runs.Average(r => r.StoredBits));
        }

        var (one, two, three) = (Mean(1), Mean(2), Mean(3));
        Assert.True(two.R > one.R, $"R: 1 копія {one.R:F3}, 2 копії {two.R:F3}");
        Assert.True(three.R > one.R, $"R: 1 копія {one.R:F3}, 3 копії {three.R:F3}");
        Assert.True(two.Bits > one.Bits && three.Bits >= two.Bits, "додаткові копії мають коштувати біти");
    }
}
