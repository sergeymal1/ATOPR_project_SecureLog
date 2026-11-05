using System.Text.Json;

namespace SecureLog.ML;

/// <summary>
/// Багатошаровий перцептрон без сторонніх бібліотек: ReLU у прихованих шарах, softmax на виході,
/// крос-ентропія, зворотне поширення помилки, Adam.
/// </summary>
public sealed class Mlp
{
    /// <summary>Розміри шарів: [вхід, приховані..., вихід].</summary>
    public int[] Sizes { get; init; } = [];

    /// <summary>W[l][j * Sizes[l] + i] — вага зв'язку від нейрона i шару l до нейрона j шару l+1.</summary>
    public double[][] W { get; init; } = [];

    public double[][] B { get; init; } = [];

    /// <summary>Середнє і відхилення ознак на train — вхід стандартизується тими самими числами і при навчанні, і при прогнозі.</summary>
    public double[] Mean { get; set; } = [];

    public double[] Std { get; set; } = [];

    public static Mlp Create(int[] sizes, Random rng)
    {
        var w = new double[sizes.Length - 1][];
        var b = new double[sizes.Length - 1][];
        for (int l = 0; l < w.Length; l++)
        {
            // ініціалізація Хе: дисперсія 2/n_in, щоб сигнал не згасав і не вибухав за ReLU
            double scale = Math.Sqrt(2.0 / sizes[l]);
            w[l] = Enumerable.Range(0, sizes[l] * sizes[l + 1]).Select(_ => Gauss(rng) * scale).ToArray();
            b[l] = new double[sizes[l + 1]];
        }
        return new Mlp { Sizes = sizes, W = w, B = b };
    }

    public int Predict(double[] features)
    {
        double[] p = Forward(Scale(features))[^1];
        return Array.IndexOf(p, p.Max());
    }

    public void Train(double[][] x, int[] y, int epochs, Random rng, double learningRate = 0.003, int batch = 32)
    {
        int n = x.Length, classes = Sizes[^1];
        FitScaler(x);
        double[][] xs = x.Select(Scale).ToArray();

        // ваги класів обернено пропорційні частоті: без них рідкісні класи 1 і 2 губляться і macro-F1 падає
        var classWeight = new double[classes];
        for (int c = 0; c < classes; c++) classWeight[c] = (double)n / (classes * Math.Max(1, y.Count(v => v == c)));

        double[][] mW = Zeros(W), vW = Zeros(W), mB = Zeros(B), vB = Zeros(B);
        int[] order = Enumerable.Range(0, n).ToArray();
        int step = 0;
        for (int epoch = 0; epoch < epochs; epoch++)
        {
            rng.Shuffle(order);
            for (int start = 0; start < n; start += batch)
            {
                int size = Math.Min(batch, n - start);
                double[][] gW = Zeros(W), gB = Zeros(B);
                for (int k = start; k < start + size; k++)
                {
                    int sample = order[k];
                    double[][] a = Forward(xs[sample]);

                    // для softmax із крос-ентропією похідна за входом вихідного шару — це p − onehot
                    var delta = (double[])a[^1].Clone();
                    delta[y[sample]] -= 1;
                    for (int j = 0; j < delta.Length; j++) delta[j] *= classWeight[y[sample]];

                    for (int l = W.Length - 1; l >= 0; l--)
                    {
                        int nIn = Sizes[l];
                        var previous = new double[nIn];
                        for (int j = 0; j < delta.Length; j++)
                        {
                            gB[l][j] += delta[j];
                            for (int i = 0; i < nIn; i++)
                            {
                                gW[l][j * nIn + i] += delta[j] * a[l][i];
                                previous[i] += W[l][j * nIn + i] * delta[j];
                            }
                        }
                        // похідна ReLU: помилка проходить лише через активні нейрони
                        if (l > 0)
                            for (int i = 0; i < nIn; i++)
                                if (a[l][i] <= 0) previous[i] = 0;
                        delta = previous;
                    }
                }
                step++;
                for (int l = 0; l < W.Length; l++)
                {
                    AdamStep(W[l], gW[l], mW[l], vW[l], learningRate, step, size);
                    AdamStep(B[l], gB[l], mB[l], vB[l], learningRate, step, size);
                }
            }
        }
    }

    /// <summary>Матриця помилок: рядок — справжній клас, стовпець — передбачений.</summary>
    public int[,] Confusion(double[][] x, int[] y)
    {
        var cm = new int[Sizes[^1], Sizes[^1]];
        for (int i = 0; i < x.Length; i++) cm[y[i], Predict(x[i])]++;
        return cm;
    }

    /// <summary>Macro-F1: F1 рахується для кожного класу окремо й усереднюється без урахування розміру класу.</summary>
    public static double MacroF1(int[,] cm)
    {
        int classes = cm.GetLength(0);
        double sum = 0;
        for (int c = 0; c < classes; c++)
        {
            double tp = cm[c, c], actual = 0, predicted = 0;
            for (int k = 0; k < classes; k++)
            {
                actual += cm[c, k];
                predicted += cm[k, c];
            }
            sum += actual + predicted == 0 ? 0 : 2 * tp / (actual + predicted);
        }
        return sum / classes;
    }

    /// <summary>Протокол навчання: кілька ініціалізацій, модель обирається за macro-F1 на valid.</summary>
    public static (Mlp Model, double F1) TrainBest(double[][] trainX, int[] trainY, double[][] validX, int[] validY,
        int[] hidden, int seeds = 3, int epochs = 30, Action<string>? log = null)
    {
        int[] sizes = [trainX[0].Length, .. hidden, trainY.Max() + 1];
        (Mlp Model, double F1) best = default;
        for (int seed = 1; seed <= seeds; seed++)
        {
            var rng = new Random(seed);
            var model = Create(sizes, rng);
            model.Train(trainX, trainY, epochs, rng);
            double f1 = MacroF1(model.Confusion(validX, validY));
            log?.Invoke($"ініціалізація {seed}: macro-F1 на valid = {f1:F4}");
            if (best.Model is null || f1 > best.F1) best = (model, f1);
        }
        return best;
    }

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(this));

    public static Mlp Load(string path) =>
        JsonSerializer.Deserialize<Mlp>(File.ReadAllText(path)) ?? throw new InvalidDataException($"порожня модель: {path}");

    /// <summary>Прямий прохід. a[0] — вхід, a[l] — активації шару l, останній елемент — імовірності класів.</summary>
    private double[][] Forward(double[] x)
    {
        var a = new double[Sizes.Length][];
        a[0] = x;
        for (int l = 0; l < W.Length; l++)
        {
            int nIn = Sizes[l], nOut = Sizes[l + 1];
            var z = new double[nOut];
            for (int j = 0; j < nOut; j++)
            {
                double s = B[l][j];
                for (int i = 0; i < nIn; i++) s += W[l][j * nIn + i] * a[l][i];
                z[j] = l < W.Length - 1 ? Math.Max(0, s) : s;
            }
            a[l + 1] = z;
        }

        // softmax; максимум віднімається, щоб exp не переповнювався
        double[] output = a[^1];
        double max = output.Max(), total = 0;
        for (int j = 0; j < output.Length; j++) total += output[j] = Math.Exp(output[j] - max);
        for (int j = 0; j < output.Length; j++) output[j] /= total;
        return a;
    }

    private void FitScaler(double[][] x)
    {
        int d = x[0].Length;
        Mean = new double[d];
        Std = new double[d];
        for (int j = 0; j < d; j++)
        {
            Mean[j] = x.Average(row => row[j]);
            double variance = x.Average(row => (row[j] - Mean[j]) * (row[j] - Mean[j]));
            Std[j] = variance < 1e-12 ? 1 : Math.Sqrt(variance);
        }
    }

    private double[] Scale(double[] x) => x.Select((v, j) => (v - Mean[j]) / Std[j]).ToArray();

    private static void AdamStep(double[] p, double[] g, double[] m, double[] v, double lr, int step, int batch)
    {
        const double b1 = 0.9, b2 = 0.999;
        for (int i = 0; i < p.Length; i++)
        {
            double grad = g[i] / batch;
            m[i] = b1 * m[i] + (1 - b1) * grad;
            v[i] = b2 * v[i] + (1 - b2) * grad * grad;
            // поправка на зміщення: на перших кроках m і v ще близькі до нуля
            double mHat = m[i] / (1 - Math.Pow(b1, step)), vHat = v[i] / (1 - Math.Pow(b2, step));
            p[i] -= lr * mHat / (Math.Sqrt(vHat) + 1e-8);
        }
    }

    private static double[][] Zeros(double[][] like) => like.Select(row => new double[row.Length]).ToArray();

    // перетворення Бокса — Мюллера
    private static double Gauss(Random rng) =>
        Math.Sqrt(-2 * Math.Log(1 - rng.NextDouble())) * Math.Cos(2 * Math.PI * rng.NextDouble());
}
