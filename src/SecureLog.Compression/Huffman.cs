using SecureLog.Core;

namespace SecureLog.Compression;

/// <summary>
/// Канонічний Гаффман над байтами (FORMAT_SPEC_P3, розділ 3.2). У потік потрапляють лише довжини кодів 1…15;
/// самі коди і кодер, і декодер виводять із довжин однаковим канонічним алгоритмом.
/// </summary>
public static class Huffman
{
    public const int MaxLength = 15;

    /// <summary>Довжини кодів для 256 символів (0 — символ не зустрічається), не довші за MaxLength.</summary>
    public static byte[] CodeLengths(int[] freq)
    {
        freq = (int[])freq.Clone();
        while (true)
        {
            byte[] lengths = TreeDepths(freq);
            if (lengths.Max() <= MaxLength) return lengths;
            // shortcut: довжину обмежено згладжуванням частот — дерево лишається повним, але не найкращим серед обмежених;
            // замінити на package-merge, якщо блоки з кодами довшими за 15 стануть типовими (потрібно понад 2500 байтів у блоці)
            for (int s = 0; s < 256; s++)
                if (freq[s] > 0) freq[s] = (freq[s] + 1) / 2;
        }
    }

    /// <summary>Глибини листків дерева Гаффмана; дерево будується чергою з пріоритетами.</summary>
    private static byte[] TreeDepths(int[] freq)
    {
        var lengths = new byte[256];
        var queue = new PriorityQueue<int, (long Freq, int Id)>();
        var symbol = new List<int>();   // symbol[v] — символ листка v
        var parent = new List<int>();   // parent[v] — батько вузла v; листки мають найменші номери
        for (int s = 0; s < 256; s++)
        {
            if (freq[s] == 0) continue;
            queue.Enqueue(parent.Count, (freq[s], parent.Count));
            symbol.Add(s);
            parent.Add(-1);
        }
        if (symbol.Count == 1)
        {
            lengths[symbol[0]] = 1;   // вироджений алфавіт: дерево з одного листка дало б код довжини 0
            return lengths;
        }
        while (queue.Count > 1)
        {
            queue.TryDequeue(out int a, out var fa);
            queue.TryDequeue(out int b, out var fb);
            int id = parent.Count;
            parent.Add(-1);
            parent[a] = parent[b] = id;
            queue.Enqueue(id, (fa.Freq + fb.Freq, id));
        }
        // батько завжди створений пізніше за дитину, тому йдемо від кореня вниз за спаданням номера
        var depth = new int[parent.Count];
        for (int v = parent.Count - 2; v >= 0; v--) depth[v] = depth[parent[v]] + 1;
        for (int v = 0; v < symbol.Count; v++) lengths[symbol[v]] = (byte)depth[v];
        return lengths;
    }

    /// <summary>Канонічні коди через bl_count і next_code: коротші коди числово менші, однакові за довжиною йдуть за зростанням символу.</summary>
    public static uint[] CanonicalCodes(byte[] lengths)
    {
        var blCount = new uint[MaxLength + 1];
        foreach (byte length in lengths)
            if (length > 0) blCount[length]++;

        var nextCode = new uint[MaxLength + 1];
        uint code = 0;
        for (int bits = 1; bits <= MaxLength; bits++)
        {
            code = (code + blCount[bits - 1]) << 1;
            nextCode[bits] = code;
        }

        var codes = new uint[256];
        for (int s = 0; s < 256; s++)
            if (lengths[s] > 0) codes[s] = nextCode[lengths[s]]++;
        return codes;
    }

    /// <summary>Перевіряє, що довжини задають повне префіксне дерево (сума Крафта = 1), а єдиний символ має довжину 1.</summary>
    public static void Validate(byte[] lengths)
    {
        int used = 0;
        long kraft = 0;   // у частках 2^-15
        foreach (byte length in lengths)
        {
            if (length == 0) continue;
            if (length > MaxLength) throw new ReplicaException(ErrorCode.Code, "довжина коду понад 15");
            used++;
            kraft += 1L << (MaxLength - length);
        }
        long required = used == 1 ? 1L << (MaxLength - 1) : 1L << MaxLength;
        if (used > 0 && kraft != required) throw new ReplicaException(ErrorCode.Code, "довжини кодів не задають повне префіксне дерево");
    }

    public static byte[] Encode(ReadOnlySpan<byte> data, byte[] lengths)
    {
        uint[] codes = CanonicalCodes(lengths);
        var writer = new BitWriter();
        foreach (byte b in data) writer.Write(codes[b], lengths[b]);
        return writer.ToArray();
    }

    /// <summary>Декодує рівно count символів і вимагає, щоб після них залишилось лише нульове доповнення останнього байта.</summary>
    public static byte[] Decode(byte[] lengths, ReadOnlySpan<byte> bitstream, int count)
    {
        Validate(lengths);
        int[] sorted = Enumerable.Range(0, 256).Where(s => lengths[s] > 0).OrderBy(s => lengths[s]).ThenBy(s => s).ToArray();
        var perLength = new int[MaxLength + 1];
        foreach (int s in sorted) perLength[lengths[s]]++;

        var reader = new BitReader(bitstream);
        var res = new byte[count];
        for (int i = 0; i < count; i++)
        {
            // first — перший канонічний код поточної довжини, index — його позиція в sorted
            int code = 0, first = 0, index = 0, length = 1;
            for (; length <= MaxLength; length++)
            {
                code |= reader.ReadBit();
                if (code - first < perLength[length])
                {
                    res[i] = (byte)sorted[index + code - first];
                    break;
                }
                index += perLength[length];
                first = (first + perLength[length]) << 1;
                code <<= 1;
            }
            if (length > MaxLength) throw new ReplicaException(ErrorCode.Code, "код відсутній у таблиці");
        }

        if ((reader.Position + 7) / 8 != bitstream.Length) throw new ReplicaException(ErrorCode.Code, "зайві байти після закодованих даних");
        while (reader.Position % 8 != 0)
            if (reader.ReadBit() != 0) throw new ReplicaException(ErrorCode.Code, "ненульове доповнення останнього байта");
        return res;
    }
}
