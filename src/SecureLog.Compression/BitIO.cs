using SecureLog.Core;

namespace SecureLog.Compression;

/// <summary>Запис бітів від старшого до молодшого (MSB-first); останній байт доповнюється нулями.</summary>
public sealed class BitWriter
{
    private readonly List<byte> _bytes = [];
    private int _acc, _count;

    public void Write(uint code, int length)
    {
        for (int i = length - 1; i >= 0; i--)
        {
            _acc = (_acc << 1) | (int)((code >> i) & 1);
            if (++_count == 8)
            {
                _bytes.Add((byte)_acc);
                _acc = _count = 0;
            }
        }
    }

    public byte[] ToArray()
    {
        var res = new List<byte>(_bytes);
        if (_count > 0) res.Add((byte)(_acc << (8 - _count)));
        return res.ToArray();
    }
}

/// <summary>Читання бітів від старшого до молодшого.</summary>
public ref struct BitReader(ReadOnlySpan<byte> data)
{
    private readonly ReadOnlySpan<byte> _data = data;

    /// <summary>Скільки бітів уже прочитано.</summary>
    public int Position { get; private set; }

    public int ReadBit()
    {
        if (Position >= _data.Length * 8) throw new ReplicaException(ErrorCode.Code, "бітовий потік закінчився раніше, ніж очікувалось");
        int bit = (_data[Position >> 3] >> (7 - (Position & 7))) & 1;
        Position++;
        return bit;
    }
}
