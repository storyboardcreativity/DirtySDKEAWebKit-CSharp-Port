using System;
using System.Linq;
using System.Numerics;
using DirtySDKEAWebKit;
using Xunit;

namespace DirtySDKEAWebKit.Tests;

public class CryptRSAMathTests
{
    private static BigInteger FromBytes(byte[] bytes) =>
        new BigInteger(bytes, isUnsigned: true, isBigEndian: true);

    private static byte[] ToFixedBytes(BigInteger value, int length)
    {
        if (value < 0)
            throw new ArgumentOutOfRangeException(nameof(value));

        byte[] raw = value.ToByteArray(
            isUnsigned: true,
            isBigEndian: true);

        if (raw.Length > length)
            throw new ArgumentException("Value does not fit.");

        byte[] result = new byte[length];
        Buffer.BlockCopy(
            raw, 0, result, length - raw.Length, raw.Length);

        return result;
    }

    private static BigInteger FromWords(ushort[] words)
    {
        byte[] bytes = new byte[words.Length * 2];

        for (int i = 0; i < words.Length; i++)
        {
            bytes[i * 2] = (byte)(words[i] >> 8);
            bytes[i * 2 + 1] = (byte)words[i];
        }

        return FromBytes(bytes);
    }

    private static ushort[] ToWords(BigInteger value, int width)
    {
        byte[] bytes = ToFixedBytes(value, width * 2);
        ushort[] words = new ushort[width];

        for (int i = 0; i < width; i++)
        {
            words[i] = (ushort)(
                (bytes[i * 2] << 8) | bytes[i * 2 + 1]);
        }

        return words;
    }

    [Theory]
    [InlineData(0, 0, 0, 0)]
    [InlineData(1, 2, 0, 3)]
    [InlineData(65535, 1, 1, 0)]
    [InlineData(65535, 65535, 1, 65534)]
    public void Addition_OneWord_ReturnsCorrectResultAndCarry(
        int a, int b, int expectedCarry, int expectedLowWord)
    {
        ushort[] left = { (ushort)a };
        ushort[] right = { (ushort)b };
        ushort[] result = new ushort[1];

        int carry = CryptRSA.Addition(result, 1, left, right);

        Assert.Equal(expectedCarry, carry);
        Assert.Equal(expectedLowWord, result[0]);
        Assert.Equal((a + b) & 0xFFFF, result[0]);
        Assert.Equal((a + b) >> 16, carry);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    [InlineData(65535, 1)]
    [InlineData(32768, 32767)]
    public void Subtract_OneWord_ReturnsCorrectResultAndBorrow(
        int a, int b)
    {
        ushort[] left = { (ushort)a };
        ushort[] right = { (ushort)b };
        ushort[] result = new ushort[1];

        int borrow = CryptRSA.Subtract(
            result, 1, left, right);

        int expectedBorrow = a < b ? 1 : 0;
        int expectedResult = (a - b) & 0xFFFF;

        Assert.Equal(expectedBorrow, borrow);
        Assert.Equal(expectedResult, result[0]);
    }

    [Fact]
    public void Addition_MultipleWords_PropagatesCarry()
    {
        ushort[] a = { 0xFFFF, 0xFFFF, 0xFFFF };
        ushort[] b = { 0x0000, 0x0000, 0x0001 };
        ushort[] result = new ushort[3];

        int carry = CryptRSA.Addition(result, 3, a, b);

        Assert.Equal(1, carry);
        Assert.Equal(new ushort[] { 0, 0, 0 }, result);
    }

    [Fact]
    public void Subtract_MultipleWords_PropagatesBorrow()
    {
        ushort[] a = { 0x0001, 0x0000, 0x0000 };
        ushort[] b = { 0x0000, 0x0000, 0x0001 };
        ushort[] result = new ushort[3];

        int borrow = CryptRSA.Subtract(result, 3, a, b);

        Assert.Equal(0, borrow);
        Assert.Equal(
            new ushort[] { 0, 0xFFFF, 0xFFFF },
            result);
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(1, 15)]
    [InlineData(2, 16)]
    [InlineData(2, 31)]
    [InlineData(3, 32)]
    [InlineData(3, 47)]
    public void BitTest_UsesBigEndianWordOrder(int width, int bit)
    {
        ushort[] words = new ushort[width];
        int byteBits = width * 16;

        // Установим только проверяемый бит.
        int wordIndex = width - 1 - bit / 16;
        int bitInWord = bit % 16;
        words[wordIndex] = (ushort)(1 << bitInWord);

        Assert.NotEqual(
            0,
            CryptRSA.BitTest(words, width, bit));

        // Соседние биты не должны срабатывать.
        if (bit + 1 < byteBits)
        {
            Assert.Equal(
                0,
                CryptRSA.BitTest(words, width, bit + 1));
        }
    }

    [Theory]
    [InlineData("0000")]
    [InlineData("0001")]
    [InlineData("1234")]
    [InlineData("FFFF")]
    [InlineData("12345678")]
    [InlineData("FFFFFFFF")]
    public void ToWords_AndFromWords_RoundTrip(string hex)
    {
        byte[] input = Convert.FromHexString(hex);
        int width = input.Length / 2;

        ushort[] words = new ushort[CryptRSA.MaxWords];
        int count = CryptRSA.ToWords(
            words, -1, input, input.Length);

        Assert.Equal(width, count);

        byte[] output = new byte[input.Length];
        CryptRSA.FromWords(words, width, output, output.Length);

        Assert.Equal(input, output);
        Assert.Equal(FromBytes(input), FromWords(words.Take(width).ToArray()));
    }

    [Fact]
    public void Multiply_MatchesBigInteger_ForDeterministicCases()
    {
        var cases = new[]
        {
            (A: 0, B: 0, M: 65521),
            (A: 1, B: 65520, M: 65521),
            (A: 12345, B: 54321, M: 65521),
            (A: 65519, B: 65518, M: 65521),
            (A: 42, B: 17, M: 101)
        };

        foreach (var item in cases)
        {
            int width = 1;
            ushort[] a = ToWords(item.A, width);
            ushort[] b = ToWords(item.B, width);
            ushort[] mod = ToWords(item.M, width);
            ushort[] result = new ushort[width];

            CryptRSA.Multiply(result, width, a, b, mod);

            BigInteger expected =
                ((BigInteger)item.A * item.B) % item.M;

            Assert.Equal(expected, FromWords(result));
        }
    }

    [Fact]
    public void Multiply_MatchesBigInteger_ForRandomMultiwordValues()
    {
        var random = new Random(123456789);

        foreach (int width in new[] { 1, 2, 3, 4, 8 })
        {
            int byteLength = width * 2;

            for (int test = 0; test < 100; test++)
            {
                byte[] modBytes = new byte[byteLength];
                random.NextBytes(modBytes);

                modBytes[0] |= 0x80;
                modBytes[^1] |= 0x01;

                BigInteger modulus = FromBytes(modBytes);

                byte[] aBytes = new byte[byteLength];
                byte[] bBytes = new byte[byteLength];

                random.NextBytes(aBytes);
                random.NextBytes(bBytes);

                BigInteger a = FromBytes(aBytes) % modulus;
                BigInteger b = FromBytes(bBytes) % modulus;

                ushort[] aWords = ToWords(a, width);
                ushort[] bWords = ToWords(b, width);
                ushort[] modWords = ToWords(modulus, width);
                ushort[] result = new ushort[width];

                CryptRSA.Multiply(
                    result, width, aWords, bWords, modWords);

                BigInteger expected = (a * b) % modulus;

                Assert.Equal(
                    expected,
                    FromWords(result));
            }
        }
    }
}
