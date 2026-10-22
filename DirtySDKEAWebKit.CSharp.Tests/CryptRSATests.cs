
using System;
using Xunit;
using System.Numerics;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.Tests;

public class CryptRSATests
{
    private static CryptRSA CreateState(byte[] exponent)
    {
        var state = new CryptRSA();

        state.Init(
            new byte[] { 0x0C, 0xA1 }, 2, // n = 3233
            exponent, exponent.Length);

        return state;
    }

    [Fact]
    public void Test_Init_CopiesKeyAndSizes()
    {
        var state = CreateState(new byte[] { 0x11 });

        Assert.Equal(2, state.iKeyModSize);
        Assert.Equal(1, state.iKeyExpSize);
        Assert.Equal(new byte[] { 0x0C, 0xA1 }, state.KeyModData[..2]);
        Assert.Equal(0x11, state.KeyExpData[0]);
    }

    [Theory]
    [InlineData(3, 2, 8)]
    [InlineData(17, 2, 1752)]
    [InlineData(5, 2, 32)]
    public void Test_Encrypt_KnownResults(byte exponent, int input, int expected)
    {
        var state = CreateState(new[] { exponent });

        state.EncryptBlock[0] = (byte)(input >> 8);
        state.EncryptBlock[1] = (byte)input;
        state.Encrypt();

        Assert.Equal((byte)(expected >> 8), state.EncryptBlock[0]);
        Assert.Equal((byte)expected, state.EncryptBlock[1]);
    }

    [Fact]
    public void Test_InitSignature_CopiesSignature()
    {
        var state = new CryptRSA();
        byte[] signature = { 1, 2, 3, 4 };

        state.InitSignature(signature, signature.Length);

        Assert.Equal(signature, state.EncryptBlock[..signature.Length]);
    }

    [Fact]
    public void Test_InitMaster_WritesExpectedBlockStructure()
    {
        var state = new CryptRSA();

        // A six-byte modulus-sized block
        state.Init(
            new byte[] { 1, 2, 3, 4, 5, 6 }, 6,
            new byte[] { 17 }, 1);

        byte[] master = { 0xAA, 0xBB };

        state.InitMaster(master, master.Length);

        Assert.Equal(0, state.EncryptBlock[0]);
        Assert.Equal(2, state.EncryptBlock[1]);
        Assert.Equal(0, state.EncryptBlock[3]);
        Assert.Equal(master, state.EncryptBlock[4..6]);
    }

    [Theory]
    [InlineData(3, 123, 3233)]
    [InlineData(17, 123, 3233)]
    [InlineData(5, 1000, 3233)]
    [InlineData(65537, 42, 3233)]
    [InlineData(17, 2000, 3233)]
    public void Test_Encrypt_ComplexValues(int exponent, int input, int modulus)
    {
        byte[] modulusBytes =
        {
            (byte)(modulus >> 8),
            (byte)modulus
        };

        byte[] exponentBytes = exponent switch
        {
            65537 => new byte[] { 0x01, 0x00, 0x01 },
            _ => new[] { (byte)exponent }
        };

        var state = new CryptRSA();

        state.Init(
            modulusBytes, modulusBytes.Length,
            exponentBytes, exponentBytes.Length);

        state.EncryptBlock[0] = (byte)(input >> 8);
        state.EncryptBlock[1] = (byte)input;

        BigInteger expected = BigInteger.ModPow(
            input, exponent, modulus);

        state.Encrypt();

        int actual =
            (state.EncryptBlock[0] << 8) |
            state.EncryptBlock[1];

        Assert.Equal((int)expected, actual);
    }

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

    [Fact]
    public void AdditionAndSubtract_MatchBigInteger_ForRandomInputs()
    {
        var random = new Random(20261021);

        foreach (int width in new[] { 1, 2, 4, 8 })
        {
            BigInteger limit = BigInteger.One << (width * 16);
            BigInteger mask = limit - 1;

            for (int test = 0; test < 500; test++)
            {
                byte[] aBytes = new byte[width * 2];
                byte[] bBytes = new byte[width * 2];

                random.NextBytes(aBytes);
                random.NextBytes(bBytes);

                BigInteger a = FromBytes(aBytes);
                BigInteger b = FromBytes(bBytes);

                ushort[] aWords = ToWords(a, width);
                ushort[] bWords = ToWords(b, width);
                ushort[] result = new ushort[width];

                int carry = CryptRSA.Addition(
                    result, width, aWords, bWords);

                Assert.Equal((a + b) & mask, FromWords(result));
                Assert.Equal((int)((a + b) >> (width * 16)), carry);

                int borrow = CryptRSA.Subtract(
                    result, width, aWords, bWords);

                Assert.Equal((a - b) & mask, FromWords(result));
                Assert.Equal(a < b ? 1 : 0, borrow);
            }
        }
    }

    [Fact]
    public void FromWords_OddLength_WritesOnlyCompleteWords()
    {
        ushort[] words = { 0x1234, 0x5678 };
        byte[] result = { 0xAA, 0xAA, 0xAA };

        CryptRSA.FromWords(words, 2, result, 3);

        Assert.Equal(
            new byte[] { 0x56, 0x78, 0xAA },
            result);
    }

    [Fact]
    public void Encrypt_Reinitialization_DoesNotReusePreviousResult()
    {
        byte[] modulus = Convert.FromHexString("F123456789ABCDEF");
        byte[] exponent = Convert.FromHexString("010001");

        var rsa = new CryptRSA();

        rsa.Init(modulus, modulus.Length, exponent, exponent.Length);

        byte[] firstInput = Convert.FromHexString("0000000000000002");
        rsa.InitSignature(firstInput, firstInput.Length);
        rsa.Encrypt();

        byte[] firstResult = rsa.EncryptBlock[..modulus.Length];

        byte[] secondInput = Convert.FromHexString("0000000000000003");
        rsa.InitSignature(secondInput, secondInput.Length);
        rsa.Encrypt();

        byte[] secondResult = rsa.EncryptBlock[..modulus.Length];

        Assert.NotEqual(firstResult, secondResult);

        Assert.Equal(
            BigInteger.ModPow(
                FromBytes(secondInput),
                FromBytes(exponent),
                FromBytes(modulus)),
            FromBytes(secondResult));
    }
}
