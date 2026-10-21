
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
}
