using System;
using System.Numerics;
using DirtySDKEAWebKit;
using Xunit;

namespace DirtySDKEAWebKit.Tests;

public class CryptRSAExponentiationTests
{
    private static BigInteger FromBytes(byte[] bytes) =>
        new BigInteger(bytes, isUnsigned: true, isBigEndian: true);

    private static byte[] ToFixedBytes(BigInteger value, int length)
    {
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

    private static byte[] Hex(string hex) =>
        Convert.FromHexString(hex);

    [Theory]
    [InlineData("03")]
    [InlineData("11")]
    [InlineData("0101")]
    [InlineData("010001")]
    [InlineData("010203")]
    [InlineData("01")]
    public void Encrypt_MatchesBigIntegerModPow(string exponentHex)
    {
        // Фиксированный 128-битный модуль.
        byte[] modulus = Hex(
            "F123456789ABCDEF0123456789ABCDEF");

        // Входной блок заведомо меньше модуля.
        byte[] input = Hex(
            "0123456789ABCDEF0123456789ABCDEF");

        byte[] exponent = Hex(exponentHex);

        BigInteger n = FromBytes(modulus);
        BigInteger x = FromBytes(input);
        BigInteger e = FromBytes(exponent);

        Assert.True(n > 1);
        Assert.True(x < n);

        byte[] expected = ToFixedBytes(
            BigInteger.ModPow(x, e, n),
            modulus.Length);

        var rsa = new CryptRSA();

        rsa.Init(
            modulus, modulus.Length,
            exponent, exponent.Length);

        rsa.InitSignature(input, input.Length);
        rsa.Encrypt();

        Assert.Equal(expected, rsa.EncryptBlock[..modulus.Length]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(255)]
    public void Encrypt_SmallInput_MatchesBigInteger(int value)
    {
        byte[] modulus = Hex("F123456789ABCDEF");
        byte[] input = new byte[modulus.Length];

        input[^1] = (byte)value;

        byte[] exponent = Hex("010001");

        BigInteger n = FromBytes(modulus);
        BigInteger x = FromBytes(input);
        BigInteger e = FromBytes(exponent);

        byte[] expected = ToFixedBytes(
            BigInteger.ModPow(x, e, n),
            modulus.Length);

        var rsa = new CryptRSA();

        rsa.Init(
            modulus, modulus.Length,
            exponent, exponent.Length);

        rsa.InitSignature(input, input.Length);
        rsa.Encrypt();

        Assert.Equal(expected, rsa.EncryptBlock[..modulus.Length]);
    }

    [Fact]
    public void Encrypt_InputZero_ReturnsZeroForPositiveExponent()
    {
        byte[] modulus = Hex("F123456789ABCDEF");
        byte[] input = new byte[modulus.Length];
        byte[] exponent = Hex("010001");

        var rsa = new CryptRSA();

        rsa.Init(
            modulus, modulus.Length,
            exponent, exponent.Length);

        rsa.InitSignature(input, input.Length);
        rsa.Encrypt();

        Assert.Equal(
            new byte[modulus.Length],
            rsa.EncryptBlock[..modulus.Length]);
    }

    [Fact]
    public void Encrypt_InputOne_ReturnsOne()
    {
        byte[] modulus = Hex("F123456789ABCDEF");
        byte[] input = new byte[modulus.Length];
        input[^1] = 1;

        byte[] exponent = Hex("010001");

        var rsa = new CryptRSA();

        rsa.Init(
            modulus, modulus.Length,
            exponent, exponent.Length);

        rsa.InitSignature(input, input.Length);
        rsa.Encrypt();

        byte[] expected = new byte[modulus.Length];
        expected[^1] = 1;

        Assert.Equal(expected, rsa.EncryptBlock[..modulus.Length]);
    }

    [Fact]
    public void Exponentiate_GeneralCase_MatchesBigInteger()
    {
        byte[] modulus = Hex("F123456789ABCDEF");
        byte[] input = Hex("0123456789ABCDEF");
        byte[] exponent = Hex("010203");

        BigInteger expectedValue = BigInteger.ModPow(
            FromBytes(input),
            FromBytes(exponent),
            FromBytes(modulus));

        byte[] expected = ToFixedBytes(
            expectedValue, modulus.Length);

        byte[] result = (byte[])input.Clone();

        CryptRSA.Exponentiate(
            result, result,
            modulus, modulus.Length,
            exponent, exponent.Length);

        Assert.Equal(expected, result);
    }
}
