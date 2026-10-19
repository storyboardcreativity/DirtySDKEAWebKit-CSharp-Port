using System;
using System.Text;
using Xunit;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.Tests;

public class CryptMD5Tests
{
    [Theory]
    [InlineData("", "D41D8CD98F00B204E9800998ECF8427E")]
    [InlineData("a", "0CC175B9C0F1B6A831C399E269772661")]
    [InlineData("abc", "900150983CD24FB0D6963F7D28E17F72")]
    [InlineData("message digest", "F96B697D7CB7938D525A2F31AAF161D0")]
    [InlineData("abcdefghijklmnopqrstuvwxyz", "C3FCD3D76192E4007DFB496CCA67E13B")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "D174AB98D277D9F5A5611C2C9F419D9F")]
    [InlineData("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57EDF4A22BE3C955AC49DA2E2107B67A")]
    public void ComputeHash_ReturnsExpectedHash(string input, string expected)
    {
        var context = new CryptMD5T();
        CryptMD5.CryptMD5Init(context);

        byte[] data = Encoding.ASCII.GetBytes(input);
        CryptMD5.CryptMD5Update(context, data, data.Length);

        byte[] output = new byte[CryptMD5.MD5_STRING_OUT];
        CryptMD5.CryptMD5Final(context, output, output.Length);

        Assert.Equal(expected, Encoding.ASCII.GetString(output, 0, 32).ToUpperInvariant());
    }

    [Fact]
    public void UpdateInChunks_ReturnsSameHashAsSingleUpdate()
    {
        byte[] data = Encoding.ASCII.GetBytes(new string('a', 1000));

        var singleContext = new CryptMD5T();
        CryptMD5.CryptMD5Init(singleContext);
        CryptMD5.CryptMD5Update(singleContext, data, data.Length);

        byte[] singleOutput = new byte[33];
        CryptMD5.CryptMD5Final(singleContext, singleOutput, singleOutput.Length);

        var chunkedContext = new CryptMD5T();
        CryptMD5.CryptMD5Init(chunkedContext);

        for (int offset = 0; offset < data.Length;)
        {
            int length = Math.Min(17, data.Length - offset);
            byte[] chunk = new byte[length];
            Array.Copy(data, offset, chunk, 0, length);

            CryptMD5.CryptMD5Update(chunkedContext, chunk, chunk.Length);
            offset += length;
        }

        byte[] chunkedOutput = new byte[33];
        CryptMD5.CryptMD5Final(chunkedContext, chunkedOutput, chunkedOutput.Length);

        Assert.Equal(singleOutput, chunkedOutput);
    }

    [Fact]
    public void BinaryOutput_ReturnsExpectedHash()
    {
        var context = new CryptMD5T();
        CryptMD5.CryptMD5Init(context);

        byte[] data = Encoding.ASCII.GetBytes("abc");
        CryptMD5.CryptMD5Update(context, data, data.Length);

        byte[] output = new byte[16];
        CryptMD5.CryptMD5Final(context, output, output.Length);

        if (OperatingSystem.IsLinux())
        {
            Assert.Equal(
                Convert.FromHexString("900150983CD24FB0D6963F7D28E17F72"),
                output);
        }
    }

    [Fact]
    public void Final_WritesNullTerminatedHexString()
    {
        var context = new CryptMD5T();
        CryptMD5.CryptMD5Init(context);

        byte[] data = Encoding.ASCII.GetBytes("abc");
        CryptMD5.CryptMD5Update(context, data, data.Length);

        byte[] output = new byte[33];
        CryptMD5.CryptMD5Final(context, output, output.Length);

        Assert.Equal((byte)0, output[32]);
        Assert.Equal(
            "900150983CD24FB0D6963F7D28E17F72",
            Encoding.ASCII.GetString(output, 0, 32).ToUpperInvariant());
    }
}
