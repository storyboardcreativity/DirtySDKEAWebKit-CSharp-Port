using System;
using System.Linq;
using System.Text;
using Xunit;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.Tests;

public class CryptMD2Tests
{
    [Theory]
    [InlineData("", "8350E5A3E24C153DF2275C9F80692773")]
    [InlineData("a", "32EC01EC4A6DAC72C0AB96FB34C0B5D1")]
    [InlineData("abc", "DA853B0D3F88D99B30283A69E6DED6BB")]
    [InlineData("message digest", "AB4F496BFB2A530B219FF33031FE06B0")]
    [InlineData("abcdefghijklmnopqrstuvwxyz", "4E8DDFF3650292AB5A4108C3AA47940B")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "DA33DEF2A42DF13975352846C30338CD")]
    [InlineData("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "D5976F79D83D3A0DC9806C3C66F3EFD8")]
    public void ComputeHash_ReturnsExpectedHash(string input, string expected)
    {
        Assert.Equal(expected, CryptMD2.ToHexString(
            CryptMD2.ComputeHash(Encoding.ASCII.GetBytes(input))));
    }

    [Fact]
    public void ConstantsAndOutputFormat_AreCorrect()
    {
        Assert.Equal(16, CryptMD2.MD2_BINARY_OUT);
        Assert.Equal(33, CryptMD2.MD2_STRING_OUT);
        Assert.Matches("^[0-9A-F]{32}$",
            CryptMD2.ToHexString(CryptMD2.ComputeHash(Array.Empty<byte>())));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(100)]
    public void Update_TracksBlockRemainder(int length)
    {
        var context = new CryptMD2();
        byte[] data = new byte[length];

        context.Init();
        context.Update(data, length);

        Assert.Equal(length % 16, context.iCount);
    }

    [Fact]
    public void UpdateInChunks_MatchesSingleUpdate()
    {
        byte[] data = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
        var context = new CryptMD2();
        byte[] actual = new byte[16];

        context.Init();

        for (int i = 0; i < data.Length; i += 7)
            context.Update(data, i, Math.Min(7, data.Length - i));

        context.Final(actual, actual.Length);

        Assert.Equal(CryptMD2.ComputeHash(data), actual);
    }

    [Fact]
    public void Update_WithOffset_HashesOnlySelectedBytes()
    {
        byte[] data = Encoding.ASCII.GetBytes("XXabcYY");
        var context = new CryptMD2();
        byte[] actual = new byte[16];

        context.Init();
        context.Update(data, 2, 3);
        context.Final(actual, actual.Length);

        Assert.Equal(CryptMD2.ComputeHash(Encoding.ASCII.GetBytes("abc")), actual);
    }

    [Fact]
    public void Final_WithShortOutput_DoesNotResetContext()
    {
        var context = new CryptMD2();
        context.Init();
        context.Update(Encoding.ASCII.GetBytes("abc"), 3);
        int count = context.iCount;

        context.Final(new byte[15], 15);

        Assert.Equal(count, context.iCount);
    }

    [Fact]
    public void Final_ResetsContext()
    {
        var context = new CryptMD2();
        context.Init();
        context.Update(Encoding.ASCII.GetBytes("abc"), 3);
        context.Final(new byte[16], 16);

        Assert.Equal(0, context.iCount);
        Assert.All(context.aState, b => Assert.Equal((byte)0, b));
        Assert.All(context.aChecksum, b => Assert.Equal((byte)0, b));
        Assert.All(context.aBuffer, b => Assert.Equal((byte)0, b));
    }

    [Fact]
    public void ComputeHash_DoesNotModifyInput_AndIsDeterministic()
    {
        byte[] data = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        byte[] original = (byte[])data.Clone();

        byte[] first = CryptMD2.ComputeHash(data);
        byte[] second = CryptMD2.ComputeHash(data);

        Assert.Equal(original, data);
        Assert.Equal(first, second);
    }
}
