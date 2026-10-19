using System;
using System.Text;
using Xunit;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.Tests;

public class CryptSHA1Tests
{
    [Theory]
    [InlineData("", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")]
    [InlineData("a", "86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8")]
    [InlineData("abc", "A9993E364706816ABA3E25717850C26C9CD0D89D")]
    [InlineData("message digest", "C12252CEDA8BE8994D5FA0290A47231C1D16AAE3")]
    [InlineData("abcdefghijklmnopqrstuvwxyz", "32D10C7B8CF96570CA04CE37F2A19D84240D3A89")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "761C457BF73B14D27E9E9265C46F4B4DDA11F940")]
    [InlineData("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "50ABF5706A150990A08B2C5EA40FA0E585554732")]
    public void ComputeHash_ReturnsExpectedHash(string input, string expected)
    {
        var sha1 = new CryptSHA1();
        byte[] data = Encoding.UTF8.GetBytes(input);

        sha1.Update(data, (uint)data.Length);

        Assert.Equal(expected, Convert.ToHexString(sha1.Final()));
    }

    [Fact]
    public void Update_InChunks_ReturnsSameHash()
    {
        var sha1 = new CryptSHA1();
        byte[] data = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");

        sha1.Update(data, 0, 7);
        sha1.Update(data, 7, 10);
        sha1.Update(data, 17, 9);

        Assert.Equal(
            "32D10C7B8CF96570CA04CE37F2A19D84240D3A89",
            Convert.ToHexString(sha1.Final()));
    }

    [Fact]
    public void Final_WithShortBuffer_WritesOnlyRequestedBytes()
    {
        var sha1 = new CryptSHA1();
        byte[] data = Encoding.UTF8.GetBytes("abc");
        byte[] output = new byte[8];

        sha1.Update(data, (uint)data.Length);
        sha1.Final(output, 8);

        Assert.Equal("A9993E364706816A", Convert.ToHexString(output));
    }
}
