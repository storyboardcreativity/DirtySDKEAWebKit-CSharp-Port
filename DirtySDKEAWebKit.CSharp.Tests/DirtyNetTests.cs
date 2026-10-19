
using System;
using Xunit;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.Tests;

public class DirtyNetTests
{
    [Fact]
    public void SockaddrInit_SetsFamilyAndClearsData()
    {
        var addr = new DirtySockAddress();
        Array.Fill(addr.SaData, (byte)0xFF);

        DirtyNet.SockaddrInit(addr, DirtyNet.AF_INET);

        Assert.Equal(DirtyNet.AF_INET, addr.Family);
        Assert.All(addr.SaData, b => Assert.Equal((byte)0, b));
    }

    [Fact]
    public void SockaddrInSetPortAndGetPort_RoundTrip()
    {
        var addr = new DirtySockAddress();

        DirtyNet.SockaddrInSetPort(addr, 8080);

        Assert.Equal((ushort)8080, DirtyNet.SockaddrInGetPort(addr));
        Assert.Equal((byte)0x1F, addr.SaData[0]);
        Assert.Equal((byte)0x90, addr.SaData[1]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(80)]
    [InlineData(443)]
    [InlineData(65535)]
    [InlineData(70000)]
    public void SockaddrInSetPort_TruncatesToTwoBytes(int port)
    {
        var addr = new DirtySockAddress();

        DirtyNet.SockaddrInSetPort(addr, port);

        Assert.Equal((ushort)(unchecked((uint)port) & 0xFFFF),
            DirtyNet.SockaddrInGetPort(addr));
    }

    [Fact]
    public void SockaddrInSetAddrAndGetAddr_RoundTrip()
    {
        var addr = new DirtySockAddress();

        DirtyNet.SockaddrInSetAddr(addr, 0xC0A8010A);

        Assert.Equal((byte)192, addr.SaData[2]);
        Assert.Equal((byte)168, addr.SaData[3]);
        Assert.Equal((byte)1, addr.SaData[4]);
        Assert.Equal((byte)10, addr.SaData[5]);

        Assert.Equal(0xC0A8010AU, DirtyNet.SockaddrInGetAddr(addr));
    }

    [Fact]
    public void SockaddrInGetAddr_ReturnsZeroForZeroAddress()
    {
        var addr = new DirtySockAddress();

        Assert.Equal(0U, DirtyNet.SockaddrInGetAddr(addr));
    }

    [Fact]
    public void SockaddrInSetMiscAndGetMisc_RoundTrip()
    {
        var addr = new DirtySockAddress();

        DirtyNet.SockaddrInSetMisc(addr, 0x12345678);

        Assert.Equal((byte)0x12, addr.SaData[6]);
        Assert.Equal((byte)0x34, addr.SaData[7]);
        Assert.Equal((byte)0x56, addr.SaData[8]);
        Assert.Equal((byte)0x78, addr.SaData[9]);

        Assert.Equal(0x12345678U, DirtyNet.SockaddrInGetMisc(addr));
    }

    [Fact]
    public void SockaddrIsLoopback_ReturnsTrueForLoopback()
    {
        var addr = new DirtySockAddress(DirtyNet.AF_INET);

        addr.SaData[0] = 127;
        addr.SaData[1] = 0;
        addr.SaData[2] = 0;
        addr.SaData[3] = 1;

        Assert.True(DirtyNet.SockaddrIsLoopback(addr));
    }

    [Fact]
    public void SockaddrIsLoopback_ReturnsFalseForOtherAddresses()
    {
        var addr = new DirtySockAddress(DirtyNet.AF_INET);

        addr.SaData[0] = 127;
        addr.SaData[1] = 0;
        addr.SaData[2] = 0;
        addr.SaData[3] = 2;

        Assert.False(DirtyNet.SockaddrIsLoopback(addr));

        addr.SaData[3] = 1;
        addr.Family = 1;

        Assert.False(DirtyNet.SockaddrIsLoopback(addr));
    }

    [Fact]
    public void SockaddrCompare_ReturnsZeroForIdenticalAddresses()
    {
        var a = new DirtySockAddress(DirtyNet.AF_INET);
        var b = new DirtySockAddress(DirtyNet.AF_INET);

        DirtyNet.SockaddrInSetAddr(a, 0xC0A80101);
        DirtyNet.SockaddrInSetAddr(b, 0xC0A80101);
        DirtyNet.SockaddrInSetPort(a, 80);
        DirtyNet.SockaddrInSetPort(b, 80);

        Assert.Equal(0, DirtyNet.SockaddrCompare(a, b));
    }

    [Fact]
    public void SockaddrCompare_ComparesFamilyFirst()
    {
        var a = new DirtySockAddress(1);
        var b = new DirtySockAddress(2);

        Assert.Equal(-1, DirtyNet.SockaddrCompare(a, b));
        Assert.Equal(1, DirtyNet.SockaddrCompare(b, a));
    }

    [Fact]
    public void SockaddrCompare_ComparesPortAndAddressForIPv4()
    {
        var a = new DirtySockAddress(DirtyNet.AF_INET);
        var b = new DirtySockAddress(DirtyNet.AF_INET);

        DirtyNet.SockaddrInSetPort(a, 80);
        DirtyNet.SockaddrInSetPort(b, 81);

        Assert.True(DirtyNet.SockaddrCompare(a, b) < 0);
        Assert.True(DirtyNet.SockaddrCompare(b, a) > 0);
    }

    [Fact]
    public void SockaddrCompare_ComparesFourteenBytesForOtherFamilies()
    {
        var a = new DirtySockAddress(1);
        var b = new DirtySockAddress(1);

        a.SaData[13] = 1;

        Assert.True(DirtyNet.SockaddrCompare(a, b) > 0);
        Assert.True(DirtyNet.SockaddrCompare(b, a) < 0);
    }

    [Theory]
    [InlineData("192.168.1.10", 0, 192, 168, 1, 10)]
    [InlineData("0.0.0.0", 0, 0, 0, 0, 0)]
    [InlineData("255.255.255.255", 0, 255, 255, 255, 255)]
    [InlineData("256.1.2.3", 0, 0, 1, 2, 3)]
    public void SockaddrInSetAddrText_ParsesAddress(
        string text, int expectedResult,
        byte a, byte b, byte c, byte d)
    {
        var addr = new DirtySockAddress();

        int result = DirtyNet.SockaddrInSetAddrText(addr, text);

        Assert.Equal(expectedResult, result);
        Assert.Equal(a, addr.SaData[2]);
        Assert.Equal(b, addr.SaData[3]);
        Assert.Equal(c, addr.SaData[4]);
        Assert.Equal(d, addr.SaData[5]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("192.168")]
    [InlineData("192.168.1")]
    [InlineData("192x168.1.2")]
    public void SockaddrInSetAddrText_ReturnsMinusOneForInvalidSeparators(
        string text)
    {
        var addr = new DirtySockAddress();

        Assert.Equal(-1, DirtyNet.SockaddrInSetAddrText(addr, text));
        Assert.Equal(0U, DirtyNet.SockaddrInGetAddr(addr));
    }

    [Fact]
    public void SockaddrInSetAddrText_IgnoresTrailingCharacters()
    {
        var addr = new DirtySockAddress();

        Assert.Equal(0,
            DirtyNet.SockaddrInSetAddrText(addr, "1.2.3.4junk"));

        Assert.Equal(0x01020304U, DirtyNet.SockaddrInGetAddr(addr));
    }

    [Theory]
    [InlineData("192.168.1.10", "192.168.1.10")]
    [InlineData("0.0.0.0", "0.0.0.0")]
    [InlineData("255.255.255.255", "255.255.255.255")]
    [InlineData("1.2.3.4", "1.2.3.4")]
    public void SockaddrInGetAddrText_FormatsAddress(
        string input, string expected)
    {
        var addr = new DirtySockAddress();

        Assert.Equal(0, DirtyNet.SockaddrInSetAddrText(addr, input));
        Assert.Equal(expected, DirtyNet.SockaddrInGetAddrText(addr));
    }

    [Fact]
    public void SockaddrInGetAddrText_ReturnsNullForShortBuffer()
    {
        var addr = new DirtySockAddress();
        char[] buffer = new char[15];

        Assert.Null(DirtyNet.SockaddrInGetAddrText(addr, buffer, 15));
        Assert.Equal('\0', buffer[0]);
    }

    [Fact]
    public void SockaddrInGetAddrText_ReturnsNullForNonPositiveLength()
    {
        var addr = new DirtySockAddress();

        Assert.Null(DirtyNet.SockaddrInGetAddrText(
            addr, Array.Empty<char>(), 0));
    }

    [Fact]
    public void SocketHtons_AndNtohs_AreInverses()
    {
        ushort[] values = { 0, 1, 0x1234, 0xABCD, 65535 };

        foreach (ushort value in values)
        {
            ushort network = DirtyNet.SocketHtons(value);
            ushort host = DirtyNet.SocketNtohs(network);

            Assert.Equal(value, host);
        }
    }

    [Fact]
    public void SocketHtonl_AndNtohl_AreInverses()
    {
        uint[] values =
        {
            0,
            1,
            0x01020304,
            0xC0A8010A,
            0xFFFFFFFF
        };

        foreach (uint value in values)
        {
            uint network = DirtyNet.SocketHtonl(value);
            uint host = DirtyNet.SocketNtohl(network);

            Assert.Equal(value, host);
        }
    }

    [Theory]
    [InlineData(0x01020304, "1.2.3.4")]
    [InlineData(unchecked((int)0xC0A8010A), "192.168.1.10")]
    [InlineData(0x7F000001, "127.0.0.1")]
    [InlineData(unchecked((int)0xFFFFFFFF), "255.255.255.255")]
    public void SocketInAddrGetText_FormatsAddress(int address, string expected)
    {
        Assert.Equal(expected, DirtyNet.SocketInAddrGetText(address));
    }

    [Fact]
    public void SocketInAddrGetText2_FormatsAddressIntoBuffer()
    {
        char[] buffer = new char[16];

        char[]? result = DirtyNet.SocketInAddrGetText2(
            0xC0A8010A, buffer, buffer.Length);

        Assert.Same(buffer, result);
        Assert.Equal("192.168.1.10", new string(buffer, 0, 12));
    }

    [Theory]
    [InlineData("192.168.1.10", unchecked((int)0xC0A8010A))]
    [InlineData("127.0.0.1", 0x7F000001)]
    [InlineData("0.0.0.0", 0)]
    [InlineData("invalid", 0)]
    public void SocketInTextGetAddr_ParsesAddress(
        string text, int expected)
    {
        Assert.Equal(expected, DirtyNet.SocketInTextGetAddr(text));
    }

    [Fact]
    public void SockaddrInParse_ParsesAddressAndPort()
    {
        var addr = new DirtySockAddress();

        int result = DirtyNet.SockaddrInParse(
            addr, "192.168.1.10:8080");

        Assert.Equal(3, result);
        Assert.Equal(0xC0A8010AU, DirtyNet.SockaddrInGetAddr(addr));
        Assert.Equal((ushort)8080, DirtyNet.SockaddrInGetPort(addr));
        Assert.Equal(DirtyNet.AF_INET, addr.Family);
    }

    [Fact]
    public void SockaddrInParse_ParsesAddressWithoutPort()
    {
        var addr = new DirtySockAddress();

        int result = DirtyNet.SockaddrInParse(addr, "192.168.1.10");

        Assert.Equal(1, result);
        Assert.Equal(0xC0A8010AU, DirtyNet.SockaddrInGetAddr(addr));
        Assert.Equal((ushort)0, DirtyNet.SockaddrInGetPort(addr));
    }

    [Fact]
    public void SockaddrInParse2_ParsesTwoPorts()
    {
        int result = DirtyNet.SockaddrInParse2(
            out uint address,
            out int port,
            out int? port2,
            "192.168.1.10:8080:9000");

        Assert.Equal(7, result);
        Assert.Equal(0xC0A8010AU, address);
        Assert.Equal(8080, port);
        Assert.Equal(9000, port2);
    }

    [Fact]
    public void SockaddrInParse2_ReportsPresentZeroPort()
    {
        int result = DirtyNet.SockaddrInParse2(
            out uint address,
            out int port,
            out int? port2,
            "0.0.0.0:0:0");

        Assert.Equal(6, result);
        Assert.Equal(0U, address);
        Assert.Equal(0, port);
        Assert.Equal(0, port2);
    }

    [Fact]
    public void SockaddrInParse2_SkipsLeadingWhitespace()
    {
        int result = DirtyNet.SockaddrInParse2(
            out uint address,
            out int port,
            out _,
            " \t192.168.1.10:80",
            false);

        Assert.Equal(3, result);
        Assert.Equal(0xC0A8010AU, address);
        Assert.Equal(80, port);
    }

    [Fact]
    public void SockaddrInParse2_SkipsTextBeforePort()
    {
        int result = DirtyNet.SockaddrInParse2(
            out uint address,
            out int port,
            out _,
            "192.168.1.10xyz:8080",
            false);

        Assert.Equal(3, result);
        Assert.Equal(0xC0A8010AU, address);
        Assert.Equal(8080, port);
    }

    [Fact]
    public void SockaddrInParse2_DoesNotParseSecondPortWhenDisabled()
    {
        int result = DirtyNet.SockaddrInParse2(
            out _,
            out int port,
            out int? port2,
            "192.168.1.10:8080:9000",
            false);

        Assert.Equal(3, result);
        Assert.Equal(8080, port);
        Assert.Null(port2);
    }

    [Fact]
    public void SockaddrInParse2_ReturnsZeroForEmptyInput()
    {
        int result = DirtyNet.SockaddrInParse2(
            out uint address,
            out int port,
            out int? port2,
            "");

        Assert.Equal(0, result);
        Assert.Equal(0U, address);
        Assert.Equal(0, port);
        Assert.Equal(0, port2);
    }

    [Fact]
    public void SockaddrInParse2_UsesUncheckedArithmeticForLargePorts()
    {
        int result = DirtyNet.SockaddrInParse2(
            out _,
            out int port,
            out _,
            "1.2.3.4:999999999999999999999");

        Assert.Equal(3, result);
        Assert.NotEqual(0, port);
    }
}
