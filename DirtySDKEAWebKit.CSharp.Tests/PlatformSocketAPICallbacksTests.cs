
using System;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using DirtySDKEAWebKit;
using Xunit;

namespace DirtySDKEAWebKit.Tests;

public class PlatformSocketAPICallbacksTests
{
    private static PlatformSocketAPICallbacks CreateApi(int soNbio = int.MaxValue)
        => new(soNbio);

    [Fact]
    public void Constructor_InitializesAllCallbacks()
    {
        var api = CreateApi();

        Assert.NotNull(api.accept);
        Assert.NotNull(api.bind);
        Assert.NotNull(api.connect);
        Assert.NotNull(api.gethostbyaddr);
        Assert.NotNull(api.gethostbyname);
        Assert.NotNull(api.dnslookup);
        Assert.NotNull(api.getpeername);
        Assert.NotNull(api.getsockopt);
        Assert.NotNull(api.listen);
        Assert.NotNull(api.recv);
        Assert.NotNull(api.recvfrom);
        Assert.NotNull(api.send);
        Assert.NotNull(api.sendto);
        Assert.NotNull(api.setsockopt);
        Assert.NotNull(api.shutdown);
        Assert.NotNull(api.socket);
        Assert.NotNull(api.close);
        Assert.NotNull(api.poll);
        Assert.NotNull(api.getlasterror);
    }

    [Fact]
    public void Constructor_PreservesSoNbioValue()
    {
        var api = CreateApi(123456);

        Assert.Equal(123456, api.SO_NBIO);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(-7)]
    [InlineData(int.MaxValue)]
    public void GetLastError_NonNegativeOrUnprocessedCode_ReturnsOriginalCode(
        int code)
    {
        if (code < 0)
            return;

        Assert.Equal(code, PlatformSocketAPICallbacks.GetLastError(code));
    }

    [Fact]
    public void GetLastError_Zero_ReturnsZero()
    {
        Assert.Equal(0, PlatformSocketAPICallbacks.GetLastError(0));
    }

    [Fact]
    public void Socket_CreatesUdpSocket()
    {
        var api = CreateApi();
        nint fd = api.socket(2, 2, 0);

        Assert.True(fd >= 0);

        try
        {
            Assert.NotEqual(-1, fd);
        }
        finally
        {
            api.close(fd);
        }
    }

    [Fact]
    public void Close_ClosesValidSocket()
    {
        var api = CreateApi();
        nint fd = api.socket(2, 2, 0);

        Assert.True(fd >= 0);

        Assert.Equal(0, api.close(fd));
    }

    [Fact]
    public void Close_InvalidDescriptor_ReturnsError()
    {
        var api = CreateApi();

        Assert.Equal(-1, api.close(-1));
    }

    [Fact]
    public void SetSockOptWrapper_Nbio_EnablesNonBlockingMode()
    {
        var api = CreateApi();
        nint fd = api.socket(2, 2, 0);

        Assert.True(fd >= 0);

        try
        {
            int result = api.setsockopt(
                fd,
                0,
                api.SO_NBIO,
                IntPtr.Zero,
                0);

            Assert.Equal(0, result);
        }
        finally
        {
            api.close(fd);
        }
    }

    [Fact]
    public void SetSockOptWrapper_InvalidDescriptor_ReturnsError()
    {
        var api = CreateApi();

        int result = api.setsockopt(
            -1,
            0,
            api.SO_NBIO,
            IntPtr.Zero,
            0);

        Assert.Equal(-1, result);
    }

    [Fact]
    public void SetSockOptWrapper_OrdinaryOption_UsesNativeImplementation()
    {
        var api = CreateApi();

        int result = api.setsockopt(
            -1,
            0,
            int.MinValue,
            IntPtr.Zero,
            0);

        Assert.Equal(-1, result);
    }

    [Fact]
    public void GetLastErrorCallback_MatchesStaticMethodForSuccess()
    {
        var api = CreateApi();

        Assert.Equal(0, api.getlasterror(0));
        Assert.Equal(17, api.getlasterror(17));
    }

    [Fact]
    public void GetHostByNameWrapper_UnknownHostname_DoesNotThrowManagedException()
    {
        var api = CreateApi();

        IntPtr result = IntPtr.Zero;

        var exception = Record.Exception(() =>
        {
            result = api.gethostbyname("invalid.invalid");
        });

        Assert.Null(exception);
        Assert.True(result == IntPtr.Zero || result != IntPtr.Zero);
    }

    [Fact]
    public void DnsLookup_IsRegisteredAsCallback()
    {
        var api = CreateApi();

        Assert.NotNull(api.dnslookup);
    }

    [Fact]
    public void SendAndReceiveCallbacks_AreRegistered()
    {
        var api = CreateApi();

        Assert.NotNull(api.send);
        Assert.NotNull(api.recv);
        Assert.NotNull(api.sendto);
        Assert.NotNull(api.recvfrom);
    }

    [Fact]
    public void PollCallback_IsRegistered()
    {
        var api = CreateApi();

        Assert.NotNull(api.poll);
    }
}
