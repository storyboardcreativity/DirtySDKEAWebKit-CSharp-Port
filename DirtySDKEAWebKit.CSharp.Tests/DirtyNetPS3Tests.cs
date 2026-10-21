
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using DirtySDKEAWebKit.CSharp;
using Xunit;

namespace DirtySDKEAWebKit.Tests;

[CollectionDefinition("DirtyNetPS3", DisableParallelization = true)]
public sealed class DirtyNetPS3Collection
{
}

[Collection("DirtyNetPS3")]
public sealed class DirtyNetPS3Tests
{
    [Fact]
    public void SocketOpen_StreamSocket_ReturnsSocket()
    {
        Socket? socket = DirtyNetPS3.SocketOpen(
            AddressFamily.InterNetwork,
            SocketType.Stream,
            ProtocolType.IP);
        Assert.NotNull(socket);
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
    }

    [Fact]
    public void SocketOpen_DatagramSocket_ReturnsSocket()
    {
        Socket? socket = DirtyNetPS3.SocketOpen(
            AddressFamily.InterNetwork,
            SocketType.Dgram,
            ProtocolType.IP);
        Assert.NotNull(socket);
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
    }

    [Fact]
    public void SocketClose_ValidSocket_ReturnsZero()
    {
        Socket? socket = DirtyNetPS3.SocketOpen(
            AddressFamily.InterNetwork,
            SocketType.Dgram,
            ProtocolType.IP)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
    }

    [Fact]
    public void SocketClose_CalledTwice_ReturnsZero()
    {
        Socket? socket = DirtyNetPS3.SocketOpen(
            AddressFamily.InterNetwork,
            SocketType.Dgram,
            ProtocolType.IP)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
    }

    [Fact]
    public void SocketShutdown_InvalidObject_ReturnsNone()
    {
        Assert.Equal(0, DirtyNetPS3.SocketShutdown(null, 2));
    }

    [Fact]
    public void SocketShutdown_DatagramSocket_ReturnsNone()
    {
        Socket? socket = DirtyNetPS3.SocketOpen(
            AddressFamily.InterNetwork,
            SocketType.Dgram,
            ProtocolType.IP)!;
        try
        {
            Assert.Equal(0, DirtyNetPS3.SocketShutdown(socket, 2));
            Assert.Equal(0, DirtyNetPS3.SocketShutdown(socket, 1));
            Assert.Equal(0, DirtyNetPS3.SocketShutdown(socket, 3));
        }
        finally
        {
            DirtyNetPS3.SocketClose(socket);
        }
    }

    [Fact]
    public void SocketBind_InvalidObject_ReturnsInvalid()
    {
        Assert.Equal(-11, DirtyNetPS3.SocketBind(null, null));
    }

    [Fact]
    public void SocketBind_ClosedSocket_ReturnsInvalid()
    {
        Socket? socket = DirtyNetPS3.SocketOpen(
            AddressFamily.InterNetwork,
            SocketType.Dgram,
            ProtocolType.IP)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        Assert.Equal(-11, DirtyNetPS3.SocketBind(socket, null));
    }

    [Fact]
    public void SocketConnect_InvalidObject_ReturnsInvalid()
    {
        Assert.Equal(-11, DirtyNetPS3.SocketConnect(null, null));
    }

    [Fact]
    public void SocketAccept_InvalidObject_ReturnsNull()
    {
        IPEndPoint? remoteEndPoint;
        Assert.Null(DirtyNetPS3.SocketAccept(null, out remoteEndPoint));
    }

    [Fact]
    public void SocketAccept_NullSocket_ReturnsNull()
    {
        IPEndPoint? remoteEndPoint;
        Assert.Null(DirtyNetPS3.SocketAccept(null, out remoteEndPoint));
    }

    [Fact]
    public void SocketSendto_ClosedSocket_ReturnsInvalid()
    {
        Socket? socket = DirtyNetPS3.SocketOpen(
            AddressFamily.InterNetwork,
            SocketType.Dgram,
            ProtocolType.IP)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        Assert.Equal(-11, DirtyNetPS3.SocketSendto(socket, null!, 0, 0, null));
    }

    [Fact]
    public void SocketRecvfrom_ClosedStreamSocket_ReturnsInvalid()
    {
        Socket? socket = DirtyNetPS3.SocketOpen(
            AddressFamily.InterNetwork,
            SocketType.Stream,
            ProtocolType.IP)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        Assert.Equal(-11, DirtyNetPS3.SocketRecvfrom(socket, null!, 0, 0, null));
    }

    [Fact]
    public void SocketInfo_NullBuffer_DoesNotThrow()
    {
        Assert.Equal(
            -2,
            DirtyNetPS3.SocketInfo(
                null,
                0,
                0,
                IntPtr.Zero,
                8
            )
        );
    }

    [Fact]
    public void SocketInfo_ZeroLengthBuffer_DoesNotAccessMemory()
    {
        Assert.Equal(
            -2,
            DirtyNetPS3.SocketInfo(
                null,
                0,
                0,
                IntPtr.Zero,
                0));
    }

    [Fact]
    public void SocketInfo_UnknownOption_ReturnsError()
    {
        Socket? socket = DirtyNetPS3.SocketOpen(
            AddressFamily.InterNetwork,
            SocketType.Dgram,
            ProtocolType.IP)!;

        try
        {
            Assert.Equal(
                -1,
                DirtyNetPS3.SocketInfo(
                    socket,
                    Tools.FourCC("test"),
                    0,
                    IntPtr.Zero,
                    0));
        }
        finally
        {
            DirtyNetPS3.SocketClose(socket);
        }
    }

    [Fact]
    public void SocketControl_UnknownOption_ReturnsError()
    {
        Assert.Equal(
            -1,
            DirtyNetPS3.SocketControl(
                null,
                Tools.FourCC("test"),
                0,
                IntPtr.Zero,
                IntPtr.Zero));
    }

    [Fact]
    public void SocketControl_PoolOption_ReturnsZero()
    {
        Assert.Equal(
            0,
            DirtyNetPS3.SocketControl(
                null,
                Tools.FourCC("pool"),
                128 * 1024,
                IntPtr.Zero,
                IntPtr.Zero));
    }

    [Fact]
    public void SocketLookup_NegativeTimeout_ReturnsNull()
    {
        Assert.Null(DirtyNetPS3.SocketLookup("127.0.0.1", -1));
    }

    [Fact]
    public void SocketLookup_LongName_IsTruncatedTo63Characters()
    {
        string name = new('a', 80);

        DirtyNetPS3.HostentT? host = DirtyNetPS3.SocketLookup(name, 1000);

        Assert.NotNull(host);
        Assert.Equal(63, host.Name.Length);
        Assert.Equal(name[..63], host.Name);
    }

    [Fact]
    public void SocketLookup_ZeroTimeout_AllowsIpv4Literal()
    {
        DirtyNetPS3.HostentT? host = DirtyNetPS3.SocketLookup("127.0.0.1", 0);

        Assert.NotNull(host);
        Assert.Equal(DirtyNetPS3.HostentT.HostLookupStatus.Success, host.Status);
        Assert.Equal(IPAddress.Parse("127.0.0.1"), host.Address);
    }
}
