
using System;
using System.Net;
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
        DirtyNetPS3.SocketT? socket = DirtyNetPS3.SocketOpen(2, 1, 0);
        Assert.NotNull(socket);
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
    }

    [Fact]
    public void SocketOpen_DatagramSocket_ReturnsSocket()
    {
        DirtyNetPS3.SocketT? socket = DirtyNetPS3.SocketOpen(2, 2, 0);
        Assert.NotNull(socket);
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
    }

    [Fact]
    public void SocketClose_ValidSocket_ReturnsZero()
    {
        DirtyNetPS3.SocketT socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
    }

    [Fact]
    public void SocketClose_CalledTwice_ReturnsZero()
    {
        DirtyNetPS3.SocketT socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
    }

    [Fact]
    public void SocketShutdown_InvalidObject_ReturnsNone()
    {
        Assert.Equal(0, DirtyNetPS3.SocketShutdown(new DirtyNetPS3.SocketT(), 2));
    }

    [Fact]
    public void SocketShutdown_DatagramSocket_ReturnsNone()
    {
        DirtyNetPS3.SocketT socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;
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
        Assert.Equal(-11, DirtyNetPS3.SocketBind(new DirtyNetPS3.SocketT(), IntPtr.Zero, 16));
    }

    [Fact]
    public void SocketBind_ClosedSocket_ReturnsInvalid()
    {
        DirtyNetPS3.SocketT socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        Assert.Equal(-11, DirtyNetPS3.SocketBind(socket, IntPtr.Zero, 16));
    }

    [Fact]
    public void SocketConnect_InvalidObject_ReturnsInvalid()
    {
        Assert.Equal(-11, DirtyNetPS3.SocketConnect(new DirtyNetPS3.SocketT(), IntPtr.Zero, 16));
    }

    [Fact]
    public void SocketAccept_InvalidObject_ReturnsNull()
    {
        Assert.Null(
            DirtyNetPS3.SocketAccept(
                new DirtyNetPS3.SocketT(), IntPtr.Zero, IntPtr.Zero));
    }

    [Fact]
    public void SocketAccept_NullSocket_ReturnsNull()
    {
        Assert.Null(
            DirtyNetPS3.SocketAccept(
                null!, IntPtr.Zero, IntPtr.Zero));
    }

    [Fact]
    public void SocketSendto_ClosedSocket_ReturnsInvalid()
    {
        DirtyNetPS3.SocketT socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        Assert.Equal(
            -11,
            DirtyNetPS3.SocketSendto(
                socket,
                IntPtr.Zero,
                0,
                0,
                IntPtr.Zero,
                0));
    }

    [Fact]
    public void SocketRecvfrom_InvalidObject_ReturnsInvalid()
    {
        Assert.Equal(
            -11,
            DirtyNetPS3.SocketRecvfrom(
                new DirtyNetPS3.SocketT
                {
                    socket = DirtyNetPS3.INVALID_SOCKET,
                    type = DirtyNetPS3.SOCK_STREAM
                },
                IntPtr.Zero,
                0,
                0,
                IntPtr.Zero,
                IntPtr.Zero));
    }

    [Fact]
    public void SocketRecvfrom_ClosedStreamSocket_ReturnsInvalid()
    {
        DirtyNetPS3.SocketT socket = DirtyNetPS3.SocketOpen(2, 1, 0)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        Assert.Equal(
            -11,
            DirtyNetPS3.SocketRecvfrom(
                socket,
                IntPtr.Zero,
                0,
                0,
                IntPtr.Zero,
                IntPtr.Zero));
    }

    [Fact]
    public void SocketInfo_InvalidObject_ReturnsErrorAndClearsBuffer()
    {
        IntPtr buffer = Marshal.AllocHGlobal(8);

        try
        {
            for (int i = 0; i < 8; i++)
                Marshal.WriteByte(buffer, i, 0x7F);

            var socket = new DirtyNetPS3.SocketT
            {
                socket = DirtyNetPS3.INVALID_SOCKET
            };
            
            Assert.Equal(-2, DirtyNetPS3.SocketInfo(socket, 0, 0, buffer, 8));

            for (int i = 0; i < 8; i++)
                Assert.Equal((byte)0, Marshal.ReadByte(buffer, i));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [Fact]
    public void SocketInfo_NullBuffer_DoesNotThrow()
    {
        Assert.Equal(
            -2,
            DirtyNetPS3.SocketInfo(
                new DirtyNetPS3.SocketT
                {
                    socket = DirtyNetPS3.INVALID_SOCKET
                },
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
                new DirtyNetPS3.SocketT{socket = DirtyNetPS3.INVALID_SOCKET},
                0,
                0,
                IntPtr.Zero,
                0));
    }

    [Fact]
    public void SocketInfo_UnknownOption_ReturnsError()
    {
        DirtyNetPS3.SocketT socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;

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
    public void SocketInfo_ClosedSocket_ReturnsError()
    {
        DirtyNetPS3.SocketT socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;
        Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        Assert.Equal(
            -2,
            DirtyNetPS3.SocketInfo(
                socket,
                Tools.FourCC("stat"),
                0,
                IntPtr.Zero,
                0));
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
