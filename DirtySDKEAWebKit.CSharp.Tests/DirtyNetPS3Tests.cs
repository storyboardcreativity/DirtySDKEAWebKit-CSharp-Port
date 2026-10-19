
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
    private static void WithModule(Action action)
    {
        int result = DirtyNetPS3.SocketCreate(0);
        Assert.Equal(0, result);

        try
        {
            action();
        }
        finally
        {
            Assert.Equal(0, DirtyNetPS3.SocketDestroy(0));
        }
    }

    [Fact]
    public void SocketCreate_WhenInactive_ReturnsZero()
    {
        Assert.Equal(0, DirtyNetPS3.SocketCreate(0));
        Assert.Equal(0, DirtyNetPS3.SocketDestroy(0));
    }

    [Fact]
    public void SocketCreate_WhenAlreadyActive_ReturnsError()
    {
        Assert.Equal(0, DirtyNetPS3.SocketCreate(0));

        try
        {
            Assert.Equal(-1, DirtyNetPS3.SocketCreate(0));
        }
        finally
        {
            Assert.Equal(0, DirtyNetPS3.SocketDestroy(0));
        }
    }

    [Fact]
    public void SocketDestroy_WhenInactive_ReturnsError()
    {
        Assert.Equal(-1, DirtyNetPS3.SocketDestroy(0));
    }

    [Fact]
    public void SocketDestroy_CanBeCalledAfterCreate()
    {
        Assert.Equal(0, DirtyNetPS3.SocketCreate(0));
        Assert.Equal(0, DirtyNetPS3.SocketDestroy(0));
        Assert.Equal(-1, DirtyNetPS3.SocketDestroy(0));
    }

    [Fact]
    public void SocketOpen_WhenModuleInactive_ReturnsNull()
    {
        Assert.Null(DirtyNetPS3.SocketOpen(2, 1, 0));
    }

    [Fact]
    public void SocketOpen_StreamSocket_ReturnsSocket()
    {
        WithModule(() =>
        {
            object? socket = DirtyNetPS3.SocketOpen(2, 1, 0);

            Assert.NotNull(socket);
            Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        });
    }

    [Fact]
    public void SocketOpen_DatagramSocket_ReturnsSocket()
    {
        WithModule(() =>
        {
            object? socket = DirtyNetPS3.SocketOpen(2, 2, 0);

            Assert.NotNull(socket);
            Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        });
    }

    [Fact]
    public void SocketClose_NullSocket_ReturnsInvalid()
    {
        Assert.Equal(-11, DirtyNetPS3.SocketClose(null!));
    }

    [Fact]
    public void SocketClose_InvalidObject_ReturnsInvalid()
    {
        Assert.Equal(-11, DirtyNetPS3.SocketClose(new object()));
    }

    [Fact]
    public void SocketClose_ValidSocket_ReturnsZero()
    {
        WithModule(() =>
        {
            object socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;

            Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        });
    }

    [Fact]
    public void SocketClose_CalledTwice_ReturnsZero()
    {
        WithModule(() =>
        {
            object socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;

            Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
            Assert.Equal(0, DirtyNetPS3.SocketClose(socket));
        });
    }

    [Fact]
    public void SocketShutdown_InvalidObject_ReturnsNone()
    {
        Assert.Equal(0, DirtyNetPS3.SocketShutdown(new object(), 2));
    }

    [Fact]
    public void SocketShutdown_NullSocket_ReturnsNone()
    {
        Assert.Equal(0, DirtyNetPS3.SocketShutdown(null!, 2));
    }

    [Fact]
    public void SocketShutdown_DatagramSocket_ReturnsNone()
    {
        WithModule(() =>
        {
            object socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;

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
        });
    }

    [Fact]
    public void SocketBind_InvalidObject_ReturnsInvalid()
    {
        Assert.Equal(
            -11,
            DirtyNetPS3.SocketBind(new object(), IntPtr.Zero, 16));
    }

    [Fact]
    public void SocketBind_ClosedSocket_ReturnsInvalid()
    {
        WithModule(() =>
        {
            object socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;
            Assert.Equal(0, DirtyNetPS3.SocketClose(socket));

            Assert.Equal(
                -11,
                DirtyNetPS3.SocketBind(socket, IntPtr.Zero, 16));
        });
    }

    [Fact]
    public void SocketConnect_InvalidObject_ReturnsInvalid()
    {
        Assert.Equal(
            -11,
            DirtyNetPS3.SocketConnect(new object(), IntPtr.Zero, 16));
    }

    [Fact]
    public void SocketListen_InvalidObject_ReturnsInvalid()
    {
        Assert.Equal(-11, DirtyNetPS3.SocketListen(new object(), 5));
    }

    [Fact]
    public void SocketAccept_InvalidObject_ReturnsNull()
    {
        Assert.Null(
            DirtyNetPS3.SocketAccept(
                new object(), IntPtr.Zero, IntPtr.Zero));
    }

    [Fact]
    public void SocketAccept_NullSocket_ReturnsNull()
    {
        Assert.Null(
            DirtyNetPS3.SocketAccept(
                null!, IntPtr.Zero, IntPtr.Zero));
    }

    [Fact]
    public void SocketSendto_InvalidObject_ReturnsInvalid()
    {
        Assert.Equal(
            -11,
            DirtyNetPS3.SocketSendto(
                new object(),
                IntPtr.Zero,
                0,
                0,
                IntPtr.Zero,
                0));
    }

    [Fact]
    public void SocketSendto_ClosedSocket_ReturnsInvalid()
    {
        WithModule(() =>
        {
            object socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;
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
        });
    }

    [Fact]
    public void SocketRecvfrom_InvalidObject_ReturnsInvalid()
    {
        Assert.Equal(
            -11,
            DirtyNetPS3.SocketRecvfrom(
                new object(),
                IntPtr.Zero,
                0,
                0,
                IntPtr.Zero,
                IntPtr.Zero));
    }

    [Fact]
    public void SocketRecvfrom_ClosedStreamSocket_ReturnsInvalid()
    {
        WithModule(() =>
        {
            object socket = DirtyNetPS3.SocketOpen(2, 1, 0)!;
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
        });
    }

    [Fact]
    public void SocketInfo_InvalidObject_ReturnsErrorAndClearsBuffer()
    {
        IntPtr buffer = Marshal.AllocHGlobal(8);

        try
        {
            for (int i = 0; i < 8; i++)
                Marshal.WriteByte(buffer, i, 0x7F);

            Assert.Equal(
                -2,
                DirtyNetPS3.SocketInfo(
                    new object(),
                    0,
                    0,
                    buffer,
                    8));

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
                new object(),
                0,
                0,
                IntPtr.Zero,
                8));
    }

    [Fact]
    public void SocketInfo_ZeroLengthBuffer_DoesNotAccessMemory()
    {
        Assert.Equal(
            -2,
            DirtyNetPS3.SocketInfo(
                new object(),
                0,
                0,
                IntPtr.Zero,
                0));
    }

    [Fact]
    public void SocketInfo_UnknownOption_ReturnsError()
    {
        WithModule(() =>
        {
            object socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;

            try
            {
                Assert.Equal(
                    -1,
                    DirtyNetPS3.SocketInfo(
                        socket,
                        DirtyMem.FourCC("test"),
                        0,
                        IntPtr.Zero,
                        0));
            }
            finally
            {
                DirtyNetPS3.SocketClose(socket);
            }
        });
    }

    [Fact]
    public void SocketInfo_ClosedSocket_ReturnsError()
    {
        WithModule(() =>
        {
            object socket = DirtyNetPS3.SocketOpen(2, 2, 0)!;
            Assert.Equal(0, DirtyNetPS3.SocketClose(socket));

            Assert.Equal(
                -2,
                DirtyNetPS3.SocketInfo(
                    socket,
                    DirtyMem.FourCC("stat"),
                    0,
                    IntPtr.Zero,
                    0));
        });
    }

    [Fact]
    public void SocketControl_UnknownOption_ReturnsError()
    {
        Assert.Equal(
            -1,
            DirtyNetPS3.SocketControl(
                null,
                DirtyMem.FourCC("test"),
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
                DirtyMem.FourCC("pool"),
                128 * 1024,
                IntPtr.Zero,
                IntPtr.Zero));
    }

    [Fact]
    public void SocketLookup_WhenModuleInactive_ReturnsNull()
    {
        Assert.Null(DirtyNetPS3.SocketLookup("127.0.0.1", 1000));
    }

    [Fact]
    public void SocketLookup_NegativeTimeout_ReturnsNull()
    {
        WithModule(() =>
        {
            Assert.Null(DirtyNetPS3.SocketLookup("127.0.0.1", -1));
        });
    }

    [Theory]
    [InlineData("127.0.0.1", 0x7F000001u)]
    [InlineData("192.168.1.1", 0xC0A80101u)]
    [InlineData("10.0.0.1", 0x0A000001u)]
    [InlineData("255.255.255.255", 0xFFFFFFFFu)]
    [InlineData("0.0.0.0", 0u)]
    public void SocketLookup_Ipv4Literal_ReturnsAddress(
        string address,
        uint expected)
    {
        WithModule(() =>
        {
            DirtyNetPS3.HostentT host =
                Assert.IsType<DirtyNetPS3.HostentT>(
                    DirtyNetPS3.SocketLookup(address, 1000));

            Assert.Equal(1, host.done);
            Assert.Equal(expected, host.addr);
            Assert.Equal(address, host.name);
            Assert.Equal(0, host.sema);
            Assert.NotNull(host.Done);
            Assert.NotNull(host.Free);
            Assert.Equal(1, host.Done!(host));

            host.Free!(host);
        });
    }

    [Fact]
    public void SocketLookup_LongName_IsTruncatedTo63Characters()
    {
        WithModule(() =>
        {
            string name = new('a', 80);

            DirtyNetPS3.HostentT? host =
                DirtyNetPS3.SocketLookup(name, 1000);

            Assert.NotNull(host);
            Assert.Equal(63, host.name.Length);
            Assert.Equal(name[..63], host.name);
        });
    }

    [Fact]
    public void SocketLookup_ZeroTimeout_AllowsIpv4Literal()
    {
        WithModule(() =>
        {
            DirtyNetPS3.HostentT? host =
                DirtyNetPS3.SocketLookup("127.0.0.1", 0);

            Assert.NotNull(host);
            Assert.Equal(1, host.done);
            Assert.Equal(0x7F000001u, host.addr);
        });
    }

    [Fact]
    public void SocketLookup_DoneCallback_ReturnsCurrentStatus()
    {
        DirtyNetPS3.HostentT host = new()
        {
            done = 1
        };

        Assert.Equal(1, host.Done is null ? host.done : host.Done(host));

        host.done = -1;

        Assert.Equal(-1, host.done);
    }

    [Fact]
    public void HostentFree_WithNoAllocatedData_DoesNotThrow()
    {
        DirtyNetPS3.HostentT host = new();

        Assert.Null(host.Free);
    }
}
