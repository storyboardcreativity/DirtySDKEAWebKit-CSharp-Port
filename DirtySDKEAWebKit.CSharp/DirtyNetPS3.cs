using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.CSharp;

public static class DirtyNetPS3
{
    public const int INVALID_SOCKET = -1;
    public const int SOCKET_MAXPOLL = 32;
    public const int SOCKET_MEMID = unchecked((int)0x64736F63);
    public const int SOCKERR_NONE = 0;
    public const int SOCKERR_CLOSED = -1;
    public const int SOCKERR_NOTCONN = -2;
    public const int SOCKERR_BLOCKED = -3;
    public const int SOCKERR_ADDRESS = -4;
    public const int SOCKERR_UNREACH = -5;
    public const int SOCKERR_REFUSED = -6;
    public const int SOCKERR_OTHER = -7;
    public const int SOCKERR_NOMEM = -8;
    public const int SOCKERR_NORSRC = -9;
    public const int SOCKERR_UNSUPPORT = -10;
    public const int SOCKERR_INVALID = -11;
    public const int SOCKERR_ADDRINUSE = -12;
    public const int SOCKERR_CONNRESET = -13;
    public const int SOCK_NORECV = 1;
    public const int SOCK_NOSEND = 2;
    public const int DIRTYVERS = 0x07050300;
    public const int AF_INET = 2;
    public const int SOCK_STREAM = 1;
    public const int SOCK_DGRAM = 2;
    public const int SOCK_RAW = 3;
    public const int SOL_SOCKET = 1;

    
    public const int POLLRDNORM = 0x0100;
    public const int POLLRDBAND = 0x0200;
    public const int POLLIN = (POLLRDNORM | POLLRDBAND);
    public const int POLLPRI = 0x0400;
    public const int POLLWRNORM = 0x0010;
    public const int POLLOUT = (POLLWRNORM);
    public const int POLLWRBAND = 0x0020;
    public const int POLLERR = 0x0001;
    public const int POLLHUP = 0x0002;
    public const int POLLNVAL = 0x0004;
    

    public const int SOCKET_ERROR = -1;

    private static readonly PlatformSocketAPICallbacks gPlatformSocketAPICallbacks = new(
        OperatingSystem.IsWindows() ? unchecked((int)0xFFAACC01) : unchecked((int)0xFFAACC01));

    private static SocketStateT? _Socket_pState = null;
    private static int _Socket_iMemPoolSize = 128 * 1024;

    [StructLayout(LayoutKind.Sequential)]
    private struct PollFd
    {
        public nint fd;
        public short events;
        public short revents;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeHostent
    {
        public IntPtr h_name;
        public IntPtr h_aliases;
        public int h_addrtype;
        public int h_length;
        public IntPtr h_addr_list;
    }

    public sealed class SocketT
    {
        public int family;
        public int type;
        public int proto;
        public sbyte opened;
        public byte unused;
        public nint socket;
    }

    private sealed class SocketStateT
    {
        public int iMemGroup;
        public IntPtr pMemGroupUserData;
        public IntPtr pMemPool;
        public int iSid;
        public int iHandlerId;
        public uint uConnStatus;
        public uint uLocalAddr;
        public readonly byte[] aMacAddr = new byte[6];
    }

    public sealed class HostentT
    {
        public enum HostLookupStatus
        {
            Pending = 0,
            Success = 1,
            Failed = -1
        }

        public HostLookupStatus Status { get; set; } = HostLookupStatus.Pending;
        public IPAddress? Address { get; set; } = null;
        public string Name { get; set; } = string.Empty;
    }

    static DirtyNetPS3()
    {
        // Initialize networking automatically at start
        SocketCreate(0);
    }

    private static int _XlatError(int error) =>
        gPlatformSocketAPICallbacks.getlasterror(error);

    //private static Sockaddr _SockAddrToSceAddr(in Sockaddr source) => source;

    private static SocketT? _SocketOpen(nint socket, int family, int type, int proto, int opened)
    {
        SocketStateT? state = _Socket_pState;
        if (state is null)
            return null;

        SocketT result = new();

        if (socket == INVALID_SOCKET)
        {
            socket = gPlatformSocketAPICallbacks.socket(AF_INET, type, proto);
            if (socket >= 0)
            {
                IntPtr value = Marshal.AllocHGlobal(sizeof(uint));
                try
                {
                    Marshal.WriteInt32(value, 1);
                    gPlatformSocketAPICallbacks.setsockopt(
                        socket, SOL_SOCKET, gPlatformSocketAPICallbacks.SO_NBIO,
                        value, sizeof(uint));
                }
                finally
                {
                    Marshal.FreeHGlobal(value);
                }
            }
            else
            {
                Tools.NetPrintf($"dirtynetps3: socket() failed (err={socket})");
            }
        }

        result.family = family;
        result.type = type;
        result.proto = proto;
        result.socket = socket;
        result.opened = (sbyte)opened;
        return result;
    }

    private static int _SocketClose(SocketT socket)
    {
        socket.socket = INVALID_SOCKET;
        socket.opened = 0;
        return 0;
    }

    private static int _SocketRecvfrom(SocketT socket, IntPtr buffer, int length, IntPtr from, IntPtr fromLength)
    {
        if (from != IntPtr.Zero)
        {
            if (fromLength == IntPtr.Zero)
                return -1;

            int fromLen = Marshal.ReadInt32(fromLength);
            int result = checked((int)gPlatformSocketAPICallbacks.recvfrom(
                socket.socket, buffer, (nuint)length, 0, from, ref fromLen));

            Marshal.WriteInt32(fromLength, fromLen);
            return result;
        }

        return checked((int)gPlatformSocketAPICallbacks.recv(
            socket.socket, buffer, (nuint)length, 0));
    }

    private static int SocketCreate(int threadPriority)
    {
        DirtyMem.DirtyMemGroupQuery(out int group, out IntPtr userData);

        if (_Socket_pState is not null)
            return -1;

        Tools.NetPrintf($"dirtynetps3: DirtySock SDK v{(DIRTYVERS >> 24) & 255}.{(DIRTYVERS >> 16) & 255}.{(DIRTYVERS >> 8) & 255}.{DIRTYVERS & 255}\n");

        //IntPtr stateMemory = DirtyMem.DirtyMemAlloc(
        //    Marshal.SizeOf<SocketStateT>(), SOCKET_MEMID, group, userData);
        //if (stateMemory == IntPtr.Zero)
        //    return -2;

        IntPtr pool = DirtyMem.DirtyMemAlloc(
            _Socket_iMemPoolSize, SOCKET_MEMID, group, userData);

        if (pool == IntPtr.Zero)
        {
            //DirtyMem.DirtyMemFree(stateMemory, SOCKET_MEMID, group, userData);
            return -3;
        }

        _Socket_pState = new SocketStateT
        {
            iMemGroup = group,
            pMemGroupUserData = userData,
            pMemPool = pool
        };

        //DirtyMem.DirtyMemFree(stateMemory, SOCKET_MEMID, group, userData);
        return 0;
    }

    private static int SocketDestroy(uint flags)
    {
        SocketStateT? state = _Socket_pState;
        if (state is null)
            return -1;

        DirtyMem.DirtyMemFree(
            state.pMemPool, SOCKET_MEMID, state.iMemGroup, state.pMemGroupUserData);

        _Socket_pState = null;
        return 0;
    }

    public static SocketT? SocketOpen(int family, int type, int proto) =>
        _SocketOpen(-1, family, type, proto, 0);

    public static int SocketClose(SocketT socket)
    {
        nint fd = socket.socket;
        SocketShutdown(socket, SOCK_NOSEND);
        if (_SocketClose(socket) < 0)
            return -1;

        if (fd >= 0)
        {
            int iResult = gPlatformSocketAPICallbacks.close(fd);
            if (iResult < 0)
                Tools.NetPrintf("dirtynetps3: socketclose() failed (err=" + iResult + ")\n");
        }

        return 0;
    }

    public static int SocketShutdown(SocketT socket, int how)
    {
        if (socket.type != SOCK_STREAM || socket.socket == INVALID_SOCKET)
            return SOCKERR_NONE;

        int nativeHow = how switch
        {
            SOCK_NOSEND => OperatingSystem.IsWindows() ? 1 : 1, // SHUT_WR
            SOCK_NORECV => OperatingSystem.IsWindows() ? 0 : 0, // SHUT_RD
            SOCK_NOSEND | SOCK_NORECV => 2, // SHUT_RDWR
            _ => how
        };

        int iResult = gPlatformSocketAPICallbacks.shutdown(socket.socket, nativeHow);
        if (iResult < 0)
            Tools.NetPrintf($"dirtynetps3: shutdown() failed (err={iResult})\n");

        return _XlatError(iResult);
    }

    public static int SocketBind(SocketT socket, IntPtr address, int addressLength)
    {
        if (socket is not SocketT s || s.socket < 0 || address == IntPtr.Zero)
            return SOCKERR_INVALID;

        return _XlatError(gPlatformSocketAPICallbacks.bind(
            s.socket, address, addressLength));
    }

    public static int SocketConnect(SocketT socket, IntPtr address, int addressLength)
    {
        if (socket is not SocketT s || s.socket < 0 || address == IntPtr.Zero)
            return SOCKERR_INVALID;

        s.opened = 0;
        int result = gPlatformSocketAPICallbacks.connect(s.socket, address, addressLength);

        if (result < 0 && _XlatError(result) != SOCKERR_NONE)
            Tools.NetPrintf($"dirtynetps3: connect() failed (err={result})");

        return _XlatError(result);
    }

    public static int SocketConnect(SocketT socket, EndPoint endpoint)
    {
        SocketAddress address = endpoint.Serialize();

        byte[] buffer = new byte[address.Size];

        for (int i = 0; i < address.Size; i++)
            buffer[i] = address[i];

        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            return SocketConnect(socket, handle.AddrOfPinnedObject(), buffer.Length);
        }
        finally
        {
            handle.Free();
        }
    }

    public static int SocketListen(SocketT socket, int backlog)
    {
        int iResult = gPlatformSocketAPICallbacks.listen(socket.socket, backlog);
        if (iResult < 0)
            Tools.NetPrintf($"dirtynetps3: listen() failed (err={iResult})\n");
        return _XlatError(iResult);
    }

    public static SocketT? SocketAccept(SocketT socket, IntPtr address, IntPtr addressLength)
    {
        if (socket is not SocketT s || s.socket == INVALID_SOCKET || s.family != AF_INET)
            return null;

        int length = 0;

        if (address != IntPtr.Zero)
        {
            if (addressLength == IntPtr.Zero)
                return null;

            length = Marshal.ReadInt32(addressLength);
            if (length <= 0)
                return null;
        }

        nint incoming = gPlatformSocketAPICallbacks.accept(s.socket, address, ref length);

        if (address != IntPtr.Zero)
            Marshal.WriteInt32(addressLength, length);

        if (incoming < 0)
            return null;

        return _SocketOpen(incoming, s.family, s.type, s.proto, 1);
    }

    public static int SocketSendto(SocketT socket, IntPtr buffer, int length, int flags, IntPtr address, int addressLength)
    {
        if (socket.socket < 0)
            return SOCKERR_INVALID;

        nint result = address == IntPtr.Zero
            ? gPlatformSocketAPICallbacks.send(socket.socket, buffer, (nuint)length, 0)
            : gPlatformSocketAPICallbacks.sendto(
                socket.socket, buffer, (nuint)length, 0, address, addressLength);

        return _XlatError(checked((int)result));
    }

    public static int SocketSend(SocketT socket, IntPtr buffer, int length, int flags)
    {
        return SocketSendto(socket, buffer, length, flags, IntPtr.Zero, 0);
    }

    public static int SocketSend(SocketT socket, byte[] buffer, int length, int flags)
    {
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            return SocketSend(socket, handle.AddrOfPinnedObject(), length, flags);
        }
        finally
        {
            handle.Free();
        }
    }

    public static int SocketRecvfrom(SocketT socket, IntPtr buffer, int length, int flags, IntPtr from, IntPtr fromLength)
    {
        int iRecv = -1;

        if (socket.type == SOCK_STREAM)
        {
            if (socket.socket == INVALID_SOCKET)
                return SOCKERR_INVALID;

            iRecv = _SocketRecvfrom(socket, buffer, length, from, fromLength);
            if (iRecv < 0 && iRecv != unchecked((int)0x80010223))//or again
                Tools.NetPrintf($"dirtynetps3: _SocketRecvfrom() failed (err={iRecv})\n\n");
        }

        return iRecv == 0 ? SOCKERR_CLOSED : _XlatError(iRecv);
    }

    public static int SocketRecv(SocketT socket, IntPtr buffer, int length, int flags)
    {
        return SocketRecvfrom(socket, buffer, length, flags, IntPtr.Zero, IntPtr.Zero);
    }

    public static int SocketRecv(SocketT socket, byte[] buffer, int length, int flags)
    {
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            return SocketRecvfrom(
                socket,
                handle.AddrOfPinnedObject(),
                length,
                flags,
                IntPtr.Zero,
                IntPtr.Zero
            );
        }
        finally
        {
            handle.Free();
        }
    }

    public static int SocketInfo(SocketT socket, int info, int data, IntPtr buffer, int length)
    {
        if (buffer != IntPtr.Zero && length > 0)
        {
            for (int i = 0; i < length; i++)
                Marshal.WriteByte(buffer, i, 0);
        }

        if (socket.socket == INVALID_SOCKET)
            return -2;

        if (info == Tools.FourCC("stat"))
        {
            if (socket.opened == 0)
            {
                PollFd pollFd = new()
                {
                    fd = socket.socket,
                    events = (short)(POLLOUT | (OperatingSystem.IsWindows() ? 0 : POLLERR)),
                    revents = 0
                };

                IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf<PollFd>());
                try
                {
                    Marshal.StructureToPtr(pollFd, p, false);
                    int result = gPlatformSocketAPICallbacks.poll(p, 1, 0);
                    pollFd = Marshal.PtrToStructure<PollFd>(p);

                    if (result != 0)
                    {
                        if (result == SOCKET_ERROR || (pollFd.revents & POLLERR) != 0)
                            socket.opened = -1;

                        if ((pollFd.revents & POLLOUT) != 0)
                            socket.opened = 1;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(p);
                }
            }

            if (socket.opened > 0)
            {
                const int bufferSize = 128; // sizeof(sockaddr) + some safe space
                IntPtr peer = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    int peerLength = bufferSize;
                    if (gPlatformSocketAPICallbacks.getpeername(socket.socket, peer, ref peerLength) < 0)
                        socket.opened = -1;
                }
                finally
                {
                    Marshal.FreeHGlobal(peer);
                }
            }

            return socket.opened;
        }

        return -1;
    }

    public static int SocketControl(SocketT? socket, int option, int data1, IntPtr data2, IntPtr data3)
    {
        if (option == Tools.FourCC("pool"))
        {
            _Socket_iMemPoolSize = data1;
            return 0;
        }

        return -1;
    }

    public static HostentT? SocketLookup(string text, int timeout)
    {
        SocketStateT? state = _Socket_pState;
        if (state is null || timeout < 0)
            return null;

        HostentT host = new()
        {
            Name = text.Length > 63 ? text[..63] : text,
            Address = null
        };

        if (IPAddress.TryParse(text, out IPAddress? address) &&
            address.AddressFamily == AddressFamily.InterNetwork)
        {
            host.Address = address;
            host.Status = HostentT.HostLookupStatus.Success;
            return host;
        }

        try
        {
            IPAddress[] addresses = Dns.GetHostAddresses(host.Name);
            IPAddress? ipv4 = Array.Find(addresses, a => a.AddressFamily == AddressFamily.InterNetwork);
            if (ipv4 is not null)
            {
                host.Address = ipv4;
                host.Status = HostentT.HostLookupStatus.Success;
            }
            else
            {
                host.Status = HostentT.HostLookupStatus.Failed;
            }
        }
        catch (SocketException)
        {
            host.Status = HostentT.HostLookupStatus.Failed;
        }
        catch (ArgumentException)
        {
            host.Status = HostentT.HostLookupStatus.Failed;
        }

        return host;
    }
}
