using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.CSharp;

public static class DirtyNetPS3
{
    private const int INVALID_SOCKET = -1;
    private const int SOCKET_MAXPOLL = 32;
    private const int SOCKET_MEMID = unchecked((int)0x64736F63);
    private const int SOCKERR_NONE = 0;
    private const int SOCKERR_CLOSED = -1;
    private const int SOCKERR_NOTCONN = -2;
    private const int SOCKERR_BLOCKED = -3;
    private const int SOCKERR_ADDRESS = -4;
    private const int SOCKERR_UNREACH = -5;
    private const int SOCKERR_REFUSED = -6;
    private const int SOCKERR_OTHER = -7;
    private const int SOCKERR_NOMEM = -8;
    private const int SOCKERR_NORSRC = -9;
    private const int SOCKERR_UNSUPPORT = -10;
    private const int SOCKERR_INVALID = -11;
    private const int SOCKERR_ADDRINUSE = -12;
    private const int SOCKERR_CONNRESET = -13;
    private const int SOCK_NORECV = 1;
    private const int SOCK_NOSEND = 2;
    private const int DIRTYVERS = 0x07050300;
    private const int AF_INET = 2;
    private const int SOCK_STREAM = 1;
    private const int SOCK_DGRAM = 2;
    private const int SOCK_RAW = 3;
    private const int SOL_SOCKET = 1;
    private const int POLLIN = 0x001;
    private const int POLLERR = 0x008;
    private const int POLLOUT = 0x004;
    private const int SOCKET_ERROR = -1;

    private static readonly PlatformSocketAPICallbacks gPlatformSocketAPICallbacks = new(
        OperatingSystem.IsWindows() ? unchecked((int)0xFFAACC01) : unchecked((int)0xFFAACC01));

    private static SocketStateT? _Socket_pState;
    private static int _Socket_iMemPoolSize = 128 * 1024;

    [StructLayout(LayoutKind.Sequential)]
    private struct PollFd
    {
        public int fd;
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

    private sealed class SocketT
    {
        public int family;
        public int type;
        public int proto;
        public sbyte opened;
        public byte unused;
        public int socket;
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

    private sealed class SocketLookupPrivT
    {
        public HostentT Host = new();
    }

    public sealed class HostentT
    {
        public int done;
        public uint addr;
        public Func<HostentT, int>? Done;
        public Action<HostentT>? Free;
        public string name = string.Empty;
        public int sema;
        public int thread;
        public IntPtr pData;
        public uint timeout;
    }

    private static int _XlatError(int error) =>
        gPlatformSocketAPICallbacks.getlasterror(error);

    //private static Sockaddr _SockAddrToSceAddr(in Sockaddr source) => source;

    private static SocketT? _SocketOpen(
        int socket, int family, int type, int proto, int opened)
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

    private static int _SocketLookupDone(HostentT host) => host.done;

    private static void _SocketLookupFree(HostentT host)
    {
        if (host.pData != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(host.pData);
            host.pData = IntPtr.Zero;
        }
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

    public static int SocketCreate(int threadPriority)
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

    public static int SocketDestroy(uint flags)
    {
        SocketStateT? state = _Socket_pState;
        if (state is null)
            return -1;

        DirtyMem.DirtyMemFree(
            state.pMemPool, SOCKET_MEMID, state.iMemGroup, state.pMemGroupUserData);

        _Socket_pState = null;
        return 0;
    }

    public static object? SocketOpen(int family, int type, int proto) =>
        _SocketOpen(INVALID_SOCKET, family, type, proto, 0);

    public static int SocketClose(object socket)
    {
        if (socket is not SocketT s)
            return SOCKERR_INVALID;

        int fd = s.socket;
        SocketShutdown(s, SOCK_NOSEND);
        _SocketClose(s);

        if (fd >= 0)
            gPlatformSocketAPICallbacks.close(fd);

        return 0;
    }

    public static int SocketShutdown(object socket, int how)
    {
        if (socket is not SocketT s || s.type != SOCK_STREAM || s.socket == INVALID_SOCKET)
            return SOCKERR_NONE;

        int nativeHow = how switch
        {
            SOCK_NOSEND => OperatingSystem.IsWindows() ? 1 : 1,
            SOCK_NORECV => OperatingSystem.IsWindows() ? 0 : 0,
            SOCK_NOSEND | SOCK_NORECV => 2,
            _ => how
        };

        return _XlatError(gPlatformSocketAPICallbacks.shutdown(s.socket, nativeHow));
    }

    public static int SocketBind(object socket, IntPtr address, int addressLength)
    {
        if (socket is not SocketT s || s.socket < 0 || address == IntPtr.Zero)
            return SOCKERR_INVALID;

        return _XlatError(gPlatformSocketAPICallbacks.bind(
            s.socket, address, addressLength));
    }

    public static int SocketConnect(object socket, IntPtr address, int addressLength)
    {
        if (socket is not SocketT s || s.socket < 0 || address == IntPtr.Zero)
            return SOCKERR_INVALID;

        s.opened = 0;
        int result = gPlatformSocketAPICallbacks.connect(
            s.socket, address, addressLength);

        if (result < 0 && _XlatError(result) != SOCKERR_NONE)
            Tools.NetPrintf($"dirtynetps3: connect() failed (err={result})");

        return _XlatError(result);
    }

    public static int SocketListen(object socket, int backlog)
    {
        if (socket is not SocketT s)
            return SOCKERR_INVALID;

        return _XlatError(gPlatformSocketAPICallbacks.listen(s.socket, backlog));
    }

    public static object? SocketAccept(object socket, IntPtr address, IntPtr addressLength)
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

        int incoming = gPlatformSocketAPICallbacks.accept(s.socket, address, ref length);

        if (address != IntPtr.Zero)
            Marshal.WriteInt32(addressLength, length);

        if (incoming < 0)
            return null;

        return _SocketOpen(incoming, s.family, s.type, s.proto, 1);
    }

    public static int SocketSendto(object socket, IntPtr buffer, int length, int flags, IntPtr address, int addressLength)
    {
        if (socket is not SocketT s || s.socket < 0)
            return SOCKERR_INVALID;

        nint result = address == IntPtr.Zero
            ? gPlatformSocketAPICallbacks.send(s.socket, buffer, (nuint)length, 0)
            : gPlatformSocketAPICallbacks.sendto(
                s.socket, buffer, (nuint)length, 0, address, addressLength);

        return _XlatError(checked((int)result));
    }

    public static int SocketRecvfrom(
        object socket, IntPtr buffer, int length, int flags,
        IntPtr from, IntPtr fromLength)
    {
        if (socket is not SocketT s)
            return SOCKERR_INVALID;

        int result = -1;

        if (s.type == SOCK_STREAM)
        {
            if (s.socket == INVALID_SOCKET)
                return SOCKERR_INVALID;

            result = _SocketRecvfrom(s, buffer, length, from, fromLength);
        }

        return result == 0 ? SOCKERR_CLOSED : _XlatError(result);
    }

    public static int SocketInfo(
        object socket, int info, int data, IntPtr buffer, int length)
    {
        if (buffer != IntPtr.Zero && length > 0)
        {
            for (int i = 0; i < length; i++)
                Marshal.WriteByte(buffer, i, 0);
        }

        if (socket is not SocketT s || s.socket == INVALID_SOCKET)
            return -2;

        if (info == DirtyMem.FourCC("stat"))
        {
            if (s.opened == 0)
            {
                PollFd pollFd = new()
                {
                    fd = s.socket,
                    events = (short)(POLLOUT | (OperatingSystem.IsWindows() ? 0 : POLLERR))
                };

                IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf<PollFd>());
                try
                {
                    Marshal.StructureToPtr(pollFd, p, false);
                    int result = gPlatformSocketAPICallbacks.poll(
                        p, 1, 0);
                    pollFd = Marshal.PtrToStructure<PollFd>(p);

                    if (result != 0)
                    {
                        if (result == SOCKET_ERROR || (pollFd.revents & POLLERR) != 0)
                            s.opened = -1;

                        if ((pollFd.revents & POLLOUT) != 0)
                            s.opened = 1;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(p);
                }
            }

            if (s.opened > 0)
            {
                const int bufferSize = 128; // sizeof(sockaddr) + some safe space
                IntPtr peer = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    int peerLength = bufferSize;
                    if (gPlatformSocketAPICallbacks.getpeername(s.socket, peer, ref peerLength) < 0)
                        s.opened = -1;
                }
                finally
                {
                    Marshal.FreeHGlobal(peer);
                }
            }

            return s.opened;
        }

        return -1;
    }

    public static int SocketControl(
        object? socket, int option, int data1, IntPtr data2, IntPtr data3)
    {
        if (option == DirtyMem.FourCC("pool"))
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
            Done = _SocketLookupDone,
            Free = _SocketLookupFree,
            name = text.Length > 63 ? text[..63] : text
        };

        if (IPAddress.TryParse(text, out IPAddress? address) &&
            address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = address.GetAddressBytes();
            host.addr = ((uint)bytes[0] << 24) |
                        ((uint)bytes[1] << 16) |
                        ((uint)bytes[2] << 8) |
                        bytes[3];
            host.done = 1;
            return host;
        }

        IntPtr nativeHost = gPlatformSocketAPICallbacks.gethostbyname(host.name);

        if (nativeHost != IntPtr.Zero)
        {
            NativeHostent native = Marshal.PtrToStructure<NativeHostent>(nativeHost);

            if (native.h_addr_list != IntPtr.Zero)
            {
                IntPtr firstAddress = Marshal.ReadIntPtr(native.h_addr_list);
                if (firstAddress != IntPtr.Zero)
                {
                    byte[] bytes = new byte[4];
                    Marshal.Copy(firstAddress, bytes, 0, bytes.Length);

                    host.addr = ((uint)bytes[0] << 24) |
                                ((uint)bytes[1] << 16) |
                                ((uint)bytes[2] << 8) |
                                bytes[3];
                    host.done = 1;
                }
                else
                {
                    host.done = -1;
                }
            }
            else
            {
                host.done = -1;
            }
        }
        else
        {
            host.done = -1;
        }

        host.sema = 0;
        return host;
    }
}
