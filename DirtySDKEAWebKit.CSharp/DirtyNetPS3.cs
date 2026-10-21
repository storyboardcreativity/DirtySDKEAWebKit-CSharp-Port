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

    private static int _XlatError(SocketError error)
    {
        return error switch
        {
            SocketError.Success => 0,
            SocketError.WouldBlock or SocketError.IOPending => 0,
            SocketError.NetworkUnreachable or SocketError.HostUnreachable => -5,
            SocketError.NotConnected => -2,
            SocketError.ConnectionRefused => -6,
            SocketError.InvalidArgument => -11,
            SocketError.ConnectionReset => -13,
            _ => -7
        };
    }

    private static Socket? _SocketOpen(Socket? socket, AddressFamily family, SocketType type, ProtocolType proto, bool opened)
    {
        SocketStateT? state = _Socket_pState;
        if (state is null)
            return null;
            
        try
        {
            if (socket is null)
            {
                socket = new Socket(family, type, proto);
                socket.Blocking = false;
            }

            return socket;
        }
        catch (SocketException ex)
        {
            Tools.NetPrintf($"dirtynetps3: socket() failed (err={ex.SocketErrorCode})");
            return null;
        }
    }

    private static int _SocketRecvfrom(Socket? socket, byte[] buffer, int length, EndPoint? from)
    {
        if (socket == null)
            return -1;

        if (length < 0 || length > buffer.Length)
            return -1;

        try
        {
            if (from is not null)
            {
                EndPoint remote = from;
                int result = socket.ReceiveFrom(
                    buffer,
                    0,
                    length,
                    SocketFlags.None,
                    ref remote);

                return result;
            }

            return socket.Receive(
                buffer,
                0,
                length,
                SocketFlags.None);
        }
        catch (SocketException ex)
        {
            return _XlatError(ex.SocketErrorCode);
        }
        catch (ObjectDisposedException)
        {
            return SOCKERR_INVALID;
        }
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

        IntPtr pool = DirtyMem.DirtyMemAlloc(_Socket_iMemPoolSize, SOCKET_MEMID, group, userData);

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

    public static Socket? SocketOpen(AddressFamily family, SocketType type, ProtocolType proto) =>
        _SocketOpen(null, family, type, proto, false);

    public static int SocketClose(Socket socket)
    {
        SocketShutdown(socket, SOCK_NOSEND);

        try
        {
            socket.Dispose();
        }
        catch (SocketException ex)
        {
            Tools.NetPrintf($"dirtynetps3: socketclose() failed (err={ex.SocketErrorCode})\n");
        }

        return 0;
    }

    public static int SocketShutdown(Socket? socket, int how)
    {
        if (socket == null || socket.SocketType != SocketType.Stream)
            return SOCKERR_NONE;

        try
        {
            SocketShutdown howTo = how switch
            {
                SOCK_NOSEND => System.Net.Sockets.SocketShutdown.Send,
                SOCK_NORECV => System.Net.Sockets.SocketShutdown.Receive,
                SOCK_NOSEND | SOCK_NORECV => System.Net.Sockets.SocketShutdown.Both,
                _ => (SocketShutdown)how
            };

            socket.Shutdown(howTo);
            return SOCKERR_NONE;
        }
        catch (SocketException ex)
        {
            Tools.NetPrintf($"dirtynetps3: shutdown() failed (err={ex.SocketErrorCode})\n");
            return _XlatError(ex.SocketErrorCode);
        }
        catch (ObjectDisposedException)
        {
            return SOCKERR_NONE;
        }
    }

    public static int SocketBind(Socket? socket, EndPoint? endpoint)
    {
        if (socket is null || endpoint is null)
            return SOCKERR_INVALID;

        try
        {
            socket.Bind(endpoint);
            return SOCKERR_NONE;
        }
        catch (SocketException ex)
        {
            return _XlatError(ex.SocketErrorCode);
        }
        catch (ObjectDisposedException)
        {
            return SOCKERR_INVALID;
        }
    }

    public static int SocketConnect(Socket? socket, EndPoint? address)
    {
        if (socket is null || address is null)
            return SOCKERR_INVALID;

        try
        {
            socket.Connect(address);
            return SOCKERR_NONE;
        }
        catch (SocketException ex)
        {
            int errcode = _XlatError(ex.SocketErrorCode);
            if (errcode != SOCKERR_NONE)
                Tools.NetPrintf($"dirtynetps3: connect() failed (err={ex.SocketErrorCode})");
            return errcode;
        }
        catch (ObjectDisposedException)
        {
            return SOCKERR_INVALID;
        }
    }

    public static int SocketListen(Socket? socket, int backlog)
    {
        if (socket is null)
            return SOCKERR_INVALID;

        try
        {
            socket.Listen(backlog);
            return SOCKERR_NONE;
        }
        catch (SocketException ex)
        {
            Tools.NetPrintf($"dirtynetps3: listen() failed (err={ex.SocketErrorCode})\n");
            return _XlatError(ex.SocketErrorCode);
        }
        catch (ObjectDisposedException)
        {
            return SOCKERR_INVALID;
        }
    }

    public static Socket? SocketAccept(Socket? socket, out IPEndPoint? address)
    {
        address = null;

        if (socket is null || socket.SocketType != SocketType.Stream || socket.AddressFamily != AddressFamily.InterNetwork)
            return null;

        try
        {
            Socket incoming = socket.Accept();
            incoming.Blocking = false;

            address = incoming.RemoteEndPoint as IPEndPoint;

            Socket? result = _SocketOpen(
                incoming,
                incoming.AddressFamily,
                incoming.SocketType,
                incoming.ProtocolType,
                true);

            if (result is null)
            {
                incoming.Dispose();
                address = null;
            }

            return result;
        }
        catch (SocketException ex)
        {
            if (ex.SocketErrorCode != SocketError.WouldBlock)
                Tools.NetPrintf($"dirtynetps3: accept() failed (err={ex.SocketErrorCode})");

            return null;
        }
        catch (ObjectDisposedException)
        {
            return null;
        }
    }

    public static int SocketSendto(Socket? socket, byte[] buffer, int length, int flags, EndPoint? address)
    {
        if (socket is null)
            return SOCKERR_INVALID;

        if (buffer is null || length < 0 || length > buffer.Length)
            return SOCKERR_INVALID;

        try
        {
            int result = address is null
                ? socket.Send(buffer, 0, length, (SocketFlags)flags)
                : socket.SendTo(buffer, 0, length, (SocketFlags)flags, address);

            return result;
        }
        catch (SocketException ex)
        {
            return _XlatError(ex.SocketErrorCode);
        }
        catch (ObjectDisposedException)
        {
            return SOCKERR_INVALID;
        }
    }

    public static int SocketSend(Socket? socket, byte[] buffer, int length, int flags)
    {
        return SocketSendto(socket, buffer, length, flags, null);
    }

    public static int SocketRecvfrom(Socket? socket, byte[] buffer, int length, int flags, EndPoint? from)
    {
        if (socket == null)
            return SOCKERR_INVALID;

        if (buffer is null || length < 0 || length > buffer.Length)
            return SOCKERR_INVALID;

        int iRecv = -1;
        if (socket.SocketType == SocketType.Stream)
        {
            iRecv = _SocketRecvfrom(socket, buffer, length, from);
            if (iRecv < 0 && iRecv != unchecked((int)0x80010223))//or again
                Tools.NetPrintf($"dirtynetps3: _SocketRecvfrom() failed (err={iRecv})\n\n");
        }

        return iRecv == 0 ? SOCKERR_CLOSED : iRecv;
    }

    public static int SocketRecv(Socket? socket, byte[] buffer, int length, int flags)
    {
        return SocketRecvfrom(socket, buffer, length, flags, null);
    }

    public static int SocketInfo(Socket? socket, int info, int data, IntPtr buffer, int length)
    {
        if (buffer != IntPtr.Zero && length > 0)
        {
            for (int i = 0; i < length; i++)
                Marshal.WriteByte(buffer, i, 0);
        }

        if (socket is null)
            return -2;

        if (info == Tools.FourCC("stat"))
        {
            int opened = 0;
            try
            {
                if (socket.Poll(0, SelectMode.SelectWrite) || socket.Poll(0, SelectMode.SelectError))
                {
                    int error = (int)socket.GetSocketOption(
                        SocketOptionLevel.Socket,
                        SocketOptionName.Error)!;

                    opened = error == 0 ? 1 : -1;
                }

                if (opened > 0)
                {
                    try
                    {
                        if (socket.RemoteEndPoint is null)
                            opened = -1;
                    }
                    catch (SocketException)
                    {
                        opened = -1;
                    }
                }
            }
            catch (SocketException)
            {
                return -1;
            }
            catch (ObjectDisposedException)
            {
                return -1;
            }

            return opened;
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
            // We use our wrapped instead of the "Dns.GetHostAddresses(host.Name)" because
            //     we need to connect to Revora instead of the old standard dead EA servers
            IPAddress[] addresses = GetHostByNameWrapper(host.Name);
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

    private static IPAddress[] GetHostByNameWrapper(string name)
    {
        string res = name;

        if (_matches(name, "servserv.generals.ea.com", "na.llnet.eadownloads.ea.com"))
            res = "http.server.cnc-online.net";
        else if (_matches(name, "bfme.fesl.ea.com", "bfme2.fesl.ea.com",
            "bfme2-ep1-pc.fesl.ea.com", "cnc3-pc.fesl.ea.com",
            "cnc3-ep1-pc.fesl.ea.com", "cncra3-pc.fesl.ea.com"))
            res = "login.server.cnc-online.net";
        else if (_matches(name, "gpcm.gamespy.com"))
            res = "gpcm.server.cnc-online.net";
        else if (_matches(name, "peerchat.gamespy.com"))
            res = "peerchat.server.cnc-online.net";
        else if (_matches(name, "lotrbme.available.gamespy.com", "lotrbme.master.gamespy.com",
            "lotrbme.ms13.gamespy.com", "lotrbme2r.available.gamespy.com",
            "lotrbme2r.master.gamespy.com", "lotrbme2r.ms9.gamespy.com",
            "ccgenerals.ms19.gamespy.com", "ccgenzh.ms6.gamespy.com",
            "cc3tibwars.available.gamespy.com", "cc3tibwars.master.gamespy.com",
            "cc3tibwars.ms17.gamespy.com", "cc3xp1.available.gamespy.com",
            "cc3xp1.master.gamespy.com", "cc3xp1.ms18.gamespy.com",
            "redalert3pc.available.gamespy.com", "redalert3pc.master.gamespy.com",
            "redalert3pc.ms1.gamespy.com", "master.gamespy.com"))
            res = "master.server.cnc-online.net";
        else if (_matches(name, "redalert3pc.natneg1.gamespy.com",
            "redalert3pc.natneg2.gamespy.com", "redalert3pc.natneg3.gamespy.com"))
            res = "natneg.server.cnc-online.net";
        else if (_matches(name, "lotrbme.gamestats.gamespy.com",
            "lotrbme2r.gamestats.gamespy.com", "gamestats.gamespy.com"))
            res = "gamestats.server.cnc-online.net";
        else if (_matches(name, "lotrbfme.arenasdk.gamespy.com",
            "arenasdk.gamespy.com", "launch.gamespyarcade.com",
            "www.gamespy.com", "ingamead.gamespy.com"))
            res = "server.cnc-online.net";

        if (res != name)
            Tools.NetPrintf($"Changed host \"{name}\" to \"{res}\"");

        return Dns.GetHostAddresses(res);
    }

    private static bool _matches(string name, params string[] values)
    {
        foreach (string value in values)
            if (string.Equals(name, value, StringComparison.Ordinal))
                return true;
        return false;
    }
}
