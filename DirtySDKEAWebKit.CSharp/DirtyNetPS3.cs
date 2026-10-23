using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.CSharp;

public class DirtyNetPS3
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


    private readonly Socket _socket;
    public DirtyNetPS3(Socket socket)
    {
        _socket = socket;
    }

    static DirtyNetPS3()
    {
        Tools.NetPrintf($"dirtynetps3: DirtySock SDK v{(DIRTYVERS >> 24) & 255}.{(DIRTYVERS >> 16) & 255}.{(DIRTYVERS >> 8) & 255}.{DIRTYVERS & 255}\n");
    }

    private static int _XlatError(SocketError error)
    {
        return error switch
        {
            SocketError.Success => SOCKERR_NONE,
            SocketError.WouldBlock or SocketError.IOPending => SOCKERR_NONE,
            SocketError.NetworkUnreachable or SocketError.HostUnreachable => SOCKERR_UNREACH,
            SocketError.NotConnected => SOCKERR_NOTCONN,
            SocketError.ConnectionRefused => SOCKERR_REFUSED,
            SocketError.InvalidArgument => SOCKERR_INVALID,
            SocketError.ConnectionReset => SOCKERR_CONNRESET,
            _ => SOCKERR_OTHER
        };
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
                int result = socket.ReceiveFrom(buffer, 0, length, SocketFlags.None, ref remote);
                
                //Tools.NetPrintf($"Received {buffer.Length} bytes from socket:");
                //Tools.PrintBuffer(buffer);
                return result;
            }

            int res = socket.Receive(
                buffer,
                0,
                length,
                SocketFlags.None);

            //Tools.NetPrintf($"Received {buffer.Length} bytes from socket:");
            //Tools.PrintBuffer(buffer);
            return res;
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

    public int SocketClose()
    {
        SocketShutdown(SOCK_NOSEND);

        try
        {
            _socket.Dispose();
        }
        catch (SocketException ex)
        {
            Tools.NetPrintf($"dirtynetps3: socketclose() failed (err={ex.SocketErrorCode})\n");
        }

        return 0;
    }

    public int SocketShutdown(int how)
    {
        if (_socket == null || _socket.SocketType != SocketType.Stream)
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

            _socket.Shutdown(howTo);
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

    public int SocketBind(EndPoint? endpoint)
    {
        if (_socket is null || endpoint is null)
            return SOCKERR_INVALID;

        try
        {
            _socket.Bind(endpoint);
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

    public int SocketConnect(EndPoint? address)
    {
        if (_socket is null || address is null)
            return SOCKERR_INVALID;

        try
        {
            _socket.Connect(address);
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

    public int SocketListen(int backlog)
    {
        if (_socket is null)
            return SOCKERR_INVALID;

        try
        {
            _socket.Listen(backlog);
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

    /*
    private Socket? _socketAccept(out IPEndPoint? address)
    {
        address = null;

        if (_socket is null || _socket.SocketType != SocketType.Stream || _socket.AddressFamily != AddressFamily.InterNetwork)
            return null;

        try
        {
            Socket incoming = _socket.Accept();
            incoming.Blocking = false;

            address = incoming.RemoteEndPoint as IPEndPoint;

            Socket? result = _socketOpen(
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
    */

    public int SocketSendto(byte[] buffer, int length, int flags, EndPoint? address)
    {
        if (_socket is null)
            return SOCKERR_INVALID;

        if (buffer is null || length < 0 || length > buffer.Length)
            return SOCKERR_INVALID;

        //Tools.NetPrintf($"Sending {length} bytes to socket:");
        //Tools.PrintBuffer(buffer.Take(length).ToArray());

        try
        {
            int result = address is null
                ? _socket.Send(buffer, 0, length, (SocketFlags)flags)
                : _socket.SendTo(buffer, 0, length, (SocketFlags)flags, address);

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

    public int SocketSend(byte[] buffer, int length, int flags)
    {
        return SocketSendto(buffer, length, flags, null);
    }

    public int SocketRecvfrom(byte[] buffer, int length, int flags, EndPoint? from)
    {
        if (_socket == null)
            return SOCKERR_INVALID;

        if (buffer is null || length < 0 || length > buffer.Length)
            return SOCKERR_INVALID;

        int iRecv = -1;
        if (_socket.SocketType == SocketType.Stream)
        {
            iRecv = _SocketRecvfrom(_socket, buffer, length, from);
            if (iRecv < 0 && iRecv != unchecked((int)0x80010223))//or again
                Tools.NetPrintf($"dirtynetps3: _SocketRecvfrom() failed (err={iRecv})\n\n");
        }

        return iRecv == 0 ? SOCKERR_CLOSED : iRecv;
    }

    public int SocketRecv(byte[] buffer, int length, int flags)
    {
        return SocketRecvfrom(buffer, length, flags, null);
    }

    public int SocketInfo(int info, int data, IntPtr buffer, int length)
    {
        if (buffer != IntPtr.Zero && length > 0)
        {
            for (int i = 0; i < length; i++)
                Marshal.WriteByte(buffer, i, 0);
        }

        if (_socket is null)
            return -2;

        if (info == Tools.FourCC("stat"))
        {
            int opened = 0;
            try
            {
                if (_socket.Poll(0, SelectMode.SelectWrite) || _socket.Poll(0, SelectMode.SelectError))
                {
                    int error = (int)_socket.GetSocketOption(
                        SocketOptionLevel.Socket,
                        SocketOptionName.Error)!;

                    opened = error == 0 ? 1 : -1;
                }

                if (opened > 0)
                {
                    try
                    {
                        if (_socket.RemoteEndPoint is null)
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

    public static int SocketControl(int option, int data1, IntPtr data2, IntPtr data3)
    {
        if (option == Tools.FourCC("pool"))
            return 0;
        return -1;
    }

    public static HostentT? SocketLookup(string text, int timeout)
    {
        if (timeout < 0)
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
            IPAddress[] addresses = _getHostByNameWrapper(host.Name);
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

    private static IPAddress[] _getHostByNameWrapper(string name)
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
