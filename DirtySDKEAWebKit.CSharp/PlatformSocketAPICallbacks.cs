using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DirtySDKEAWebKit
{
    public sealed class PlatformSocketAPICallbacks
    {
        private static readonly bool Windows = OperatingSystem.IsWindows();
        private const int FIONBIO = unchecked((int)0x8004667E);
        private const int O_NONBLOCK = 0x800;
        private const int F_GETFL = 3;
        private const int F_SETFL = 4;

        public int SO_NBIO { get; }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int AcceptDelegate(int fd, IntPtr addr, ref int len);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int BindDelegate(int fd, IntPtr addr, int len);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ConnectDelegate(int fd, IntPtr addr, int len);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr GetHostByAddrDelegate(IntPtr addr, int len, int type);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public delegate IntPtr GetHostByNameDelegate(string name);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public delegate int DnsLookupDelegate(string hostname, IntPtr unk, IntPtr unkSema, IntPtr unkAddr);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int GetPeerNameDelegate(int fd, IntPtr addr, ref int len);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int GetSockOptDelegate(int fd, int level, int opt, IntPtr value, ref int len);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ListenDelegate(int fd, int backlog);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate nint RecvDelegate(int fd, IntPtr buf, nuint len, int flags);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate nint RecvFromDelegate(int fd, IntPtr buf, nuint len, int flags, IntPtr addr, ref int addrLen);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate nint SendDelegate(int fd, IntPtr buf, nuint len, int flags);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate nint SendToDelegate(int fd, IntPtr buf, nuint len, int flags, IntPtr addr, int addrLen);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int SetSockOptDelegate(int fd, int level, int opt, IntPtr value, int len);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ShutdownDelegate(int fd, int how);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int SocketDelegate(int domain, int type, int protocol);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int CloseDelegate(int fd);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int PollDelegate(IntPtr fds, nuint count, int timeout);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int GetLastErrorDelegate(int code);

        public AcceptDelegate accept = NativeAccept;
        public BindDelegate bind = NativeBind;
        public ConnectDelegate connect = NativeConnect;
        public GetHostByAddrDelegate gethostbyaddr = NativeGetHostByAddr;
        public GetHostByNameDelegate gethostbyname;
        public DnsLookupDelegate dnslookup = DnsLookup;
        public GetPeerNameDelegate getpeername = NativeGetPeerName;
        public GetSockOptDelegate getsockopt = NativeGetSockOpt;
        public ListenDelegate listen = NativeListen;
        public RecvDelegate recv = RecvWrapper;
        public RecvFromDelegate recvfrom = NativeRecvFrom;
        public SendDelegate send = SendWrapper;
        public SendToDelegate sendto = NativeSendTo;
        public SetSockOptDelegate setsockopt;
        public ShutdownDelegate shutdown = NativeShutdown;
        public SocketDelegate socket = NativeSocket;
        public CloseDelegate close;
        public PollDelegate poll;
        public GetLastErrorDelegate getlasterror = GetLastError;

        public PlatformSocketAPICallbacks(int soNbio)
        {
            SO_NBIO = soNbio;
            gethostbyname = GetHostByNameWrapper;
            setsockopt = SetSockOptWrapper;

            if (Windows)
            {
                close = WinClose;
                poll = NativePollWindows;
            }
            else if (OperatingSystem.IsLinux())
            {
                close = UnixClose;
                poll = NativePollLinux;
            }
            else
            {
                throw new PlatformNotSupportedException();
            }
        }

        public static int GetLastError(int code)
        {
            if (code >= 0)
                return code;

            int err = Windows ? WSAGetLastError() : Marshal.GetLastPInvokeError();

            return err switch
            {
                10035 or 997 => 0,
                10051 or 10065 => -5,
                10057 => -2,
                10061 => -6,
                10022 => -11,
                _ => err != 10054 ? -7 : -13
            };
        }

        public static int DnsLookup(string hostname, IntPtr unk, IntPtr unkSema, IntPtr unkAddr)
        {
            Console.WriteLine("dnslookup() is not implemented! Exiting.");
            Environment.Exit(-1);
            return -1;
        }

        public int SetSockOptWrapper(int fd, int level, int opt, IntPtr value, int len)
        {
            if (opt == SO_NBIO)
            {
                if (Windows)
                {
                    uint mode = 1;
                    return IoctlSocket(fd, FIONBIO, ref mode) == 0 ? 0 : -1;
                }

                int flags = Fcntl(fd, F_GETFL, 0);
                if (flags < 0)
                    return -1;

                return Fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ? -1 : 0;
            }

            return NativeSetSockOpt(fd, level, opt, value, len);
        }

        public static nint SendWrapper(int fd, IntPtr buf, nuint len, int flags)
        {
            Debug.WriteLine($"Sending {len} bytes to socket 0x{fd:X}:");
            DebugBuffer(buf, len);
            return NativeSend(fd, buf, len, flags);
        }

        public static nint RecvWrapper(int fd, IntPtr buf, nuint len, int flags)
        {
            nint size = NativeRecv(fd, buf, len, flags);
            Debug.WriteLine($"Received {size} bytes from socket 0x{fd:X}:");
            DebugBuffer(buf, size > 0 ? (nuint)size : 0);
            return size;
        }

        public static IntPtr GetHostByNameWrapper(string name)
        {
            string res = name;

            if (Matches(name, "servserv.generals.ea.com", "na.llnet.eadownloads.ea.com"))
                res = "http.server.cnc-online.net";
            else if (Matches(name, "bfme.fesl.ea.com", "bfme2.fesl.ea.com",
                "bfme2-ep1-pc.fesl.ea.com", "cnc3-pc.fesl.ea.com",
                "cnc3-ep1-pc.fesl.ea.com", "cncra3-pc.fesl.ea.com"))
                res = "login.server.cnc-online.net";
            else if (Matches(name, "gpcm.gamespy.com"))
                res = "gpcm.server.cnc-online.net";
            else if (Matches(name, "peerchat.gamespy.com"))
                res = "peerchat.server.cnc-online.net";
            else if (Matches(name, "lotrbme.available.gamespy.com", "lotrbme.master.gamespy.com",
                "lotrbme.ms13.gamespy.com", "lotrbme2r.available.gamespy.com",
                "lotrbme2r.master.gamespy.com", "lotrbme2r.ms9.gamespy.com",
                "ccgenerals.ms19.gamespy.com", "ccgenzh.ms6.gamespy.com",
                "cc3tibwars.available.gamespy.com", "cc3tibwars.master.gamespy.com",
                "cc3tibwars.ms17.gamespy.com", "cc3xp1.available.gamespy.com",
                "cc3xp1.master.gamespy.com", "cc3xp1.ms18.gamespy.com",
                "redalert3pc.available.gamespy.com", "redalert3pc.master.gamespy.com",
                "redalert3pc.ms1.gamespy.com", "master.gamespy.com"))
                res = "master.server.cnc-online.net";
            else if (Matches(name, "redalert3pc.natneg1.gamespy.com",
                "redalert3pc.natneg2.gamespy.com", "redalert3pc.natneg3.gamespy.com"))
                res = "natneg.server.cnc-online.net";
            else if (Matches(name, "lotrbme.gamestats.gamespy.com",
                "lotrbme2r.gamestats.gamespy.com", "gamestats.gamespy.com"))
                res = "gamestats.server.cnc-online.net";
            else if (Matches(name, "lotrbfme.arenasdk.gamespy.com",
                "arenasdk.gamespy.com", "launch.gamespyarcade.com",
                "www.gamespy.com", "ingamead.gamespy.com"))
                res = "server.cnc-online.net";

            if (res != name)
                Debug.WriteLine($"Changed host \"{name}\" to \"{res}\"");

            return NativeGetHostByName(res);
        }

        private static int NativePollWindows(IntPtr fds, nuint count, int timeout)
            => WinPoll(fds, checked((uint)count), timeout);

        private static int NativePollLinux(IntPtr fds, nuint count, int timeout)
            => UnixPoll(fds, count, timeout);

        private static bool Matches(string name, params string[] values)
        {
            foreach (string value in values)
                if (string.Equals(name, value, StringComparison.Ordinal))
                    return true;
            return false;
        }

        private static void DebugBuffer(IntPtr buf, nuint len)
        {
            if (buf == IntPtr.Zero || len == 0)
                return;
        }

        private static int NativeAccept(int fd, IntPtr a, ref int l) => Windows ? WinAccept(fd, a, ref l) : UnixAccept(fd, a, ref l);
        private static int NativeBind(int fd, IntPtr a, int l) => Windows ? WinBind(fd, a, l) : UnixBind(fd, a, l);
        private static int NativeConnect(int fd, IntPtr a, int l) => Windows ? WinConnect(fd, a, l) : UnixConnect(fd, a, l);
        private static IntPtr NativeGetHostByAddr(IntPtr a, int l, int t) => Windows ? WinGetHostByAddr(a, l, t) : UnixGetHostByAddr(a, l, t);
        private static IntPtr NativeGetHostByName(string n) => Windows ? WinGetHostByName(n) : UnixGetHostByName(n);
        private static int NativeGetPeerName(int fd, IntPtr a, ref int l) => Windows ? WinGetPeerName(fd, a, ref l) : UnixGetPeerName(fd, a, ref l);
        private static int NativeGetSockOpt(int fd, int l, int o, IntPtr v, ref int n) => Windows ? WinGetSockOpt(fd, l, o, v, ref n) : UnixGetSockOpt(fd, l, o, v, ref n);
        private static int NativeListen(int fd, int b) => Windows ? WinListen(fd, b) : UnixListen(fd, b);
        private static nint NativeRecv(int fd, IntPtr b, nuint n, int f) => Windows ? WinRecv(fd, b, checked((int)n), f) : UnixRecv(fd, b, n, f);
        private static nint NativeRecvFrom(int fd, IntPtr b, nuint n, int f, IntPtr a, ref int l) => Windows ? WinRecvFrom(fd, b, checked((int)n), f, a, ref l) : UnixRecvFrom(fd, b, n, f, a, ref l);
        private static nint NativeSend(int fd, IntPtr b, nuint n, int f) => Windows ? WinSend(fd, b, checked((int)n), f) : UnixSend(fd, b, n, f);
        private static nint NativeSendTo(int fd, IntPtr b, nuint n, int f, IntPtr a, int l) => Windows ? WinSendTo(fd, b, checked((int)n), f, a, l) : UnixSendTo(fd, b, n, f, a, l);
        private static int NativeSetSockOpt(int fd, int l, int o, IntPtr v, int n) => Windows ? WinSetSockOpt(fd, l, o, v, n) : UnixSetSockOpt(fd, l, o, v, n);
        private static int NativeShutdown(int fd, int h) => Windows ? WinShutdown(fd, h) : UnixShutdown(fd, h);
        private static int NativeSocket(int d, int t, int p) => Windows ? WinSocket(d, t, p) : UnixSocket(d, t, p);
        private static int IoctlSocket(int fd, int cmd, ref uint mode) => WinIoctlSocket(fd, cmd, ref mode);
        private static int Fcntl(int fd, int cmd, int val) => UnixFcntl(fd, cmd, val);
        private static int WSAGetLastError() => WinWSAGetLastError();

        private const string Ws2 = "ws2_32.dll";
        private const string LibC = "libc";

        [DllImport(Ws2, EntryPoint = "accept")] private static extern int WinAccept(int fd, IntPtr a, ref int l);
        [DllImport(Ws2, EntryPoint = "bind")] private static extern int WinBind(int fd, IntPtr a, int l);
        [DllImport(Ws2, EntryPoint = "connect")] private static extern int WinConnect(int fd, IntPtr a, int l);
        [DllImport(Ws2, EntryPoint = "gethostbyaddr")] private static extern IntPtr WinGetHostByAddr(IntPtr a, int l, int t);
        [DllImport(Ws2, EntryPoint = "gethostbyname", CharSet = CharSet.Ansi)] private static extern IntPtr WinGetHostByName(string n);
        [DllImport(Ws2, EntryPoint = "getpeername")] private static extern int WinGetPeerName(int fd, IntPtr a, ref int l);
        [DllImport(Ws2, EntryPoint = "getsockopt")] private static extern int WinGetSockOpt(int fd, int l, int o, IntPtr v, ref int n);
        [DllImport(Ws2, EntryPoint = "listen")] private static extern int WinListen(int fd, int b);
        [DllImport(Ws2, EntryPoint = "recv")] private static extern int WinRecv(int fd, IntPtr b, int n, int f);
        [DllImport(Ws2, EntryPoint = "recvfrom")] private static extern int WinRecvFrom(int fd, IntPtr b, int n, int f, IntPtr a, ref int l);
        [DllImport(Ws2, EntryPoint = "send")] private static extern int WinSend(int fd, IntPtr b, int n, int f);
        [DllImport(Ws2, EntryPoint = "sendto")] private static extern int WinSendTo(int fd, IntPtr b, int n, int f, IntPtr a, int l);
        [DllImport(Ws2, EntryPoint = "setsockopt")] private static extern int WinSetSockOpt(int fd, int l, int o, IntPtr v, int n);
        [DllImport(Ws2, EntryPoint = "shutdown")] private static extern int WinShutdown(int fd, int h);
        [DllImport(Ws2, EntryPoint = "socket")] private static extern int WinSocket(int d, int t, int p);
        [DllImport(Ws2, EntryPoint = "closesocket")] private static extern int WinClose(int fd);
        [DllImport(Ws2, EntryPoint = "WSAPoll")] private static extern int WinPoll(IntPtr fds, uint n, int t);
        [DllImport(Ws2, EntryPoint = "ioctlsocket")] private static extern int WinIoctlSocket(int fd, int cmd, ref uint mode);
        [DllImport(Ws2, EntryPoint = "WSAGetLastError")] private static extern int WinWSAGetLastError();

        [DllImport(LibC, EntryPoint = "accept")] private static extern int UnixAccept(int fd, IntPtr a, ref int l);
        [DllImport(LibC, EntryPoint = "bind")] private static extern int UnixBind(int fd, IntPtr a, int l);
        [DllImport(LibC, EntryPoint = "connect")] private static extern int UnixConnect(int fd, IntPtr a, int l);
        [DllImport(LibC, EntryPoint = "gethostbyaddr")] private static extern IntPtr UnixGetHostByAddr(IntPtr a, int l, int t);
        [DllImport(LibC, EntryPoint = "gethostbyname", CharSet = CharSet.Ansi)] private static extern IntPtr UnixGetHostByName(string n);
        [DllImport(LibC, EntryPoint = "getpeername")] private static extern int UnixGetPeerName(int fd, IntPtr a, ref int l);
        [DllImport(LibC, EntryPoint = "getsockopt")] private static extern int UnixGetSockOpt(int fd, int l, int o, IntPtr v, ref int n);
        [DllImport(LibC, EntryPoint = "listen")] private static extern int UnixListen(int fd, int b);
        [DllImport(LibC, EntryPoint = "recv")] private static extern nint UnixRecv(int fd, IntPtr b, nuint n, int f);
        [DllImport(LibC, EntryPoint = "recvfrom")] private static extern nint UnixRecvFrom(int fd, IntPtr b, nuint n, int f, IntPtr a, ref int l);
        [DllImport(LibC, EntryPoint = "send")] private static extern nint UnixSend(int fd, IntPtr b, nuint n, int f);
        [DllImport(LibC, EntryPoint = "sendto")] private static extern nint UnixSendTo(int fd, IntPtr b, nuint n, int f, IntPtr a, int l);
        [DllImport(LibC, EntryPoint = "setsockopt")] private static extern int UnixSetSockOpt(int fd, int l, int o, IntPtr v, int n);
        [DllImport(LibC, EntryPoint = "shutdown")] private static extern int UnixShutdown(int fd, int h);
        [DllImport(LibC, EntryPoint = "socket")] private static extern int UnixSocket(int d, int t, int p);
        [DllImport(LibC, EntryPoint = "close")] private static extern int UnixClose(int fd);
        [DllImport(LibC, EntryPoint = "poll")] private static extern int UnixPoll(IntPtr fds, nuint n, int t);
        [DllImport(LibC, EntryPoint = "fcntl")] private static extern int UnixFcntl(int fd, int cmd, int val);
    }
}
