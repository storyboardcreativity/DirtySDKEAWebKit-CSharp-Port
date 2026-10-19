using System;

namespace DirtySDKEAWebKit
{
    public sealed class DirtySockAddress
    {
        public ushort Family { get; set; }
        public byte[] SaData { get; } = new byte[14];
        public DirtySockAddress() {}
        public DirtySockAddress(ushort family)
        {
            DirtyNet.SockaddrInit(this, family);
        }
    }

    public static class DirtyNet
    {
        public const ushort AF_INET = 2;

        public static void SockaddrInit(DirtySockAddress addr, ushort family)
        {
            ArgumentNullException.ThrowIfNull(addr);
            addr.Family = family;
            Array.Clear(addr.SaData, 0, addr.SaData.Length);
        }

        public static ushort SockaddrInGetPort(DirtySockAddress addr)
        {
            return (ushort)(((uint)addr.SaData[0] << 8) | addr.SaData[1]);
        }

        public static void SockaddrInSetPort(DirtySockAddress addr, int value)
        {
            uint val = unchecked((uint)value);
            addr.SaData[0] = (byte)(val >> 8);
            addr.SaData[1] = (byte)val;
        }

        public static uint SockaddrInGetAddr(DirtySockAddress addr)
        {
            return ((uint)addr.SaData[2] << 24)
                 | ((uint)addr.SaData[3] << 16)
                 | ((uint)addr.SaData[4] << 8)
                 | addr.SaData[5];
        }

        public static void SockaddrInSetAddr(DirtySockAddress addr, uint value)
        {
            addr.SaData[5] = (byte)value;
            value >>= 8;
            addr.SaData[4] = (byte)value;
            value >>= 8;
            addr.SaData[3] = (byte)value;
            value >>= 8;
            addr.SaData[2] = (byte)value;
        }

        public static uint SockaddrInGetMisc(DirtySockAddress addr)
        {
            return ((uint)addr.SaData[6] << 24)
                 | ((uint)addr.SaData[7] << 16)
                 | ((uint)addr.SaData[8] << 8)
                 | addr.SaData[9];
        }

        public static void SockaddrInSetMisc(DirtySockAddress addr, uint value)
        {
            addr.SaData[9] = (byte)value;
            value >>= 8;
            addr.SaData[8] = (byte)value;
            value >>= 8;
            addr.SaData[7] = (byte)value;
            value >>= 8;
            addr.SaData[6] = (byte)value;
        }

        public static bool SockaddrIsLoopback(DirtySockAddress addr)
        {
            return addr.Family == AF_INET
                && addr.SaData[0] == 127
                && addr.SaData[1] == 0
                && addr.SaData[2] == 0
                && addr.SaData[3] == 1;
        }

        public static int SockaddrCompare(DirtySockAddress addr1, DirtySockAddress addr2)
        {
            if (addr1.Family != addr2.Family)
                return (int)addr1.Family - addr2.Family;

            int len = addr1.Family == AF_INET ? 6 : 14;

            for (int i = 0; i < len; i++)
            {
                int diff = addr1.SaData[i] - addr2.SaData[i];
                if (diff != 0)
                    return diff;
            }

            return 0;
        }

        public static int SockaddrInSetAddrText(DirtySockAddress addr, string text)
        {
            text = CString(text);

            int pos = 0;

            for (int i = 0; i < 4; ++i)
            {
                addr.SaData[2 + i] = 0;

                while (pos < text.Length &&
                       text[pos] >= '0' && text[pos] <= '9')
                {
                    addr.SaData[2 + i] = unchecked(
                        (byte)(addr.SaData[2 + i] * 10 + (text[pos] & 15)));
                    pos++;
                }

                if (i < 3)
                {
                    if (pos >= text.Length || text[pos] != '.')
                    {
                        addr.SaData[2] = 0;
                        addr.SaData[3] = 0;
                        addr.SaData[4] = 0;
                        addr.SaData[5] = 0;
                        return -1;
                    }

                    pos++;
                }
            }

            return 0;
        }

        public static char[]? SockaddrInGetAddrText(DirtySockAddress addr, char[] buffer, int len)
        {
            if (len <= 0)
                return null;

            if (len < 16)
            {
                if (buffer.Length > 0)
                    buffer[0] = '\0';
                return null;
            }

            if (buffer.Length < len)
                throw new ArgumentException("Buffer is smaller than len.");

            int pos = 0;

            for (int i = 2; i < 6; ++i)
            {
                int val = addr.SaData[i];

                if (val > 99)
                {
                    buffer[pos++] = (char)('0' + val / 100);
                    val %= 100;
                    buffer[pos++] = (char)('0' + val / 10);
                    val %= 10;
                }

                if (val > 9)
                {
                    buffer[pos++] = (char)('0' + val / 10);
                    val %= 10;
                }

                buffer[pos++] = (char)('0' + val);

                if (i < 5)
                    buffer[pos++] = '.';
            }

            buffer[pos] = '\0';
            return buffer;
        }

        public static string? SockaddrInGetAddrText(DirtySockAddress addr, int len = 16)
        {
            if (len <= 0)
                return null;

            char[] buffer = new char[len];

            if (SockaddrInGetAddrText(addr, buffer, len) == null)
                return null;

            int end = Array.IndexOf(buffer, '\0');
            return new string(buffer, 0, end < 0 ? buffer.Length : end);
        }

        public static ushort SocketHtons(ushort addr)
        {
            if (BitConverter.IsLittleEndian)
                return (ushort)((addr << 8) | (addr >> 8));
            return addr;
        }

        public static uint SocketHtonl(uint addr)
        {
            if (BitConverter.IsLittleEndian)
                return ((addr & 0x000000FFU) << 24)
                    | ((addr & 0x0000FF00U) << 8)
                    | ((addr & 0x00FF0000U) >> 8)
                    | ((addr & 0xFF000000U) >> 24);
            return addr;
        }

        public static ushort SocketNtohs(ushort addr)
        {
            return SocketHtons(addr);
        }

        public static uint SocketNtohl(uint addr)
        {
            return SocketHtonl(addr);
        }

        public static string SocketInAddrGetText(int addr)
        {
            var sa = new DirtySockAddress();
            SockaddrInSetAddr(sa, unchecked((uint)addr));
            return SockaddrInGetAddrText(sa, 20) ?? string.Empty;
        }

        public static char[]? SocketInAddrGetText2(uint addr, char[] buffer, int len)
        {
            var sa = new DirtySockAddress();
            SockaddrInSetAddr(sa, addr);
            return SockaddrInGetAddrText(sa, buffer, len);
        }

        public static int SocketInTextGetAddr(string addrText)
        {
            var sa = new DirtySockAddress();

            if (SockaddrInSetAddrText(sa, addrText) == 0)
                return unchecked((int)SockaddrInGetAddr(sa));

            return 0;
        }

        public static int SockaddrInParse(DirtySockAddress sa, string parse)
        {
            parse = CString(parse);

            SockaddrInit(sa, AF_INET);

            int result = SockaddrInParse2(out uint addr, out int port, out _, parse, false);

            SockaddrInSetAddr(sa, addr);
            SockaddrInSetPort(sa, port);

            return result;
        }

        public static int SockaddrInParse2(out uint address, out int port, out int? port2, string parse, bool parsePort2 = true)
        {
            int result = 0;
            int pos = 0;

            while (pos < parse.Length &&
                   parse[pos] > '\0' && parse[pos] <= ' ')
                pos++;

            uint value = 0;

            while (pos < parse.Length &&
                   ((parse[pos] >= '0' && parse[pos] <= '9') ||
                    parse[pos] == '.'))
            {
                char ch = parse[pos++];

                if (ch != '.')
                {
                    unchecked
                    {
                        value = (value - (value & 255))
                              + ((value & 255) * 10)
                              + (uint)(ch & 15);
                    }
                }
                else
                {
                    value = unchecked(value << 8);
                }
            }

            address = value;

            if (address != 0)
                result |= 1;

            while (pos < parse.Length && parse[pos] != ':')
                pos++;

            value = 0;

            if (pos < parse.Length && parse[pos] == ':')
            {
                pos++;

                while (pos < parse.Length &&
                       parse[pos] >= '0' && parse[pos] <= '9')
                {
                    unchecked
                    {
                        value = value * 10 + (uint)(parse[pos] & 15);
                    }

                    pos++;
                }

                result |= 2;
            }

            port = unchecked((int)value);
            port2 = null;

            if (parsePort2)
            {
                value = 0;

                if (pos < parse.Length && parse[pos] == ':')
                {
                    pos++;

                    while (pos < parse.Length &&
                           parse[pos] >= '0' && parse[pos] <= '9')
                    {
                        unchecked
                        {
                            value = value * 10 + (uint)(parse[pos] & 15);
                        }

                        pos++;
                    }

                    result |= 4;
                }

                port2 = unchecked((int)value);
            }

            return result;
        }

        private static string CString(string value)
        {
            ArgumentNullException.ThrowIfNull(value);

            int end = value.IndexOf('\0');
            return end >= 0 ? value.Substring(0, end) : value;
        }
    }
}