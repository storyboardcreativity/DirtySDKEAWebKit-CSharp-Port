
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace DirtySDKEAWebKit
{
    public sealed class EnctypeX
    {
        public sealed class DataState
        {
            public readonly byte[] EncXKey = new byte[261];
            public int Offset;
            public int Start;
        }

        private int cleanerLevel = 2;

        public int CleanerLevel
        {
            get => cleanerLevel;
            set => cleanerLevel = value;
        }

        private static readonly byte[] StrangeChars =
        {
            32,69,32,44,102,44,46,116,32,94,37,83,60,69,32,90,
            32,32,96,96,34,34,46,45,45,126,96,83,62,101,32,90,
            89,89,105,99,101,111,89,73,83,96,99,97,60,45,45,69,
            45,96,43,50,51,96,117,80,45,44,49,96,62,37,37,37,
            63,65,65,65,65,65,65,65,67,69,69,69,69,73,73,73,
            73,68,78,79,79,79,79,79,120,48,85,85,85,85,89,68,
            66,97,97,97,97,97,97,101,99,101,101,101,101,105,105,105,
            105,111,110,111,111,111,111,111,43,111,117,117,117,117,121,98,
            121
        };

        private static int CStrLen(byte[] data, int offset = 0)
        {
            int i = offset;
            while (i < data.Length && data[i] != 0)
                i++;
            return i - offset;
        }

        private static int CStrLen(byte[] data)
            => CStrLen(data, 0);

        private static byte[] AsciiZ(string value)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(value);
            Array.Resize(ref bytes, bytes.Length + 1);
            return bytes;
        }

        private static int WrapByte(int value) => value & 0xff;

        // enctypex_func5
        private static int Func5(
            byte[] key, int cnt, byte[] id, int idlen,
            ref int n1, ref int n2)
        {
            if (cnt == 0)
                return 0;

            int mask = 1;

            if (cnt > 1)
            {
                do
                {
                    mask = unchecked((mask << 1) + 1);
                }
                while (mask < cnt);
            }

            int i = 0;
            int tmp;

            do
            {
                n1 = unchecked(key[n1 & 0xff] + id[n2]);
                n2++;

                if (n2 >= idlen)
                {
                    n2 = 0;
                    n1 = unchecked(n1 + idlen);
                }

                tmp = n1 & mask;

                if (++i > 11)
                    tmp %= cnt;
            }
            while (tmp > cnt);

            return tmp;
        }

        // enctypex_func4
        private static void Func4(byte[] key, byte[] id, int idlen)
        {
            int n1 = 0;
            int n2 = 0;

            if (idlen < 1)
                return;

            for (int i = 0; i < 256; i++)
                key[i] = (byte)i;

            for (int i = 255; i >= 0; i--)
            {
                byte t1 = (byte)Func5(key, i, id, idlen, ref n1, ref n2);
                byte t2 = key[i];
                key[i] = key[t1];
                key[t1] = t2;
            }

            key[256] = key[1];
            key[257] = key[3];
            key[258] = key[5];
            key[259] = key[7];
            key[260] = key[n1 & 0xff];
        }

        // enctypex_func7
        private static byte Func7(byte[] k, byte d)
        {
            byte a, b, c;

            a = k[256];
            b = k[257];
            c = k[a];
            k[256] = unchecked((byte)(a + 1));
            k[257] = unchecked((byte)(b + c));

            a = k[260];
            b = k[257];
            b = k[b];
            c = k[a];
            k[a] = b;

            a = k[259];
            b = k[257];
            a = k[a];
            k[b] = a;

            a = k[256];
            b = k[259];
            a = k[a];
            k[b] = a;

            a = k[256];
            k[a] = c;

            b = k[258];
            a = k[c];
            c = k[259];
            b = unchecked((byte)(b + a));
            k[258] = b;

            a = b;
            c = k[c];
            b = k[257];
            b = k[b];
            a = k[a];
            c = unchecked((byte)(c + b));

            b = k[260];
            b = k[b];
            c = unchecked((byte)(c + b));

            b = k[c];
            c = k[256];
            c = k[c];
            a = unchecked((byte)(a + c));

            c = k[b];
            b = k[a];

            k[260] = d;
            c ^= (byte)(b ^ d);
            k[259] = c;

            return c;
        }

        // enctypex_func7e
        private static byte Func7E(byte[] k, byte d)
        {
            byte a, b, c;

            a = k[256];
            b = k[257];
            c = k[a];
            k[256] = unchecked((byte)(a + 1));
            k[257] = unchecked((byte)(b + c));

            a = k[260];
            b = k[257];
            b = k[b];
            c = k[a];
            k[a] = b;

            a = k[259];
            b = k[257];
            a = k[a];
            k[b] = a;

            a = k[256];
            b = k[259];
            a = k[a];
            k[b] = a;

            a = k[256];
            k[a] = c;

            b = k[258];
            a = k[c];
            c = k[259];
            b = unchecked((byte)(b + a));
            k[258] = b;

            a = b;
            c = k[c];
            b = k[257];
            b = k[b];
            a = k[a];
            c = unchecked((byte)(c + b));

            b = k[260];
            b = k[b];
            c = unchecked((byte)(c + b));

            b = k[c];
            c = k[256];
            c = k[c];
            a = unchecked((byte)(a + c));

            c = k[b];
            b = k[a];

            c ^= (byte)(b ^ d);
            k[260] = c;
            k[259] = d;

            return c;
        }

        // enctypex_func6
        private static int Func6(byte[] key, byte[] data, int offset, int len)
        {
            for (int i = 0; i < len; i++)
                data[offset + i] = Func7(key, data[offset + i]);
            return len;
        }

        // enctypex_func6e
        private static int Func6E(byte[] key, byte[] data, int offset, int len)
        {
            for (int i = 0; i < len; i++)
                data[offset + i] = Func7E(key, data[offset + i]);
            return len;
        }

        // enctypex_funcx
        private static void FuncX(byte[] encxkey, byte[] key, byte[] encxvalidate, byte[] data,  int offset, int datalen)
        {
            int keylen = CStrLen(key);

            if (keylen == 0)
                throw new ArgumentException("Key must not be empty.", nameof(key));

            for (int i = 0; i < datalen; i++)
            {
                int index = (key[i % keylen] * i) & 7;
                encxvalidate[index] ^= (byte)(encxvalidate[i & 7] ^ data[offset + i]);
            }

            Func4(encxkey, encxvalidate, 8);
        }

        // enctypex_data_cleaner
        public int DataCleaner(byte[] dst, byte[] src, int max)
        {
            if (dst == null)
                return 0;

            if (src == null)
            {
                dst[0] = 0;
                return 0;
            }

            if (!ReferenceEquals(dst, src))
                dst[0] = 0;

            if (max < 0)
                max = CStrLen(src);

            int p = 0;
            int s = 0;

            while (s < src.Length && src[s] != 0 && max > 0)
            {
                byte c = src[s];

                if (c == '\\')
                {
                    dst[p++] = (byte)'/';
                    s++;
                    max--;
                    continue;
                }

                if (cleanerLevel >= 1)
                {
                    if (c == '^')
                    {
                        if (s + 1 < src.Length &&
                            (char.IsAsciiDigit((char)src[s + 1]) ||
                            char.IsAsciiLetterLower((char)src[s + 1])))
                        {
                            s++;
                            max--;
                        }
                        else
                        {
                            dst[p++] = c;
                        }

                        s++;
                        max--;
                        continue;
                    }

                    if (c == 0x1b)
                    {
                        s += 4;
                        max -= 4;
                        continue;
                    }

                    if (c < ' ')
                    {
                        s++;
                        max--;
                        continue;
                    }
                }

                if (cleanerLevel >= 2 && c >= 0x7f)
                {
                    int idx = c - 0x7f;
                    c = idx < StrangeChars.Length
                        ? StrangeChars[idx]
                        : (byte)' ';
                }

                if (cleanerLevel >= 3)
                {
                    switch (c)
                    {
                        case (byte)'\'':
                        case (byte)'"':
                        case (byte)'&':
                        case (byte)'^':
                        case (byte)'?':
                        case (byte)'{':
                        case (byte)'}':
                        case (byte)'(':
                        case (byte)')':
                        case (byte)'[':
                        case (byte)']':
                        case (byte)'-':
                        case (byte)';':
                        case (byte)'~':
                        case (byte)'|':
                        case (byte)'$':
                        case (byte)'!':
                        case (byte)'<':
                        case (byte)'>':
                        case (byte)'*':
                        case (byte)'%':
                        case (byte)',':
                            c = (byte)'.';
                            break;
                    }
                }

                if (c != '\r' && c != '\n')
                    dst[p++] = c;

                s++;
                max--;
            }

            dst[p] = 0;
            return p;
        }

        // enctypex_init
        private int Init(byte[] encxkey, byte[] key, byte[] validate, byte[] data, ref int datalen, DataState state)
        {
            if (datalen < 1)
                return -1;

            int a = (data[0] ^ 0xec) + 2;

            if (datalen < a)
                return -1;

            int b = data[a - 1] ^ 0xea;

            if (datalen < a + b)
                return -1;

            byte[] encxvalidate = new byte[8];
            Array.Copy(validate, encxvalidate, 8);

            FuncX(encxkey, key, encxvalidate, data, a, b);

            a += b;

            if (state == null)
            {
                datalen -= a;
                return a;
            }

            state.Offset = a;
            state.Start = a;

            return a;
        }

        // Returns the offset of the first decoded data byte
        public int Decoder(
            byte[] key, byte[] validate, byte[] data,
            ref int datalen, DataState state = null)
        {
            if (key == null || validate == null || data == null)
                return -1;

            byte[] workKey;

            if (state != null && state.Start != 0)
            {
                workKey = state.EncXKey;
            }
            else
            {
                workKey = new byte[261];
                int init = Init(workKey, key, validate, data, ref datalen, state);

                if (init < 0)
                    return -1;

                if (state == null)
                {
                    Func6(workKey, data, init, datalen);
                    return init;
                }
            }

            if (state != null && state.Start != 0)
            {
                int count = datalen - state.Offset;

                if (count < 0)
                    return -1;

                state.Offset += Func6(
                    workKey, data, state.Offset, count);

                return state.Start;
            }

            return -1;
        }

        // Returns the offset of the first encoded data byte
        public int Encoder(
            byte[] key, byte[] validate, byte[] data,
            ref int datalen, DataState state = null)
        {
            if (key == null || validate == null || data == null)
                return -1;

            byte[] workKey;

            if (state != null && state.Start != 0)
            {
                workKey = state.EncXKey;
            }
            else
            {
                workKey = new byte[261];
                int init = Init(workKey, key, validate, data, ref datalen, state);

                if (init < 0)
                    return -1;

                if (state == null)
                {
                    Func6E(workKey, data, init, datalen);
                    return init;
                }
            }

            if (state != null && state.Start != 0)
            {
                int count = datalen - state.Offset;

                if (count < 0)
                    return -1;

                state.Offset += Func6E(
                    workKey, data, state.Offset, count);

                return state.Start;
            }

            return -1;
        }

        // enctypex_wrapper
        public int Wrapper(
            byte[] key, byte[] validate, byte[] data, int size)
        {
            if (key == null || validate == null || data == null || size < 0)
                return 0;

            int len = size;
            int offset = Decoder(key, validate, data, ref len);

            if (offset < 0)
                return -1;

            // The C wrapper copies the decoded payload to data[0]
            Buffer.BlockCopy(data, offset, data, 0, len);
            return len;
        }

        // enctypex_decoder_rand_validate
        public byte[] RandomValidate()
        {
            int rnd = unchecked(~(int)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            byte[] validate = new byte[9];

            for (int i = 0; i < 8; i++)
            {
                do
                {
                    rnd = unchecked(rnd * 0x343FD + 0x269EC3) & 0x7f;
                }
                while (rnd < 0x21 || rnd >= 0x7f);

                validate[i] = (byte)rnd;
            }

            validate[8] = 0;
            return validate;
        }

        // enctypex_msname
        public string MasterServerName(string gameName)
        {
            if (gameName == null)
                return null;

            int serverNum = 0;

            foreach (char ch in gameName)
            {
                int c = char.ToLowerInvariant(ch);
                serverNum = unchecked(c - serverNum * 0x63306ce7);
            }

            serverNum %= 20;

            return $"{gameName}.ms{serverNum}.gamespy.com";
        }

        // enctypex_quick_encrypt
        // The input must have at least size + 23 bytes
        public int QuickEncrypt(
            byte[] key, byte[] validate, byte[] data, int size)
        {
            if (key == null || validate == null || data == null || size < 0)
                return 0;

            int keylen = CStrLen(key);
            int vallen = CStrLen(validate);

            if (keylen == 0 || vallen == 0)
                return 0;

            if (data.Length < size + 23)
                throw new ArgumentException(
                    "Buffer must have at least size + 23 bytes.", nameof(data));

            byte[] tmp = new byte[23];

            int rnd = unchecked(~(int)DateTimeOffset.UtcNow.ToUnixTimeSeconds());

            for (int i = 0; i < tmp.Length; i++)
            {
                rnd = unchecked(rnd * 0x343FD + 0x269EC3);
                tmp[i] = (byte)(rnd ^ key[i % keylen] ^ validate[i % vallen]);
            }

            tmp[0] = 0xeb;
            tmp[1] = 0x00;
            tmp[2] = 0x00;
            tmp[8] = 0xe4;

            Array.Copy(data, 0, data, 23, size);
            Array.Copy(tmp, 0, data, 0, 23);

            int total = size + 23;
            int len = total;

            Encoder(key, validate, data, ref len);

            return total;
        }
    }
}