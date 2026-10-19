
using System;

namespace DirtySDKEAWebKit
{
    public sealed class CryptMD5T
    {
        public readonly byte[] strData = new byte[64 + 8];
        public uint uCount;
        public readonly uint[] uRegs = new uint[4];
    }

    public static class CryptMD5
    {
        public const int MD5_BINARY_OUT = 16;
        public const int MD5_STRING_OUT = 33;
        private const uint A0 = 0x67452301;
        private const uint B0 = 0xefcdab89;
        private const uint C0 = 0x98badcfe;
        private const uint D0 = 0x10325476;
        private static readonly char[] MD5_HexChars = "0123456789abcdef".ToCharArray();
        private static readonly int[] Shift =
        {
            7, 12, 17, 22, 7, 12, 17, 22,
            7, 12, 17, 22, 7, 12, 17, 22,

            5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20,

            4, 11, 16, 23, 4, 11, 16, 23,
            4, 11, 16, 23, 4, 11, 16, 23,

            6, 10, 15, 21, 6, 10, 15, 21,
            6, 10, 15, 21, 6, 10, 15, 21
        };
        private static readonly uint[] K =
        {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };

        private static uint RotateLeft(uint value, int bits)
        {
            return (value << bits) | (value >> (32 - bits));
        }

        public static void CryptMD5Init(CryptMD5T pContext)
        {
            ArgumentNullException.ThrowIfNull(pContext);

            pContext.uCount = 0;

            pContext.uRegs[0] = A0;
            pContext.uRegs[1] = B0;
            pContext.uRegs[2] = C0;
            pContext.uRegs[3] = D0;
        }

        public static void CryptMD5Update(CryptMD5T pContext, byte[] pBuffer, int iLength)
        {
            ArgumentNullException.ThrowIfNull(pContext);
            ArgumentNullException.ThrowIfNull(pBuffer);

            if (iLength < 0)
            {
                iLength = 0;

                while (iLength < pBuffer.Length &&
                    pBuffer[iLength] != 0)
                {
                    iLength++;
                }

                if (iLength == pBuffer.Length)
                {
                    throw new ArgumentException(
                        "Не найден завершающий нулевой байт.",
                        nameof(pBuffer));
                }
            }

            if (iLength > pBuffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(iLength));
            }

            if (iLength == 0)
                return;

            uint uCount = pContext.uCount & 63;

            unchecked
            {
                pContext.uCount += (uint)iLength;
            }

            int offset = 0;

            if (uCount > 0)
            {
                int uAdd = 64 - (int)uCount;

                if (iLength < uAdd)
                {
                    Array.Copy(
                        pBuffer, offset,
                        pContext.strData, (int)uCount,
                        iLength);

                    return;
                }

                Array.Copy(
                    pBuffer, offset,
                    pContext.strData, (int)uCount,
                    uAdd);

                offset += uAdd;
                iLength -= uAdd;

                CryptMD5Transform(pContext, pContext.strData, 0);
            }

            while (iLength >= 64)
            {
                CryptMD5Transform(pContext, pBuffer, offset);

                offset += 64;
                iLength -= 64;
            }

            if (iLength > 0)
            {
                Array.Copy(
                    pBuffer, offset,
                    pContext.strData, 0,
                    iLength);
            }
        }

        private static void CryptMD5Transform(CryptMD5T pContext, byte[] pBlock, int offset)
        {
            Span<uint> words = stackalloc uint[16];

            for (int i = 0; i < 16; i++)
            {
                int j = offset + i * 4;

                words[i] =
                    (uint)pBlock[j] |
                    ((uint)pBlock[j + 1] << 8) |
                    ((uint)pBlock[j + 2] << 16) |
                    ((uint)pBlock[j + 3] << 24);
            }

            uint a = pContext.uRegs[0];
            uint b = pContext.uRegs[1];
            uint c = pContext.uRegs[2];
            uint d = pContext.uRegs[3];

            unchecked
            {
                for (int i = 0; i < 64; i++)
                {
                    uint f;
                    int g;

                    if (i < 16)
                    {
                        // FF(b, c, d)
                        f = d ^ (b & (c ^ d));
                        g = i;
                    }
                    else if (i < 32)
                    {
                        // GG(b, c, d)
                        f = c ^ (d & (b ^ c));
                        g = (5 * i + 1) & 15;
                    }
                    else if (i < 48)
                    {
                        // HH(b, c, d)
                        f = b ^ c ^ d;
                        g = (3 * i + 5) & 15;
                    }
                    else
                    {
                        // II(b, c, d)
                        f = c ^ (b | ~d);
                        g = (7 * i) & 15;
                    }

                    uint temp = d;
                    d = c;
                    c = b;

                    uint sum = a + f + K[i] + words[g];
                    b = b + RotateLeft(sum, Shift[i]);

                    a = temp;
                }

                pContext.uRegs[0] += a;
                pContext.uRegs[1] += b;
                pContext.uRegs[2] += c;
                pContext.uRegs[3] += d;
            }
        }

        public static void CryptMD5Final(CryptMD5T pContext, byte[] pBuffer, int iLength)
        {
            ArgumentNullException.ThrowIfNull(pContext);
            ArgumentNullException.ThrowIfNull(pBuffer);

            int uIndex = (int)(pContext.uCount & 63);

            pContext.strData[uIndex++] = 0x80;

            if (uIndex > 56)
            {
                for (int i = 0; i < 8; i++)
                {
                    pContext.strData[uIndex + i] = 0;
                }

                CryptMD5Transform(pContext, pContext.strData, 0);
                uIndex = 0;
            }

            pContext.strData[uIndex + 0] = 0;
            pContext.strData[uIndex + 1] = 0;
            pContext.strData[uIndex + 2] = 0;

            int uZero = (uIndex + 3) >> 2;
            int zeroOffset = uZero * 4;

            Array.Clear(
                pContext.strData,
                zeroOffset,
                64 - zeroOffset);

            unchecked
            {
                uint count = pContext.uCount;

                pContext.strData[56] = (byte)(count << 3);
                pContext.strData[57] = (byte)(count >> 5);
                pContext.strData[58] = (byte)(count >> 13);
                pContext.strData[59] = (byte)(count >> 21);
                pContext.strData[60] = (byte)(count >> 29);
            }

            CryptMD5Transform(pContext, pContext.strData, 0);

            if (OperatingSystem.IsLinux())
            {
                if (iLength == MD5_BINARY_OUT / 2)
                {
                    EnsureOutputLength(pBuffer, iLength);
                    WriteBinary(pContext, pBuffer, 8);
                    return;
                }

                if (iLength == MD5_BINARY_OUT)
                {
                    EnsureOutputLength(pBuffer, iLength);
                    WriteBinary(pContext, pBuffer, 16);
                    return;
                }
            }

            int outputIndex = 0;
            uint uData = 0;

            EnsureOutputLength(
                pBuffer,
                iLength >= MD5_STRING_OUT
                    ? MD5_STRING_OUT
                    : Math.Max(0, Math.Min(iLength, 16)));

            for (uIndex = 0; uIndex < 16; uIndex++)
            {
                if ((uIndex & 3) == 0)
                {
                    uData = pContext.uRegs[uIndex >> 2];
                }

                if (iLength >= MD5_STRING_OUT)
                {
                    pBuffer[outputIndex++] =
                        (byte)MD5_HexChars[(uData >> 4) & 15];

                    pBuffer[outputIndex++] =
                        (byte)MD5_HexChars[uData & 15];
                }
                else if (uIndex < iLength)
                {
                    pBuffer[outputIndex++] = (byte)uData;
                }

                uData >>= 8;
            }

            if (iLength >= MD5_STRING_OUT)
            {
                pBuffer[outputIndex] = 0;
            }
        }

        private static void WriteBinary(CryptMD5T pContext, byte[] output, int count)
        {
            int index = 0;

            for (int i = 0; i < 4 && index < count; i++)
            {
                uint value = pContext.uRegs[i];

                for (int j = 0; j < 4 && index < count; j++)
                {
                    output[index++] = (byte)value;
                    value >>= 8;
                }
            }
        }

        private static void EnsureOutputLength(byte[] buffer, int requiredLength)
        {
            if (requiredLength < 0 || buffer.Length < requiredLength)
            {
                throw new ArgumentException(
                    "Insufficient output buffer size",
                    nameof(buffer));
            }
        }
    }
}