using System;

namespace DirtySDKEAWebKit
{
    public sealed class CryptSHA1
    {
        public const int HASHSIZE = 160 / 8;
        private const int BLOCK_SIZE = 16 * 4;

        private uint uCount;
        private uint uPartialCount;
        private readonly uint[] H = new uint[5];
        private readonly byte[] strData = new byte[BLOCK_SIZE];

        public CryptSHA1()
        {
            Init();
        }

        public void Init()
        {
            uCount = 0;
            uPartialCount = 0;

            H[0] = 0x67452301;
            H[1] = 0xEFCDAB89;
            H[2] = 0x98BADCFE;
            H[3] = 0x10325476;
            H[4] = 0xC3D2E1F0;
        }

        public void Update(byte[] input, uint inputLength)
        {
            Update(input, 0, inputLength);
        }

        public void Update(byte[] input, int offset, uint inputLength)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            if (offset < 0 || offset > input.Length ||
                inputLength > (uint)(input.Length - offset))
            {
                throw new ArgumentOutOfRangeException(nameof(inputLength));
            }

            unchecked
            {
                if (uPartialCount != 0)
                {
                    uint want = BLOCK_SIZE - uPartialCount;
                    uint have = want > inputLength ? inputLength : want;

                    Array.Copy(
                        input,
                        offset,
                        strData,
                        (int)uPartialCount,
                        (int)have);

                    offset += (int)have;
                    inputLength -= have;

                    if (have == want)
                    {
                        ProcessBlock(strData, 0);
                        uCount += BLOCK_SIZE;
                        uPartialCount = 0;
                    }
                    else
                    {
                        uPartialCount += have;
                    }
                }

                while (inputLength >= BLOCK_SIZE)
                {
                    ProcessBlock(input, offset);

                    uCount += BLOCK_SIZE;
                    inputLength -= BLOCK_SIZE;
                    offset += BLOCK_SIZE;
                }

                if (inputLength != 0)
                {
                    Array.Copy(
                        input,
                        offset,
                        strData,
                        (int)uPartialCount,
                        (int)inputLength);

                    uPartialCount += inputLength;
                }
            }
        }

        public void Final(byte[] output, uint length)
        {
            if (output == null)
                throw new ArgumentNullException(nameof(output));

            if (length > output.Length)
                throw new ArgumentOutOfRangeException(nameof(length));

            unchecked
            {
                uint i;
                byte pad = 0x80;
                uint space = BLOCK_SIZE - uPartialCount;

                uCount += uPartialCount;

                if (space < 9)
                {
                    strData[(int)uPartialCount] = pad;

                    for (i = uPartialCount + 1; i < BLOCK_SIZE; i++)
                    {
                        strData[(int)i] = 0x00;
                    }

                    ProcessBlock(strData, 0);

                    pad = 0x00;
                    uPartialCount = 0;
                }

                strData[(int)uPartialCount] = pad;

                for (i = uPartialCount + 1; i < BLOCK_SIZE - 8; i++)
                {
                    strData[(int)i] = 0x00;
                }

                strData[56] = 0;
                strData[57] = 0;
                strData[58] = 0;
                strData[59] = (byte)(uCount >> 29);
                strData[60] = (byte)(uCount >> 21);
                strData[61] = (byte)(uCount >> 13);
                strData[62] = (byte)(uCount >> 5);
                strData[63] = (byte)(uCount << 3);

                ProcessBlock(strData, 0);

                CopyHash(output, length);
            }
        }

        public byte[] Final()
        {
            byte[] hash = new byte[HASHSIZE];
            Final(hash, HASHSIZE);
            return hash;
        }

        private static uint RotateLeft(uint value, int bits)
        {
            return (value << bits) | (value >> (32 - bits));
        }

        private void ProcessBlock(byte[] data, int offset)
        {
            unchecked
            {
                uint[] W = new uint[80];

                for (int i = 0; i < 16; i++)
                {
                    int j = offset + i * 4;

                    W[i] =
                        ((uint)data[j] << 24) |
                        ((uint)data[j + 1] << 16) |
                        ((uint)data[j + 2] << 8) |
                        data[j + 3];
                }

                for (int t = 16; t < 80; t++)
                {
                    W[t] = RotateLeft(
                        W[t - 3] ^
                        W[t - 8] ^
                        W[t - 14] ^
                        W[t - 16],
                        1);
                }

                uint A = H[0];
                uint B = H[1];
                uint C = H[2];
                uint D = H[3];
                uint E = H[4];

                for (int t = 0; t < 20; t++)
                {
                    uint temp =
                        RotateLeft(A, 5) +
                        ((B & C) | (~B & D)) +
                        E + W[t] + 0x5A827999u;

                    E = D;
                    D = C;
                    C = RotateLeft(B, 30);
                    B = A;
                    A = temp;
                }

                for (int t = 20; t < 40; t++)
                {
                    uint temp =
                        RotateLeft(A, 5) +
                        (B ^ C ^ D) +
                        E + W[t] + 0x6ED9EBA1u;

                    E = D;
                    D = C;
                    C = RotateLeft(B, 30);
                    B = A;
                    A = temp;
                }

                for (int t = 40; t < 60; t++)
                {
                    uint temp =
                        RotateLeft(A, 5) +
                        ((B & C) | (B & D) | (C & D)) +
                        E + W[t] + 0x8F1BBCDCu;

                    E = D;
                    D = C;
                    C = RotateLeft(B, 30);
                    B = A;
                    A = temp;
                }

                for (int t = 60; t < 80; t++)
                {
                    uint temp =
                        RotateLeft(A, 5) +
                        (B ^ C ^ D) +
                        E + W[t] + 0xCA62C1D6u;

                    E = D;
                    D = C;
                    C = RotateLeft(B, 30);
                    B = A;
                    A = temp;
                }

                H[0] += A;
                H[1] += B;
                H[2] += C;
                H[3] += D;
                H[4] += E;
            }
        }

        private void CopyHash(byte[] output, uint length)
        {
            if (length > HASHSIZE)
                length = HASHSIZE;

            for (uint i = 0; i < length; i++)
            {
                output[(int)i] = (byte)(
                    H[i / 4] >> (int)((3 - (i % 4)) * 8));
            }
        }
    }
}