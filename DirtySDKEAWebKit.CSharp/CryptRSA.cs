using System;
using System.Diagnostics;

namespace DirtySDKEAWebKit
{
    public class CryptRSA
    {
        internal const int MaxWords = 4096 / 16;

        private struct CryptRSARandomT
        {
            public uint u0;
            public uint u1;
        }

        public int iKeyModSize;
        public int iKeyExpSize;
        public byte[] EncryptBlock = new byte[1024];
        public byte[] KeyModData = new byte[256 + 1];
        public byte[] KeyExpData = new byte[256 + 1];
        private CryptRSARandomT _Random;

        internal static int Addition(ushort[] result, int width, ushort[] add1, ushort[] add2)
        {
            uint accum = 0;

            for (int i = width - 1; i >= 0; --i)
            {
                accum += (uint)add1[i] + add2[i];
                result[i] = (ushort)accum;
                accum >>= 16;
            }

            return (int)accum;
        }

        internal static int Subtract(ushort[] result, int width, ushort[] sub1, ushort[] sub2)
        {
            uint accum = 0;

            for (int i = width - 1; i >= 0; --i)
            {
                // Preserve the original C unsigned-underflow behavior
                accum = unchecked((uint)sub1[i] - sub2[i] - accum);
                result[i] = (ushort)accum;
                accum = (accum >> 16) & 1;
            }

            return (int)accum;
        }

        internal static int BitTest(ushort[] value, int width, int bit)
        {
            int step = sizeof(ushort) * 8;
            int weight = bit % step;
            int offset = (step * width - bit - 1) / step;

            ushort result = (ushort)(value[offset] & (1 << weight));
            return result;
        }

        internal static void Multiply(ushort[] result, int width, ushort[] mul1, ushort[] mul2, ushort[] mod)
        {
            int count;
            int carry;

            ushort[] temp1 = new ushort[MaxWords];
            ushort[] temp2 = new ushort[MaxWords];

            ushort[] cur = temp1;
            ushort[] alt = temp2;

            Array.Clear(cur, 0, width);

            for (count = width * sizeof(ushort) * 8 - 1;
                count >= 0; --count)
            {
                carry = Addition(cur, width, cur, cur);

                if (Subtract(alt, width, cur, mod) == 0 || carry != 0)
                {
                    ushort[] swap = cur;
                    cur = alt;
                    alt = swap;
                }

                if (BitTest(mul1, width, count) != 0)
                {
                    carry = Addition(cur, width, cur, mul2);

                    if (Subtract(alt, width, cur, mod) == 0 || carry != 0)
                    {
                        ushort[] swap = cur;
                        cur = alt;
                        alt = swap;
                    }
                }
            }

            Array.Copy(cur, result, width);
        }

        internal static int ToWords(ushort[] result, int width, byte[] source, int length)
        {
            int fullWordCount = length / 2;
            int wordCount = (length + 1) / 2;

            if (width < 0)
            {
                width = wordCount;
            }

            int resultIndex = 0;
            int sourceIndex = 0;

            for (; width > wordCount; --width)
            {
                result[resultIndex++] = 0;
            }

            if (fullWordCount != wordCount)
            {
                result[resultIndex++] = source[sourceIndex];
                sourceIndex += 1;
                width -= 1;
            }

            for (; width > 0; --width)
            {
                result[resultIndex++] =
                    (ushort)((source[sourceIndex] << 8) |
                            (source[sourceIndex + 1] << 0));

                sourceIndex += 2;
            }

            return wordCount;
        }

        internal static void FromWords(ushort[] source, int width, byte[] result, int length)
        {
            length /= 2;

            int sourceIndex = width - length;
            int resultIndex = 0;

            for (; length > 0; --length)
            {
                result[resultIndex++] = (byte)(source[sourceIndex] >> 8);
                result[resultIndex++] = (byte)(source[sourceIndex] >> 0);
                sourceIndex += 1;
            }
        }

        internal static void Exponentiate(byte[] result, byte[] powerOf, byte[] modulus, int modSize, byte[] exponent, int expSize)
        {
            int index;
            int width;
            uint exponentValue;

            ushort[] modulusWords = new ushort[MaxWords];
            ushort[] powerWords = new ushort[MaxWords];
            ushort[] accum = new ushort[MaxWords];

            width = ToWords(modulusWords, -1, modulus, modSize);

            ToWords(powerWords, -1, powerOf, modSize);

            exponentValue = 0;

            for (index = 0; index < expSize; ++index)
            {
                exponentValue = unchecked(
                    (exponentValue << 8) | exponent[index]);
            }

            if (exponentValue == 3)
            {
                Multiply(accum, width, powerWords, powerWords, modulusWords);
                Multiply(accum, width, accum, powerWords, modulusWords);
            }
            else if (exponentValue == 17)
            {
                Multiply(accum, width, powerWords, powerWords, modulusWords);
                Multiply(accum, width, accum, accum, modulusWords);
                Multiply(accum, width, accum, accum, modulusWords);
                Multiply(accum, width, accum, accum, modulusWords);
                Multiply(accum, width, accum, powerWords, modulusWords);
            }
            else if (exponentValue == 65537)
            {
                Multiply(accum, width, powerWords, powerWords, modulusWords);

                for (int i = 0; i < 15; ++i)
                {
                    Multiply(accum, width, accum, accum, modulusWords);
                }

                Multiply(accum, width, accum, powerWords, modulusWords);
            }
            else
            {
                Tools.NetPrintf(
                    "cryptrsa: warning; executing general case code, " +
                    "which is likely to be slow\n");

                Array.Clear(accum, 0, accum.Length);
                accum[width - 1] = 1;

                while (exponentValue != 0)
                {
                    if ((exponentValue & 1) != 0)
                    {
                        Multiply(accum, width, accum, powerWords, modulusWords);
                    }

                    Multiply(powerWords, width, powerWords, powerWords, modulusWords);
                    exponentValue >>= 1;
                }
            }

            FromWords(accum, width, result, modSize);
        }

        public void Init(byte[] modulus, int modSize, byte[] exponent, int expSize)
        {
            int maxModSize = KeyModData.Length - 1;
            int maxExpSize = KeyExpData.Length - 1;

            if (modSize > maxModSize)
            {
                Tools.NetPrintf(
                    $"cryptrsa: requested iModSize of {modSize} " +
                    $"is too large; truncating to {maxModSize}\n");

                modSize = maxModSize;
            }

            if (expSize > maxExpSize)
            {
                Tools.NetPrintf(
                    $"cryptrsa: requested iExpSize of {expSize} " +
                    $"is too large; truncating to {maxExpSize}\n");

                expSize = maxExpSize;
            }

            iKeyModSize = modSize;
            iKeyExpSize = expSize;

            Array.Copy(modulus, 0, KeyModData, 0, modSize);
            Array.Copy(exponent, 0, KeyExpData, 0, expSize);
        }

        public void InitMaster(byte[] master, int masterLen)
        {
            ArgumentNullException.ThrowIfNull(master);
            if (masterLen < 0 || masterLen > master.Length)
                throw new ArgumentOutOfRangeException(nameof(masterLen));
            
            if (masterLen > iKeyModSize - 11)
                throw new ArgumentException("Master key is too long for PKCS#1 v1.5 padding.");

            int index;
            uint random = Tools.NetTick();

            for (index = 0; index < iKeyModSize; ++index)
            {
                EncryptBlock[index] =
                    (byte)((random & (1u << (index & 31))) != 0 ? 1 : 0);
            }

            for (index = 0; index < iKeyModSize; ++index)
            {
                do
                {
                    random = unchecked((random * 69069u) + 69069u);

                    EncryptBlock[index] ^=
                        unchecked((byte)random);
                }
                while (EncryptBlock[index] == 0);
            }

            EncryptBlock[0] = 0;
            EncryptBlock[1] = 2;

            index = iKeyModSize - masterLen;

            EncryptBlock[index - 1] = 0;

            Array.Copy(master, 0, EncryptBlock, index, masterLen);
        }

        public void InitSignature(byte[] signature, int sigLen)
        {
            Array.Copy(signature, 0, EncryptBlock, 0, sigLen);
        }

        public void Encrypt()
        {
            Exponentiate(
                EncryptBlock,
                EncryptBlock,
                KeyModData,
                iKeyModSize,
                KeyExpData,
                iKeyExpSize);
        }
    }
}