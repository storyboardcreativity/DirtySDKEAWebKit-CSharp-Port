
using System;

namespace DirtySDKEAWebKit
{
    public class CryptMD2
    {
        public int iCount;
        public readonly byte[] aState = new byte[16];
        public readonly byte[] aChecksum = new byte[16];
        public readonly byte[] aBuffer = new byte[16];

        public const int MD2_BINARY_OUT = 16;
        public const int MD2_STRING_OUT = 33;

        private static readonly byte[] _CryptMD2_aPiSubst =
        {
            41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240,   6,  19,
            98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,  76, 130, 202,
            30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111, 24,  138,  23, 229,  18,
            190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142, 187,  47, 238, 122,
            169, 104, 121, 145,  21, 178,   7,  63, 148, 194,  16, 137,  11,  34,  95,  33,
            128, 127,  93, 154,  90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
            255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42, 172,  86, 170, 198,
            79, 184,  56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,
            69, 157, 112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
            27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126,  15,
            85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197, 234,  38,
            44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244, 65,  129,  77,  82,
            106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,  12, 189, 177,  74,
            120, 136, 149, 139, 227,  99, 232, 109, 233, 203, 213, 254,  59,   0,  29,  57,
            242, 239, 183,  14, 102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
            49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51, 159,  17, 131,  20
        };

        public void Init()
        {
            Array.Clear(aState, 0, aState.Length);
            Array.Clear(aChecksum, 0, aChecksum.Length);
            Array.Clear(aBuffer, 0, aBuffer.Length);
            iCount = 0;
        }

        private void _CryptMD2Transform(byte[] pInput, int inputOffset)
        {
            byte[] aCryptBlock = new byte[48];
            int iBlock;
            int iIter;
            int iTemp;

            Array.Copy(aState, 0, aCryptBlock, 0, 16);
            Array.Copy(pInput, inputOffset, aCryptBlock, 16, 16);

            for (iBlock = 0; iBlock < 16; iBlock++)
            {
                aCryptBlock[iBlock + 32] =
                    (byte)(aState[iBlock] ^ pInput[inputOffset + iBlock]);
            }

            for (iIter = 0, iTemp = 0; iIter < 18; iIter++)
            {
                for (iBlock = 0; iBlock < 48; iBlock++)
                {
                    aCryptBlock[iBlock] ^= _CryptMD2_aPiSubst[iTemp];
                    iTemp = aCryptBlock[iBlock];
                }

                iTemp = (iTemp + iIter) & 0xff;
            }

            Array.Copy(aCryptBlock, 0, aState, 0, 16);

            iTemp = aChecksum[15];

            for (iBlock = 0; iBlock < 16; iBlock++)
            {
                iTemp = aChecksum[iBlock] =
                    (byte)(aChecksum[iBlock] ^
                        _CryptMD2_aPiSubst[pInput[inputOffset + iBlock] ^ iTemp]);
            }

            Array.Clear(aCryptBlock, 0, aCryptBlock.Length);
        }

        public void Update(byte[] pBuffer, int iLength)
        {
            Update(pBuffer, 0, iLength);
        }

        public void Update(byte[] pBuffer, int bufferOffset, int iLength)
        {
            int iIndex;
            int iPartLen;

            // The C implementation treats negative lengths as null-terminated byte strings
            if (iLength < 0)
            {
                iLength = 0;

                while (pBuffer[bufferOffset + iLength] != 0)
                {
                    iLength++;
                }
            }

            int iCount_ = iCount;
            iCount = (iCount_ + iLength) & 0x0f;
            iPartLen = 16 - iCount_;

            if (iLength >= iPartLen)
            {
                Array.Copy(pBuffer, bufferOffset, aBuffer, iCount_, iPartLen);

                _CryptMD2Transform(aBuffer, 0);

                for (iIndex = iPartLen;
                    iIndex + 15 < iLength;
                    iIndex += 16)
                {
                    _CryptMD2Transform(pBuffer, bufferOffset + iIndex);
                }

                iCount_ = 0;
            }
            else
            {
                iIndex = 0;
            }

            int remaining = iLength - iIndex;
            if (remaining > 0)
                Array.Copy(pBuffer, bufferOffset + iIndex, aBuffer, iCount_, remaining);
        }

        public void Final(byte[] pBuffer, int iLength)
        {
            Final(pBuffer, 0, iLength);
        }

        public void Final(byte[] pBuffer, int bufferOffset, int iLength)
        {
            if (iLength < MD2_BINARY_OUT)
            {
                // Equivalent to the original insufficient-buffer behavior: do not finalize or reset the context
                return;
            }

            int iPadLen = 16 - iCount;

            // MD2 padding consists of iPadLen bytes, each equal to iPadLen
            byte[] padding = new byte[iPadLen];
            Array.Fill(padding, (byte)iPadLen);

            Update(padding, 0, iPadLen);

            // Update buffers the checksum block before transforming it, matching the original C implementation
            Update(aChecksum, 0, 16);

            Array.Copy(aState, 0, pBuffer, bufferOffset, MD2_BINARY_OUT);

            // The original implementation clears the whole context
            Init();
        }

        public static byte[] ComputeHash(byte[] data)
        {
            CryptMD2 context = new CryptMD2();
            byte[] digest = new byte[MD2_BINARY_OUT];

            context.Init();
            context.Update(data, data.Length);
            context.Final(digest, digest.Length);

            return digest;
        }

        public static string ToHexString(byte[] digest)
        {
            return Convert.ToHexString(digest);
        }
    }
}
