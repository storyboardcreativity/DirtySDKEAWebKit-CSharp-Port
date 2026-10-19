using System;

namespace DirtySDKEAWebKit
{
    public static class LobbyBase64
    {
        private const string EncodeTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private static readonly sbyte[] DecodeTable =
        {
            62,                         // +
            -1, -1, -1,                 // ,-.
            63,                         // /
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // 0-9
            -1, -1, -1, -1, -1, -1, -1, // :;<=>?@
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
            10, 11, 12,                  // A-M
            13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25,                  // N-Z
            -1, -1, -1, -1, -1, -1,     // [\]^_`
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
            36, 37, 38,                  // a-m
            39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
            49, 50, 51                   // n-z
        };

        public static string Encode(byte[] input, int inputLen)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            if (inputLen < 0 || inputLen > input.Length)
                throw new ArgumentOutOfRangeException(nameof(inputLen));

            int outputLen = ((inputLen + 2) / 3) * 4;
            char[] output = new char[outputLen + 1];

            int o = 0;
            int i = 0;
            int remaining = inputLen;

            while (remaining >= 3)
            {
                output[o + 0] = EncodeTable[(input[i] >> 2) & 0x3F];

                output[o + 1] = EncodeTable[
                    ((input[i] & 0x03) << 4) |
                    ((input[i + 1] >> 4) & 0x0F)];

                output[o + 2] = EncodeTable[
                    ((input[i + 1] & 0x0F) << 2) |
                    ((input[i + 2] >> 6) & 0x03)];

                output[o + 3] = EncodeTable[input[i + 2] & 0x3F];

                o += 4;
                i += 3;
                remaining -= 3;
            }

            switch (remaining)
            {
                case 1:
                    output[o + 0] = EncodeTable[(input[i] >> 2) & 0x3F];
                    output[o + 1] = EncodeTable[(input[i] & 0x03) << 4];
                    output[o + 2] = '=';
                    output[o + 3] = '=';
                    o += 4;
                    break;

                case 2:
                    output[o + 0] = EncodeTable[(input[i] >> 2) & 0x3F];

                    output[o + 1] = EncodeTable[
                        ((input[i] & 0x03) << 4) |
                        ((input[i + 1] >> 4) & 0x0F)];

                    output[o + 2] = EncodeTable[
                        (input[i + 1] & 0x0F) << 2];

                    output[o + 3] = '=';
                    o += 4;
                    break;
            }

            output[o] = '\0';

            return new string(output, 0, o);
        }

        public static int Decode(int inputLen, byte[] input, byte[] output, int outputLen)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            if (inputLen < 0 || inputLen > input.Length)
                throw new ArgumentOutOfRangeException(nameof(inputLen));

            if (output != null &&
                (outputLen < 0 || outputLen > output.Length))
            {
                throw new ArgumentOutOfRangeException(nameof(outputLen));
            }

            int inputOff = 0;
            int outputOff = 0;

            while (inputOff < inputLen)
            {
                byte[] ci = new byte[4];
                int inputCnt = 0;

                while (inputCnt < 4 &&
                    inputOff < inputLen &&
                    input[inputOff] != 0)
                {
                    byte ch = input[inputOff];
                    inputOff++;

                    if (ch == (byte)' ' ||
                        ch == (byte)'\t' ||
                        ch == (byte)'\r' ||
                        ch == (byte)'\n')
                    {
                        continue;
                    }
                    else if (ch < (byte)'+' || ch > (byte)'z')
                    {
                        return 0;
                    }
                    else
                    {
                        ci[inputCnt++] = ch;
                    }
                }

                if (inputCnt == 0)
                    break;

                if (inputCnt < 4)
                    return 0;

                int co0 = DecodeTable[ci[0] - (byte)'+' - 0];
                int co1 = DecodeTable[ci[1] - (byte)'+' - 0];
                int co2 = DecodeTable[ci[2] - (byte)'+' - 0];
                int co3 = DecodeTable[ci[3] - (byte)'+' - 0];

                if (co0 >= 0 && co1 >= 0)
                {
                    if (co2 >= 0 && co3 >= 0)
                    {
                        if (output != null)
                        {
                            if (outputOff + 3 > outputLen)
                                throw new ArgumentException(
                                    "Output buffer is too small.",
                                    nameof(output));

                            output[outputOff + 0] =
                                (byte)((co0 << 2) | ((co1 >> 4) & 0x03));

                            output[outputOff + 1] =
                                (byte)(((co1 & 0x3F) << 4) |
                                    ((co2 >> 2) & 0x3F));

                            output[outputOff + 2] =
                                (byte)(((co2 & 0x03) << 6) | co3);
                        }

                        outputOff += 3;
                    }
                    else if (co2 >= 0 && ci[3] == (byte)'=')
                    {
                        if (output != null)
                        {
                            if (outputOff + 2 > outputLen)
                                throw new ArgumentException(
                                    "Output buffer is too small.",
                                    nameof(output));

                            output[outputOff + 0] =
                                (byte)((co0 << 2) | ((co1 >> 4) & 0x03));

                            output[outputOff + 1] =
                                (byte)(((co1 & 0x3F) << 4) |
                                    ((co2 >> 2) & 0x3F));
                        }

                        outputOff += 2;
                        inputOff = inputLen;
                    }
                    else if (ci[2] == (byte)'=' &&
                            ci[3] == (byte)'=')
                    {
                        if (output != null)
                        {
                            if (outputOff + 1 > outputLen)
                                throw new ArgumentException(
                                    "Output buffer is too small.",
                                    nameof(output));

                            output[outputOff] =
                                (byte)((co0 << 2) | ((co1 >> 4) & 0x03));
                        }

                        outputOff += 1;
                        inputOff = inputLen;
                    }
                    else
                    {
                        return 0;
                    }
                }
                else
                {
                    return 0;
                }
            }

            if (output == null)
            {
                return inputOff == inputLen ? outputOff : 0;
            }
            else
            {
                return inputOff == inputLen ? 1 : 0;
            }
        }

        public static bool TryDecode(byte[] input, int inputLen, byte[] output, int outputLen)
        {
            return Decode(inputLen, input, output, outputLen) == 1;
        }
    }
}