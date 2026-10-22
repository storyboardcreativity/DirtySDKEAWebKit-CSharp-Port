using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DirtySDKEAWebKit
{
    public sealed class Tools
    {
        // Closest managed equivalent of the supplied NetTick()
        // (uses process CPU time)
        public static uint NetTick()
        {
            double milliseconds =
                Process.GetCurrentProcess().TotalProcessorTime.TotalMilliseconds;

            return unchecked((uint)milliseconds);
        }

        public static void NetPrintf(string message)
        {
            Console.WriteLine(message);
        }

        public static int FourCC(string value)
        {
            ArgumentNullException.ThrowIfNull(value);

            if (value.Length != 4)
                throw new ArgumentException(
                    "FourCC must contain exactly four characters.",
                    nameof(value));

            return unchecked(
                (value[0] << 24) |
                (value[1] << 16) |
                (value[2] << 8) |
                value[3]);
        }

        public static void PrintBuffer(byte[] buffer)
        {
            const int symbolsCnt = 16;

            for (int i = 0; i < buffer.Length; i += symbolsCnt)
            {
                var hex = new System.Text.StringBuilder();
                var chars = new System.Text.StringBuilder();

                for (int p = 0; p < symbolsCnt; p++)
                {
                    if (i + p < buffer.Length)
                    {
                        byte b = buffer[i + p];
                        hex.Append($"{b:x2} ");
                    }
                    else
                    {
                        hex.Append(".. ");
                    }
                }

                hex.Append("| ");

                for (int p = 0; p < symbolsCnt; p++)
                {
                    if (i + p < buffer.Length)
                    {
                        byte b = buffer[i + p];
                        chars.Append(b >= 0x21 && b <= 0x7E ? (char)b : '.');
                    }
                    else
                    {
                        chars.Append(' ');
                    }
                }

                Console.WriteLine(hex.ToString() + chars);
            }
        }
    }
}