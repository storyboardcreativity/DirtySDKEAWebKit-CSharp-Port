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
            Console.Write(message);
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
    }
}