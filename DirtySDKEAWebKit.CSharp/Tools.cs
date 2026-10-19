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
    }
}