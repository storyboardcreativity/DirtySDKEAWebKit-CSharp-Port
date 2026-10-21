
using System;
using System.Runtime.InteropServices;

namespace DirtySDKEAWebKit
{
    public static class DirtyMem
    {
        private const int MaxGroups = 16;

        private sealed class MemInfo
        {
            public int Group;
            public IntPtr UserData;
        }

        private static int _group;
        private static readonly MemInfo[] _groupStack = CreateStack();

        private static MemInfo[] CreateStack()
        {
            var stack = new MemInfo[MaxGroups];

            for (int i = 0; i < stack.Length; i++)
                stack[i] = new MemInfo();

            // C: {'dflt', NULL}
            stack[0].Group = Tools.FourCC("dflt");
            stack[0].UserData = IntPtr.Zero;

            return stack;
        }

        public static void DirtyMemGroupEnter(int group, IntPtr userData)
        {
            if (_group >= MaxGroups - 1)
            {
                Console.Error.WriteLine(
                    "dirtymem: group stack overflow");
                return;
            }

            _group++;

            _groupStack[_group].Group = group;
            _groupStack[_group].UserData = userData;
        }

        public static void DirtyMemGroupLeave()
        {
            if (_group <= 0)
            {
                Console.Error.WriteLine(
                    "dirtymem: group stack underflow");
                return;
            }

            _group--;
        }

        public static void DirtyMemGroupQuery(out int group, out IntPtr userData)
        {
            group = _groupStack[_group].Group;
            userData = _groupStack[_group].UserData;
        }

        public static void DirtyMemGroupQuery(int? groupOutput, Action<int>? setGroup, Action<IntPtr>? setUserData)
        {
            if (setGroup is null && setUserData is null)
                return;

            MemInfo current = _groupStack[_group];

            setGroup?.Invoke(current.Group);
            setUserData?.Invoke(current.UserData);
        }

        public static IntPtr DirtyMemAlloc(int size, int memModule, int memGroup, IntPtr userData)
        {
            if (size <= 0)
                return IntPtr.Zero;

            try
            {
                IntPtr memory = Marshal.AllocHGlobal(size);
                return memory;
            }
            catch (OutOfMemoryException)
            {
                return IntPtr.Zero;
            }
        }

        public static void DirtyMemFree(
            IntPtr memory,
            int memModule,
            int memGroup,
            IntPtr userData)
        {
            if (memory == IntPtr.Zero)
                return;

            Marshal.FreeHGlobal(memory);
        }

    #if DEBUG
        public static void DirtyMemDebugAlloc(
            IntPtr memory, int size, int memModule, int memGroup, IntPtr userData)
        {
            Console.WriteLine(
                $"dirtymem: [a] 0x{memory.ToInt64():X8} " +
                $"mod={FourCCText(memModule)} " +
                $"grp={FourCCText(memGroup)} " +
                $"udataptr=0x{userData.ToInt64():X8} size={size}");
        }

        public static void DirtyMemDebugFree(IntPtr memory, int size, int memModule, int memGroup, IntPtr userData)
        {
            string sizeText = size > 0
                ? size.ToString()
                : $"0x{unchecked((uint)size):X8}";

            Console.WriteLine(
                $"dirtymem: [f] 0x{memory.ToInt64():X8} " +
                $"mod={FourCCText(memModule)} " +
                $"grp={FourCCText(memGroup)} " +
                $"udataptr=0x{userData.ToInt64():X8}" +
                (size > 0 ? $" size={sizeText}" : $" size={sizeText}"));
        }
    #endif

        private static string FourCCText(int value)
        {
            return new string(new[]
            {
                (char)((value >> 24) & 0xFF),
                (char)((value >> 16) & 0xFF),
                (char)((value >> 8) & 0xFF),
                (char)(value & 0xFF)
            });
        }
    }
}
