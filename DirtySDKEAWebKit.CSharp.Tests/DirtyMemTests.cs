
using System;
using System.IO;
using System.Runtime.InteropServices;
using Xunit;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.Tests;

public class DirtyMemTests
{
    [Fact]
    public void FourCC_ConvertsFourCharacters()
    {
        Assert.Equal(
            unchecked((int)0x64736F63),
            DirtyMem.FourCC("dsoc"));
    }

    [Fact]
    public void FourCC_RejectsInvalidLength()
    {
        Assert.Throws<ArgumentException>(() => DirtyMem.FourCC("abc"));
        Assert.Throws<ArgumentException>(() => DirtyMem.FourCC("abcde"));
    }

    [Fact]
    public void FourCC_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => DirtyMem.FourCC(null!));
    }

    [Fact]
    public void GroupQuery_ReturnsDefaultGroupInitially()
    {
        DirtyMem.DirtyMemGroupQuery(out int group, out IntPtr userData);
        Assert.Equal(DirtyMem.FourCC("dflt"), group);
        Assert.Equal(IntPtr.Zero, userData);
    }

    [Fact]
    public void GroupEnterAndQuery_ReturnEnteredValues()
    {
        int group = DirtyMem.FourCC("test");
        IntPtr userData = new IntPtr(1234);

        DirtyMem.DirtyMemGroupEnter(group, userData);

        try
        {
            DirtyMem.DirtyMemGroupQuery(
                out int actualGroup, out IntPtr actualUserData);

            Assert.Equal(group, actualGroup);
            Assert.Equal(userData, actualUserData);
        }
        finally
        {
            DirtyMem.DirtyMemGroupLeave();
        }
    }

    [Fact]
    public void GroupLeave_RestoresPreviousGroup()
    {
        DirtyMem.DirtyMemGroupQuery(
            out int originalGroup, out IntPtr originalUserData);

        DirtyMem.DirtyMemGroupEnter(
            DirtyMem.FourCC("test"), new IntPtr(42));

        DirtyMem.DirtyMemGroupLeave();

        DirtyMem.DirtyMemGroupQuery(
            out int group, out IntPtr userData);

        Assert.Equal(originalGroup, group);
        Assert.Equal(originalUserData, userData);
    }

    [Fact]
    public void GroupEnter_SupportsNestedGroups()
    {
        int first = DirtyMem.FourCC("grp1");
        int second = DirtyMem.FourCC("grp2");

        DirtyMem.DirtyMemGroupEnter(first, new IntPtr(1));
        try
        {
            DirtyMem.DirtyMemGroupEnter(second, new IntPtr(2));
            try
            {
                DirtyMem.DirtyMemGroupQuery(
                    out int group, out IntPtr userData);

                Assert.Equal(second, group);
                Assert.Equal(new IntPtr(2), userData);
            }
            finally
            {
                DirtyMem.DirtyMemGroupLeave();
            }

            DirtyMem.DirtyMemGroupQuery(
                out int restoredGroup, out IntPtr restoredData);

            Assert.Equal(first, restoredGroup);
            Assert.Equal(new IntPtr(1), restoredData);
        }
        finally
        {
            DirtyMem.DirtyMemGroupLeave();
        }
    }

    [Fact]
    public void GroupEnter_OverflowDoesNotChangeCurrentGroup()
    {
        int group = DirtyMem.FourCC("test");
        DirtyMem.DirtyMemGroupEnter(group, IntPtr.Zero);

        try
        {
            for (int i = 0; i < 20; i++)
            {
                DirtyMem.DirtyMemGroupEnter(
                    DirtyMem.FourCC("more"), IntPtr.Zero);
            }

            DirtyMem.DirtyMemGroupQuery(
                out int actualGroup, out _);

            Assert.Equal(DirtyMem.FourCC("more"), actualGroup);
        }
        finally
        {
            for (int i = 0; i < 20; i++)
                DirtyMem.DirtyMemGroupLeave();
        }
    }

    [Fact]
    public void GroupLeave_AtRootDoesNotThrow()
    {
        for (int i = 0; i < 16; i++)
            DirtyMem.DirtyMemGroupLeave();

        var exception = Record.Exception(
            () => DirtyMem.DirtyMemGroupLeave());

        Assert.Null(exception);

        DirtyMem.DirtyMemGroupQuery(
            out int group, out IntPtr userData);

        Assert.Equal(DirtyMem.FourCC("dflt"), group);
        Assert.Equal(IntPtr.Zero, userData);
    }

    [Fact]
    public void GroupQuery_ReturnsCurrentGroup()
    {
        int expectedGroup = DirtyMem.FourCC("qry1");
        IntPtr expectedData = new IntPtr(987);

        DirtyMem.DirtyMemGroupEnter(expectedGroup, expectedData);

        try
        {
            int actualGroup = 0;
            IntPtr actualData = IntPtr.Zero;

            DirtyMem.DirtyMemGroupQuery(
                null,
                value => actualGroup = value,
                value => actualData = value);

            Assert.Equal(expectedGroup, actualGroup);
            Assert.Equal(expectedData, actualData);
        }
        finally
        {
            DirtyMem.DirtyMemGroupLeave();
        }
    }

    [Fact]
    public void Alloc_AllocatesMemory()
    {
        IntPtr memory = DirtyMem.DirtyMemAlloc(
            128, DirtyMem.FourCC("test"),
            DirtyMem.FourCC("dflt"), IntPtr.Zero);

        Assert.NotEqual(IntPtr.Zero, memory);

        DirtyMem.DirtyMemFree(
            memory, DirtyMem.FourCC("test"),
            DirtyMem.FourCC("dflt"), IntPtr.Zero);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void Alloc_NonPositiveSize_ReturnsZero(int size)
    {
        IntPtr memory = DirtyMem.DirtyMemAlloc(
            size, 0, 0, IntPtr.Zero);

        Assert.Equal(IntPtr.Zero, memory);
    }

    [Fact]
    public void Alloc_MemoryCanBeReadAndWritten()
    {
        IntPtr memory = DirtyMem.DirtyMemAlloc(
            sizeof(int), 0, 0, IntPtr.Zero);

        Assert.NotEqual(IntPtr.Zero, memory);

        try
        {
            Marshal.WriteInt32(memory, 123456);
            Assert.Equal(123456, Marshal.ReadInt32(memory));
        }
        finally
        {
            DirtyMem.DirtyMemFree(memory, 0, 0, IntPtr.Zero);
        }
    }

    [Fact]
    public void Free_NullPointerDoesNotThrow()
    {
        var exception = Record.Exception(
            () => DirtyMem.DirtyMemFree(IntPtr.Zero, 0, 0, IntPtr.Zero));

        Assert.Null(exception);
    }

    [Fact]
    public void Free_ReleasesAllocatedMemory()
    {
        IntPtr memory = DirtyMem.DirtyMemAlloc(
            64, 0, 0, IntPtr.Zero);

        Assert.NotEqual(IntPtr.Zero, memory);

        var exception = Record.Exception(
            () => DirtyMem.DirtyMemFree(memory, 0, 0, IntPtr.Zero));

        Assert.Null(exception);
    }

#if DEBUG
    [Fact]
    public void DebugAlloc_WritesExpectedInformation()
    {
        using var writer = new StringWriter();
        TextWriter original = Console.Out;
        Console.SetOut(writer);

        try
        {
            DirtyMem.DirtyMemDebugAlloc(
                new IntPtr(0x1234),
                64,
                DirtyMem.FourCC("mod1"),
                DirtyMem.FourCC("grp1"),
                IntPtr.Zero);
        }
        finally
        {
            Console.SetOut(original);
        }

        string output = writer.ToString();

        Assert.Contains("dirtymem: [a]", output);
        Assert.Contains("mod=mod1", output);
        Assert.Contains("grp=grp1", output);
        Assert.Contains("size=64", output);
    }

    [Theory]
    [InlineData(64, "size=64")]
    [InlineData(0, "size=0x00000000")]
    [InlineData(-1, "size=0xFFFFFFFF")]
    public void DebugFree_FormatsSize(int size, string expected)
    {
        using var writer = new StringWriter();
        TextWriter original = Console.Out;
        Console.SetOut(writer);

        try
        {
            DirtyMem.DirtyMemDebugFree(
                new IntPtr(0x1234), size,
                DirtyMem.FourCC("mod1"),
                DirtyMem.FourCC("grp1"),
                IntPtr.Zero);
        }
        finally
        {
            Console.SetOut(original);
        }

        Assert.Contains(expected, writer.ToString());
    }
#endif
}
