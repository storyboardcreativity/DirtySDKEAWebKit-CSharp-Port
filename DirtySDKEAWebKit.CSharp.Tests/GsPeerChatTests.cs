
using System;
using Xunit;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.Tests;

public class GsPeerChatTests
{
    private static readonly byte[] Challenge =
    {
        0x10, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x12, 0x34, 0x56,
        0x78, 0x9A, 0xBC, 0xDE
    };

    private static readonly byte[] GameKey =
    {
        0x47, 0x61, 0x6D, 0x65,
        0x4B, 0x65, 0x79
    };

    [Fact]
    public void Process_ShouldEncryptAndDecryptData()
    {
        byte[] original =
        {
            0x00, 0x01, 0x02, 0x03,
            0x7F, 0x80, 0xFE, 0xFF
        };

        byte[] encrypted = (byte[])original.Clone();

        var encryptor = new GsPeerChat(Challenge, GameKey);
        encryptor.Process(encrypted, encrypted.Length);

        Assert.NotEqual(original, encrypted);

        var decryptor = new GsPeerChat(Challenge, GameKey);
        decryptor.Process(encrypted, encrypted.Length);

        Assert.Equal(original, encrypted);
    }

    [Fact]
    public void Process_ShouldHandleAllByteValues()
    {
        byte[] data = new byte[256];

        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)i;

        byte[] original = (byte[])data.Clone();

        var encryptor = new GsPeerChat(Challenge, GameKey);
        encryptor.Process(data, data.Length);

        Assert.NotEqual(original, data);

        var decryptor = new GsPeerChat(Challenge, GameKey);
        decryptor.Process(data, data.Length);

        Assert.Equal(original, data);
    }

    [Fact]
    public void Process_ShouldPreserveStateBetweenCalls()
    {
        byte[] original =
        {
            0x10, 0x20, 0x30, 0x40,
            0x50, 0x60, 0x70, 0x80,
            0x90, 0xA0, 0xB0, 0xC0
        };

        byte[] expected = (byte[])original.Clone();
        byte[] actual = (byte[])original.Clone();

        var singleCall = new GsPeerChat(Challenge, GameKey);
        singleCall.Process(expected, expected.Length);

        var multipleCalls = new GsPeerChat(Challenge, GameKey);

        byte[] part1 = GetSlice(actual, 0, 4);
        multipleCalls.Process(part1, part1.Length);
        Array.Copy(part1, 0, actual, 0, part1.Length);

        byte[] part2 = GetSlice(actual, 4, 4);
        multipleCalls.Process(part2, part2.Length);
        Array.Copy(part2, 0, actual, 4, part2.Length);

        byte[] part3 = GetSlice(actual, 8, 4);
        multipleCalls.Process(part3, part3.Length);
        Array.Copy(part3, 0, actual, 8, part3.Length);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Process_ShouldMatchSingleCallWhenDataIsSplit()
    {
        byte[] original = new byte[512];

        for (int i = 0; i < original.Length; i++)
            original[i] = (byte)(i * 37);

        byte[] expected = (byte[])original.Clone();
        byte[] actual = (byte[])original.Clone();

        var singleCall = new GsPeerChat(Challenge, GameKey);
        singleCall.Process(expected, expected.Length);

        var splitCalls = new GsPeerChat(Challenge, GameKey);

        splitCalls.Process(actual, 100);

        byte[] secondPart = GetSlice(actual, 100, 200);
        splitCalls.Process(secondPart, secondPart.Length);
        Array.Copy(secondPart, 0, actual, 100, secondPart.Length);

        byte[] thirdPart = GetSlice(actual, 300, 212);
        splitCalls.Process(thirdPart, thirdPart.Length);
        Array.Copy(thirdPart, 0, actual, 300, thirdPart.Length);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Process_WithZeroSize_ShouldNotChangeData()
    {
        byte[] data = { 0x11, 0x22, 0x33 };
        byte[] original = (byte[])data.Clone();

        var peerChat = new GsPeerChat(Challenge, GameKey);
        peerChat.Process(data, 0);

        Assert.Equal(original, data);
    }

    [Fact]
    public void Process_ShouldOnlyModifyRequestedBytes()
    {
        byte[] data =
        {
            0x10, 0x20, 0x30, 0x40,
            0x50, 0x60, 0x70, 0x80
        };

        byte[] original = (byte[])data.Clone();

        var peerChat = new GsPeerChat(Challenge, GameKey);
        peerChat.Process(data, 4);

        Assert.NotEqual(original[..4], data[..4]);
        Assert.Equal(original[4..], data[4..]);
    }

    [Fact]
    public void Constructor_ShouldRejectNullChallenge()
    {
        Assert.Throws<ArgumentNullException>(
            () => new GsPeerChat(null!, GameKey));
    }

    [Fact]
    public void Constructor_ShouldRejectNullGameKey()
    {
        Assert.Throws<ArgumentNullException>(
            () => new GsPeerChat(Challenge, null!));
    }

    [Fact]
    public void Constructor_ShouldRejectShortChallenge()
    {
        byte[] challenge = new byte[15];

        Assert.Throws<ArgumentException>(
            () => new GsPeerChat(challenge, GameKey));
    }

    [Fact]
    public void Constructor_ShouldRejectEmptyGameKey()
    {
        Assert.Throws<ArgumentException>(
            () => new GsPeerChat(Challenge, Array.Empty<byte>()));
    }

    [Fact]
    public void Process_ShouldRejectNullData()
    {
        var peerChat = new GsPeerChat(Challenge, GameKey);

        Assert.Throws<ArgumentNullException>(
            () => peerChat.Process(null!, 0));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(4)]
    public void Process_ShouldRejectInvalidSize(int size)
    {
        byte[] data = { 0x01, 0x02, 0x03 };
        var peerChat = new GsPeerChat(Challenge, GameKey);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => peerChat.Process(data, size));
    }

    private static byte[] GetSlice(
        byte[] source,
        int offset,
        int count)
    {
        byte[] result = new byte[count];
        Array.Copy(source, offset, result, 0, count);
        return result;
    }
}
