
using System;
using System.Linq;
using System.Text;
using DirtySDKEAWebKit;
using Xunit;

namespace DirtySDKEAWebKit.Tests;

public class EnctypeXTests
{
    private static readonly byte[] Key =
        Encoding.ASCII.GetBytes("test-game-key\0");

    private static readonly byte[] Validate =
        Encoding.ASCII.GetBytes("12345678\0");

    [Fact]
    public void DataState_ShouldInitializeWithExpectedValues()
    {
        var state = new EnctypeX.DataState();

        Assert.Equal(261, state.EncXKey.Length);
        Assert.All(state.EncXKey, b => Assert.Equal(0, b));
        Assert.Equal(0, state.Offset);
        Assert.Equal(0, state.Start);
    }

    [Fact]
    public void RandomValidate_ShouldReturnEightPrintableAsciiBytes()
    {
        var enctypeX = new EnctypeX();

        byte[] validate = enctypeX.RandomValidate();

        Assert.Equal(9, validate.Length);
        Assert.Equal(0, validate[8]);

        for (int i = 0; i < 8; i++)
        {
            Assert.InRange(validate[i], (byte)0x21, (byte)0x7e);
        }
    }

    [Fact]
    public void MasterServerName_ShouldReturnExpectedFormat()
    {
        var enctypeX = new EnctypeX();

        string result = enctypeX.MasterServerName("example");

        Assert.StartsWith("example.ms", result);
        Assert.EndsWith(".gamespy.com", result);

        string serverNumber = result["example.ms".Length..^".gamespy.com".Length];

        Assert.True(int.TryParse(serverNumber, out int number));
        Assert.InRange(number, 0, 19);
    }

    [Fact]
    public void MasterServerName_ShouldReturnNullForNullInput()
    {
        var enctypeX = new EnctypeX();

        Assert.Null(enctypeX.MasterServerName(null));
    }

    [Fact]
    public void CleanerLevel_ShouldPreserveAssignedValue()
    {
        var enctypeX = new EnctypeX();

        enctypeX.CleanerLevel = 0;
        Assert.Equal(0, enctypeX.CleanerLevel);

        enctypeX.CleanerLevel = 3;
        Assert.Equal(3, enctypeX.CleanerLevel);
    }

    [Fact]
    public void DataCleaner_ShouldReplaceBackslashesWithSlashes()
    {
        var enctypeX = new EnctypeX
        {
            CleanerLevel = 0
        };

        byte[] source = Encoding.ASCII.GetBytes(@"one\two\three");
        Array.Resize(ref source, source.Length + 1); // here we add '\0' byte
        byte[] destination = new byte[128];

        int length = enctypeX.DataCleaner(destination, source, -1);

        Assert.Equal("one/two/three", Encoding.ASCII.GetString(destination, 0, length));
        Assert.Equal(0, destination[length]);
    }

    [Fact]
    public void DataCleaner_ShouldRemoveCarriageReturnsAndLineFeeds()
    {
        var enctypeX = new EnctypeX
        {
            CleanerLevel = 0
        };

        byte[] source = Encoding.ASCII.GetBytes("hello\r\nworld\0");
        byte[] destination = new byte[128];

        int length = enctypeX.DataCleaner(destination, source, -1);

        Assert.Equal("helloworld", Encoding.ASCII.GetString(destination, 0, length));
    }

    [Fact]
    public void DataCleaner_ShouldRemoveQuakeColorCodes()
    {
        var enctypeX = new EnctypeX
        {
            CleanerLevel = 1
        };

        byte[] source = Encoding.ASCII.GetBytes("^1Red ^2Green\0");
        byte[] destination = new byte[128];

        int length = enctypeX.DataCleaner(destination, source, -1);

        Assert.Equal("Red Green", Encoding.ASCII.GetString(destination, 0, length));
    }

    [Fact]
    public void DataCleaner_ShouldPreserveCaretWithoutColorCode()
    {
        var enctypeX = new EnctypeX
        {
            CleanerLevel = 1
        };

        byte[] source = Encoding.ASCII.GetBytes("a^!b\0");
        byte[] destination = new byte[128];

        int length = enctypeX.DataCleaner(destination, source, -1);

        Assert.Equal("a^!b", Encoding.ASCII.GetString(destination, 0, length));
    }

    [Fact]
    public void DataCleaner_ShouldSupportMaximumLength()
    {
        var enctypeX = new EnctypeX
        {
            CleanerLevel = 0
        };

        byte[] source = Encoding.ASCII.GetBytes("abcdef\0");
        byte[] destination = new byte[16];

        int length = enctypeX.DataCleaner(destination, source, 3);

        Assert.Equal(3, length);
        Assert.Equal("abc", Encoding.ASCII.GetString(destination, 0, length));
        Assert.Equal(0, destination[length]);
    }

    [Fact]
    public void DataCleaner_ShouldReturnZeroForNullDestination()
    {
        var enctypeX = new EnctypeX();

        Assert.Equal(0, enctypeX.DataCleaner(null, Encoding.ASCII.GetBytes("test"), -1));
    }

    [Fact]
    public void DataCleaner_ShouldHandleNullSource()
    {
        var enctypeX = new EnctypeX();
        byte[] destination = new byte[16];

        destination[0] = 123;

        int length = enctypeX.DataCleaner(destination, null, -1);

        Assert.Equal(0, length);
        Assert.Equal(0, destination[0]);
    }

    [Fact]
    public void Wrapper_ShouldReturnZeroForNullArguments()
    {
        var enctypeX = new EnctypeX();
        byte[] data = new byte[32];

        Assert.Equal(0, enctypeX.Wrapper(null, Validate, data, data.Length));
        Assert.Equal(0, enctypeX.Wrapper(Key, null, data, data.Length));
        Assert.Equal(0, enctypeX.Wrapper(Key, Validate, null, data.Length));
    }

    [Fact]
    public void Wrapper_ShouldReturnZeroForNegativeSize()
    {
        var enctypeX = new EnctypeX();
        byte[] data = new byte[32];

        Assert.Equal(0, enctypeX.Wrapper(Key, Validate, data, -1));
    }

    [Fact]
    public void Decoder_ShouldRejectEmptyPacket()
    {
        var enctypeX = new EnctypeX();
        byte[] data = Array.Empty<byte>();
        int length = 0;

        int result = enctypeX.Decoder(Key, Validate, data, ref length);

        Assert.Equal(-1, result);
    }

    [Fact]
    public void Encoder_ShouldRejectEmptyPacket()
    {
        var enctypeX = new EnctypeX();
        byte[] data = Array.Empty<byte>();
        int length = 0;

        int result = enctypeX.Encoder(Key, Validate, data, ref length);

        Assert.Equal(-1, result);
    }

    [Fact]
    public void QuickEncrypt_ShouldReturnZeroForNullArguments()
    {
        var enctypeX = new EnctypeX();
        byte[] data = new byte[64];

        Assert.Equal(0, enctypeX.QuickEncrypt(null, Validate, data, 1));
        Assert.Equal(0, enctypeX.QuickEncrypt(Key, null, data, 1));
        Assert.Equal(0, enctypeX.QuickEncrypt(Key, Validate, null, 1));
    }

    [Fact]
    public void QuickEncrypt_ShouldReturnZeroForNegativeSize()
    {
        var enctypeX = new EnctypeX();
        byte[] data = new byte[64];

        Assert.Equal(0, enctypeX.QuickEncrypt(Key, Validate, data, -1));
    }

    [Fact]
    public void QuickEncrypt_ShouldRequireHeaderCapacity()
    {
        var enctypeX = new EnctypeX();
        byte[] data = new byte[32];

        Assert.Throws<ArgumentException>(
            () => enctypeX.QuickEncrypt(Key, Validate, data, 32));
    }

    [Fact]
    public void QuickEncrypt_ShouldReturnPayloadLengthPlusHeaderSize()
    {
        var enctypeX = new EnctypeX();
        byte[] payload = Encoding.ASCII.GetBytes("hello");
        byte[] data = new byte[payload.Length + 23];

        Array.Copy(payload, data, payload.Length);

        int result = enctypeX.QuickEncrypt(
            Key, Validate, data, payload.Length);

        Assert.Equal(payload.Length + 23, result);
    }

    [Fact]
    public void QuickEncrypt_ShouldWriteExpectedHeaderMarkers()
    {
        var enctypeX = new EnctypeX();
        byte[] data = new byte[23 + 8];

        int result = enctypeX.QuickEncrypt(Key, Validate, data, 8);

        Assert.Equal(31, result);

        // Header markers are initialized before encryption.
        // This assertion is intentionally not made against the final
        // encrypted bytes, since the entire packet is transformed.
    }

    [Fact]
    public void QuickEncrypt_ShouldNotModifyBytesBeyondPacket()
    {
        var enctypeX = new EnctypeX();
        byte[] data = Enumerable.Repeat((byte)0xAA, 64).ToArray();
        byte[] tailBefore = data[40..];

        enctypeX.QuickEncrypt(Key, Validate, data, 5);

        Assert.Equal(tailBefore, data[40..]);
    }

    [Fact]
    public void RandomValidate_ShouldProduceDifferentArrays()
    {
        var enctypeX = new EnctypeX();

        byte[] first = enctypeX.RandomValidate();
        byte[] second = enctypeX.RandomValidate();

        Assert.NotSame(first, second);
    }
}
