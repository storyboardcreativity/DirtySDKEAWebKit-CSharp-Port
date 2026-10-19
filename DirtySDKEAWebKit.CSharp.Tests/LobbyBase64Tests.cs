using System;
using System.Text;
using Xunit;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.Tests;

public class LobbyBase64Tests
{
    [Theory]
    [InlineData("", "")]
    [InlineData("M", "TQ==")]
    [InlineData("Ma", "TWE=")]
    [InlineData("Man", "TWFu")]
    [InlineData("Hello", "SGVsbG8=")]
    [InlineData("Hello World", "SGVsbG8gV29ybGQ=")]
    [InlineData("foobar", "Zm9vYmFy")]
    public void Encode_ShouldReturnExpectedBase64(string input, string expected)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(input);
        string actual = LobbyBase64.Encode(bytes, bytes.Length);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Encode_ShouldHandleAllByteValues()
    {
        byte[] input = new byte[256];
        for (int i = 0; i < input.Length; i++)
            input[i] = (byte)i;
        string actual = LobbyBase64.Encode(input, input.Length);
        Assert.Equal(Convert.ToBase64String(input), actual);
    }

    [Fact]
    public void Encode_ShouldRespectInputLength()
    {
        byte[] input = Encoding.ASCII.GetBytes("HelloExtra");
        string actual = LobbyBase64.Encode(input, 5);
        Assert.Equal("SGVsbG8=", actual);
    }

    [Fact]
    public void Encode_EmptyInput_ShouldReturnEmptyString()
    {
        string actual = LobbyBase64.Encode(Array.Empty<byte>(), 0);
        Assert.Equal(string.Empty, actual);
    }

    [Fact]
    public void Encode_NullInput_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => LobbyBase64.Encode(null!, 0));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(4)]
    public void Encode_InvalidInputLength_ShouldThrow(int inputLength)
    {
        byte[] input = new byte[3];
        Assert.Throws<ArgumentOutOfRangeException>(() => LobbyBase64.Encode(input, inputLength));
    }

    [Theory]
    [InlineData("TWFu", "Man")]
    [InlineData("TQ==", "M")]
    [InlineData("TWE=", "Ma")]
    [InlineData("SGVsbG8=", "Hello")]
    [InlineData("SGVsbG8gV29ybGQ=", "Hello World")]
    [InlineData("Zm9vYmFy", "foobar")]
    public void Decode_ShouldReturnExpectedBytes(string input, string expected)
    {
        byte[] encoded = Encoding.ASCII.GetBytes(input);
        byte[] output = new byte[encoded.Length / 4 * 3];

        int result = LobbyBase64.Decode(
            encoded.Length,
            encoded,
            output,
            output.Length);

        Assert.Equal(1, result);
        Assert.Equal(
            Encoding.ASCII.GetBytes(expected),
            output[..Encoding.ASCII.GetByteCount(expected)]);
    }

    [Fact]
    public void Decode_AllByteValues_ShouldRoundTrip()
    {
        byte[] input = new byte[256];

        for (int i = 0; i < input.Length; i++)
            input[i] = (byte)i;

        string encodedString = LobbyBase64.Encode(input, input.Length);
        byte[] encoded = Encoding.ASCII.GetBytes(encodedString);
        byte[] decoded = new byte[input.Length];

        int result = LobbyBase64.Decode(
            encoded.Length,
            encoded,
            decoded,
            decoded.Length);

        Assert.Equal(1, result);
        Assert.Equal(input, decoded);
    }

    [Fact]
    public void Decode_EmptyInput_ShouldSucceed()
    {
        byte[] input = Array.Empty<byte>();
        byte[] output = Array.Empty<byte>();

        int result = LobbyBase64.Decode(
            0,
            input,
            output,
            output.Length);

        Assert.Equal(1, result);
    }

    [Fact]
    public void Decode_EmptyInput_SizeQuery_ShouldReturnZero()
    {
        int result = LobbyBase64.Decode(0, Array.Empty<byte>(), null, 0);
        Assert.Equal(0, result);
    }

    [Theory]
    [InlineData("TWFu", 3)]
    [InlineData("TWE=", 2)]
    [InlineData("TQ==", 1)]
    [InlineData("SGVsbG8=", 5)]
    [InlineData("", 0)]
    public void Decode_NullOutput_ShouldReturnDecodedLength(string input, int expectedLength)
    {
        byte[] encoded = Encoding.ASCII.GetBytes(input);
        int result = LobbyBase64.Decode(encoded.Length, encoded, null, 0);
        Assert.Equal(expectedLength, result);
    }

    [Theory]
    [InlineData("T W F u", "Man")]
    [InlineData("T\tWFu", "Man")]
    [InlineData("TW\nFu", "Man")]
    [InlineData("TW\rFu", "Man")]
    [InlineData("T W\r\nF u", "Man")]
    public void Decode_ShouldIgnoreWhitespace(string input, string expected)
    {
        byte[] encoded = Encoding.ASCII.GetBytes(input);
        byte[] output = new byte[encoded.Length];

        int result = LobbyBase64.Decode(
            encoded.Length,
            encoded,
            output,
            output.Length);

        Assert.Equal(1, result);

        Assert.Equal(
            Encoding.ASCII.GetBytes(expected),
            output[..Encoding.ASCII.GetByteCount(expected)]);
    }

    [Theory]
    [InlineData("TR==", "M")]
    [InlineData("TWF=", "Ma")]
    public void Decode_ShouldAcceptNonCanonicalTrailingBits(string input, string expected)
    {
        byte[] encoded = Encoding.ASCII.GetBytes(input);
        byte[] output = new byte[encoded.Length];

        int result = LobbyBase64.Decode(
            encoded.Length,
            encoded,
            output,
            output.Length);

        Assert.Equal(1, result);

        Assert.Equal(
            Encoding.ASCII.GetBytes(expected),
            output[..Encoding.ASCII.GetByteCount(expected)]);
    }

    [Theory]
    [InlineData("TQ==")]
    [InlineData("TWE=")]
    [InlineData("TWFu")]
    public void Decode_ShouldAcceptValidPadding(string input)
    {
        byte[] encoded = Encoding.ASCII.GetBytes(input);
        byte[] output = new byte[encoded.Length];

        int result = LobbyBase64.Decode(
            encoded.Length,
            encoded,
            output,
            output.Length);

        Assert.Equal(1, result);
    }

    [Theory]
    [InlineData("T")]
    [InlineData("TQ")]
    [InlineData("TWE")]
    [InlineData("TWF")]
    public void Decode_IncompleteBlock_ShouldFail(string input)
    {
        byte[] encoded = Encoding.ASCII.GetBytes(input);
        byte[] output = new byte[encoded.Length];

        int result = LobbyBase64.Decode(
            encoded.Length,
            encoded,
            output,
            output.Length);

        Assert.Equal(0, result);
    }

    [Theory]
    [InlineData("!!!!")]
    [InlineData("TW-F")]
    [InlineData("TW.F")]
    [InlineData("TW:F")]
    [InlineData("=AAA")]
    [InlineData("A=AA")]
    [InlineData("AA=A")]
    public void Decode_InvalidCharactersOrPadding_ShouldFail(
        string input)
    {
        byte[] encoded = Encoding.ASCII.GetBytes(input);
        byte[] output = new byte[encoded.Length];

        int result = LobbyBase64.Decode(
            encoded.Length,
            encoded,
            output,
            output.Length);

        Assert.Equal(0, result);
    }

    [Theory]
    [InlineData("TWFu!")]
    [InlineData("TWFuA")]
    public void Decode_InvalidTrailingData_ShouldFail(string input)
    {
        byte[] encoded = Encoding.ASCII.GetBytes(input);
        byte[] output = new byte[encoded.Length];

        int result = LobbyBase64.Decode(
            encoded.Length,
            encoded,
            output,
            output.Length);

        Assert.Equal(0, result);
    }

    [Fact]
    public void Decode_NullByteAtEnd_ShouldFail()
    {
        byte[] input =
        {
            (byte)'T', (byte)'W', (byte)'F', (byte)'u', 0
        };

        byte[] output = new byte[3];

        int result = LobbyBase64.Decode(
            input.Length,
            input,
            output,
            output.Length);

        Assert.Equal(0, result);
        Assert.Equal(Encoding.ASCII.GetBytes("Man"), output);
    }
    
    [Fact]
    public void Decode_NullByteBeforeInputEnd_ShouldFail()
    {
        byte[] input =
        {
            (byte)'T', (byte)'W', (byte)'F', (byte)'u',
            0,
            (byte)'T', (byte)'Q', (byte)'=', (byte)'='
        };

        byte[] output = new byte[6];

        int result = LobbyBase64.Decode(
            input.Length,
            input,
            output,
            output.Length);

        Assert.Equal(0, result);
    }

    [Fact]
    public void Decode_OutputBufferTooSmall_ShouldThrow()
    {
        byte[] input = Encoding.ASCII.GetBytes("TWFu");
        byte[] output = new byte[2];

        Assert.Throws<ArgumentException>(
            () => LobbyBase64.Decode(
                input.Length,
                input,
                output,
                output.Length));
    }

    [Fact]
    public void Decode_OutputBufferWithExtraCapacity_ShouldSucceed()
    {
        byte[] input = Encoding.ASCII.GetBytes("TWFu");
        byte[] output = new byte[10];

        int result = LobbyBase64.Decode(
            input.Length,
            input,
            output,
            output.Length);

        Assert.Equal(1, result);
        Assert.Equal(Encoding.ASCII.GetBytes("Man"), output[..3]);
    }

    [Fact]
    public void Decode_NullInput_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(
            () => LobbyBase64.Decode(0, null!, null, 0));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(4)]
    public void Decode_InvalidInputLength_ShouldThrow(int inputLength)
    {
        byte[] input = new byte[3];

        Assert.Throws<ArgumentOutOfRangeException>(
            () => LobbyBase64.Decode(inputLength, input, null, 0));
    }

    [Fact]
    public void Decode_InvalidOutputLength_ShouldThrow()
    {
        byte[] input = Encoding.ASCII.GetBytes("TWFu");
        byte[] output = new byte[3];

        Assert.Throws<ArgumentOutOfRangeException>(
            () => LobbyBase64.Decode(
                input.Length,
                input,
                output,
                4));
    }
}
