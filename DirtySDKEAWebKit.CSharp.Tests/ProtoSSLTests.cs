using System;
using System.Text;
using System.Diagnostics;
using System.Buffers.Binary;
using Xunit;
using DirtySDKEAWebKit.CSharp;

namespace DirtySDKEAWebKit.Tests;

public class ProtoSSLTests
{
    private const string _serverAddress = "login.server.cnc-online.net";
    private const int _serverPort = 18840;
    private const int TimeoutMs = 30_000;

    [Fact]
    [Trait("Category", "Integration")]
    public void ShouldConnectAndCompleteHelloMemCheckExchange()
    {
        ProtoSSLRefT? ssl = ProtoSSL.ProtoSSLCreate();
        ProtoSSL.ProtoSSLReset(ssl!);
        ProtoSSL.ProtoSSLControl(ssl!, Tools.FourCC("ncrt"), 1);

        Assert.NotNull(ssl);

        try
        {
            int result = ProtoSSL.ProtoSSLConnect(ssl!, 1, _serverAddress, 0, _serverPort);
            Assert.Equal(DirtyNetPS3.SOCKERR_NONE, result);

            // Advance the connection/handshake state machine
            ProtoSSL.ProtoSSLUpdate(ssl!);

            string hello =
                "TXN=Hello\n" +
                "clientString=cncra3-pc\n" +
                "sku=15299\n" +
                "locale=ru\n" +
                "clientPlatform=PC\n" +
                "clientVersion=1.0\n" +
                "SDKVersion=4.3.4.0.0\n" +
                "protocolVersion=2.0\n" +
                "fragmentSize=8096\n" +
                "clientType=\n";

            SendFeslPacket(ssl!, "fsys", 0xC0000001, hello);

            string helloResponse = ReceiveFeslPacket(ssl!);
            Assert.False(string.IsNullOrEmpty(helloResponse),
                "The server returned an empty HELLO response.");

            string memCheckResponse = ReceiveFeslPacket(ssl!);
            Assert.False(string.IsNullOrEmpty(memCheckResponse),
                "The server returned an empty memcheck response.");

            string memCheck =
                "TXN=MemCheck\n" +
                "result=\n";

            SendFeslPacket(ssl!, "fsys", 0x00000080, memCheck);
        }
        finally
        {
            ProtoSSL.ProtoSSLDestroy(ssl!);
        }
    }

    private static void SendFeslPacket(
        ProtoSSLRefT ssl,
        string type,
        uint magic,
        string message)
    {
        byte[] body = Encoding.UTF8.GetBytes(message + '\0');
        byte[] packet = new byte[12 + body.Length];

        // Four ASCII bytes identifying the packet type
        Encoding.ASCII.GetBytes(type).CopyTo(packet, 0);

        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), magic);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8, 4), (uint)packet.Length);
        Buffer.BlockCopy(body, 0, packet, 12, body.Length);

        int sent = ProtoSSL.ProtoSSLSend(ssl, packet, packet.Length);
        if (sent < 0)
        {
            Tools.NetPrintf($"ProtoSSLSend failed with error {sent}.");
            throw new InvalidOperationException($"ProtoSSLSend failed with error {sent}.");
        }

        Assert.Equal(packet.Length, sent);
    }

    private static string ReceiveFeslPacket(ProtoSSLRefT ssl)
    {
        var stopwatch = Stopwatch.StartNew();
        byte[] header = new byte[12];
        int received = 0;

        // Read the complete 12-byte FESL header.
        while (received < header.Length)
        {
            EnsureNotTimedOut(stopwatch);

            ProtoSSL.ProtoSSLUpdate(ssl);

            byte[] chunk = new byte[header.Length - received];
            int count = ProtoSSL.ProtoSSLRecv(
                ssl, chunk, chunk.Length);

            if (count > 0)
            {
                Buffer.BlockCopy(
                    chunk, 0, header, received, count);
                received += count;
            }
            else if (count < -1)
            {
                throw new InvalidOperationException(
                    $"ProtoSSLRecv failed with error {count}.");
            }
            else
            {
                System.Threading.Thread.Sleep(10);
            }
        }

        uint packetSize = BinaryPrimitives.ReadUInt32BigEndian(
            header.AsSpan(8, 4));

        Assert.InRange(packetSize, 12u, 1024u * 1024u);

        int bodySize = checked((int)packetSize - 12);
        byte[] body = new byte[bodySize];
        received = 0;

        while (received < body.Length)
        {
            EnsureNotTimedOut(stopwatch);

            ProtoSSL.ProtoSSLUpdate(ssl);

            byte[] chunk = new byte[body.Length - received];
            int count = ProtoSSL.ProtoSSLRecv(
                ssl, chunk, chunk.Length);

            if (count > 0)
            {
                Buffer.BlockCopy(
                    chunk, 0, body, received, count);
                received += count;
            }
            else if (count < -1)
            {
                throw new InvalidOperationException(
                    $"ProtoSSLRecv failed with error {count}.");
            }
            else
            {
                System.Threading.Thread.Sleep(10);
            }
        }

        int textLength = Array.IndexOf(body, (byte)0);
        if (textLength < 0)
            textLength = body.Length;

        return Encoding.UTF8.GetString(body, 0, textLength);
    }

    private static void EnsureNotTimedOut(Stopwatch stopwatch)
    {
        Assert.True(
            stopwatch.ElapsedMilliseconds < TimeoutMs,
            $"Timed out after {TimeoutMs} ms waiting for server data.");
    }
}
