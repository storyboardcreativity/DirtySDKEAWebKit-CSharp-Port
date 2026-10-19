
using System;

namespace DirtySDKEAWebKit;

public sealed class GsPeerChat
{
    private byte _gsPeerChat1;
    private byte _gsPeerChat2;
    private readonly byte[] _crypt = new byte[256];

    public GsPeerChat(byte[] chall, byte[] gamekey)
    {
        Init(chall, gamekey);
    }

    public void Init(byte[] chall, byte[] gamekey)
    {
        ArgumentNullException.ThrowIfNull(chall);
        ArgumentNullException.ThrowIfNull(gamekey);

        if (chall.Length < 16)
            throw new ArgumentException("Challenge must contain at least 16 bytes.", nameof(chall));

        if (gamekey.Length == 0)
            throw new ArgumentException("Game key must not be empty.", nameof(gamekey));

        _gsPeerChat1 = 0;
        _gsPeerChat2 = 0;

        byte[] challenge = new byte[16];
        int keyIndex = 0;

        for (int i = 0; i < 16; i++)
        {
            if (keyIndex >= gamekey.Length || gamekey[keyIndex] == 0)
                keyIndex = 0;

            challenge[i] = (byte)(chall[i] ^ gamekey[keyIndex]);
            keyIndex++;
        }

        for (int i = 0; i < 256; i++)
            _crypt[i] = (byte)(255 - i);

        int t1 = 0;
        int challengeIndex = 0;

        for (int i = 0; i < 256; i++)
        {
            t1 = (t1 + challenge[challengeIndex] + _crypt[i]) & 0xFF;

            byte t = _crypt[t1];
            _crypt[t1] = _crypt[i];
            _crypt[i] = t;

            challengeIndex++;

            if (challengeIndex == 16)
                challengeIndex = 0;
        }
    }

    public void Process(byte[] data, int size)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (size < 0 || size > data.Length)
            throw new ArgumentOutOfRangeException(nameof(size));

        int num1 = _gsPeerChat1;
        int num2 = _gsPeerChat2;

        for (int i = 0; i < size; i++)
        {
            num1 = (num1 + 1) & 0xFF;

            byte t = _crypt[num1];

            num2 = (num2 + t) & 0xFF;

            _crypt[num1] = _crypt[num2];
            _crypt[num2] = t;

            t = (byte)(t + _crypt[num1]);

            data[i] ^= _crypt[t];
        }

        _gsPeerChat1 = (byte)num1;
        _gsPeerChat2 = (byte)num2;
    }
}
