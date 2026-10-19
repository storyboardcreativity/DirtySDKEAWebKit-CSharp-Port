using System;
using Xunit;
using DirtySDKEAWebKit;

namespace DirtySDKEAWebKit.Tests;

public class CryptArc4Tests
{
    private static readonly byte[] Key = {1, 2, 3, 4, 5};

    [Fact]
    public void Test_EncryptDecrypt()
    {
        // Arrange
        byte[] original = System.Text.Encoding.UTF8.GetBytes(
            "Hello, CryptArc4!");

        byte[] encrypted = (byte[])original.Clone();

        var encryptor = new CryptArc4();
        encryptor.Init(Key, Key.Length, 1);
        encryptor.Apply(encrypted, encrypted.Length);

        Assert.NotEqual(original, encrypted);

        var decryptor = new CryptArc4();
        decryptor.Init(Key, Key.Length, 1);
        decryptor.Apply(encrypted, encrypted.Length);

        Assert.Equal(original, encrypted);
    }

    [Fact]
    public void Test_Advance()
    {
        byte[] data1 = new byte[100];
        byte[] data2 = new byte[50];

        var cipher1 = new CryptArc4();
        cipher1.Init(Key, Key.Length, 1);

        var cipher2 = new CryptArc4();
        cipher2.Init(Key, Key.Length, 1);

        cipher1.Apply(data1, data1.Length);

        cipher2.Advance(50);
        cipher2.Apply(data2, data2.Length);

        Assert.Equal(data1[50..], data2);
    }
}
