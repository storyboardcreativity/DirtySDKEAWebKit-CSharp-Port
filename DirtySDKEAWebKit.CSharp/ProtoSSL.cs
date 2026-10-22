using System;
using System.Net;
using System.Linq;
using System.Security.Cryptography;
using DirtySDKEAWebKit.CSharp;
using System.Net.Sockets;

namespace DirtySDKEAWebKit
{
    public static class ProtoSSLConstants
    {
        public const int SSL_MIN_PACKET = 5;
        public const int SSL_CRYPTO_PAD = 1024;
        public const int SSL_RAW_PACKET = 16384;
        public const int SSL_RCVMAX_PACKET =
            SSL_RAW_PACKET + SSL_CRYPTO_PAD;
        public const int SSL_SNDMAX_PACKET = SSL_RAW_PACKET;
        public const int SSL_SNDLIM_PACKET = SSL_SNDMAX_PACKET - 384;

        public const int SSL3_VERSION = 0x0300;

        public const byte SSL3_REC_CIPHER = 20;
        public const byte SSL3_REC_ALERT = 21;
        public const byte SSL3_REC_HANDSHAKE = 22;
        public const byte SSL3_REC_APPLICATION = 23;

        public const byte SSL3_MSG_CLIENT_HELLO = 1;
        public const byte SSL3_MSG_SERVER_HELLO = 2;
        public const byte SSL3_MSG_CERTIFICATE = 11;
        public const byte SSL3_MSG_SERVER_KEY = 12;
        public const byte SSL3_MSG_CERT_REQ = 13;
        public const byte SSL3_MSG_SERVER_DONE = 14;
        public const byte SSL3_MSG_CERT_VERIFY = 15;
        public const byte SSL3_MSG_CLIENT_KEY = 16;
        public const byte SSL3_MSG_FINISHED = 20;

        public const byte SSL3_MAC_NULL = 0;
        public const byte SSL3_MAC_MD5 = 16;
        public const byte SSL3_MAC_SHA = 20;

        public const byte SSL3_KEY_NULL = 0;
        public const byte SSL3_KEY_RSA = 1;

        public const byte SSL3_ENC_NULL = 0;
        public const byte SSL3_ENC_RC4 = 1;

        public const byte SSL3_ALERT_LEVEL_WARNING = 1;
        public const byte SSL3_ALERT_LEVEL_FATAL = 2;

        public const byte SSL3_ALERT_DESC_CLOSE_NOTIFY = 0;
        public const byte SSL3_ALERT_DESC_UNEXPECTED_MESSAGE = 10;
        public const byte SSL3_ALERT_DESC_BAD_RECORD_MAC = 20;
        public const byte SSL3_ALERT_DESC_DECOMPRESSION_FAILURE = 30;
        public const byte SSL3_ALERT_DESC_HANDSHAKE_FAILURE = 40;
        public const byte SSL3_ALERT_DESC_NO_CERTIFICATE = 41;
        public const byte SSL3_ALERT_DESC_BAD_CERTFICIATE = 42;
        public const byte SSL3_ALERT_DESC_UNSUPPORTED_CERTIFICATE = 43;
        public const byte SSL3_ALERT_DESC_CERTIFICATE_REVOKED = 44;
        public const byte SSL3_ALERT_DESC_CERTIFICATE_EXPIRED = 45;
        public const byte SSL3_ALERT_DESC_CERTIFICATE_UNKNOWN = 46;
        public const byte SSL3_ALERT_DESC_ILLEGAL_PARAMETER = 47;

        public const int ST_IDLE = 0;
        public const int ST_ADDR = 1;
        public const int ST_CONN = 2;
        public const int ST_WAIT = 3;

        public const int ST3_SEND_HELLO = 20;
        public const int ST3_RECV_HELLO = 21;
        public const int ST3_SEND_KEY = 22;
        public const int ST3_SEND_CHANGE = 23;
        public const int ST3_SEND_FINISH = 24;
        public const int ST3_RECV_CHANGE = 25;
        public const int ST3_RECV_FINISH = 26;
        public const int ST3_SECURE = 30;
        public const int ST_UNSECURE = 31;

        public const int ST_FAIL = 0x1000;
        public const int ST_FAIL_DNS = 0x1001;
        public const int ST_FAIL_CONN = 0x1002;
        public const int ST_FAIL_CERT = 0x1003;
        public const int ST_FAIL_SETUP = 0x1004;
        public const int ST_FAIL_SECURE = 0x1005;

        public const int ASN_CLASS_UNIV = 0x00;
        public const int ASN_CLASS_APPL = 0x40;
        public const int ASN_CLASS_CONT = 0x80;
        public const int ASN_CLASS_PRIV = 0xc0;

        public const int ASN_PRIMITIVE = 0x00;
        public const int ASN_CONSTRUCT = 0x20;

        public const int ASN_TYPE_INTEGER = 0x02;
        public const int ASN_TYPE_BITSTRING = 0x03;
        public const int ASN_TYPE_OCTSTRING = 0x04;
        public const int ASN_TYPE_NULL = 0x05;
        public const int ASN_TYPE_OBJECT = 0x06;
        public const int ASN_TYPE_UTF8STR = 0x0c;
        public const int ASN_TYPE_SEQN = 0x10;
        public const int ASN_TYPE_SET = 0x11;
        public const int ASN_TYPE_PRINTSTR = 0x13;
        public const int ASN_TYPE_T61 = 0x14;
        public const int ASN_TYPE_IA5 = 0x16;
        public const int ASN_TYPE_UTCTIME = 0x17;
        public const int ASN_TYPE_GENERALIZEDTIME = 0x18;
    }

    public sealed class ProtoSSLCertIdentT
    {
        public string strCountry = "";
        public string strState = "";
        public string strCity = "";
        public string strOrg = "";
        public string strUnit = "";
        public string strCommon = "";
    }

    public sealed class ProtoSSLCACertT
    {
        public ProtoSSLCertIdentT Subject = new();

        public int iKeyModSize;
        public byte[] pKeyModData = Array.Empty<byte>();

        public int iKeyExpSize;
        public byte[] KeyExpData = new byte[16];

        public int iMemGroup;
        public object? pMemGroupUserData;

        public ProtoSSLCACertT? pNext = null;
    }

    public sealed class X509CertificateT
    {
        public ProtoSSLCertIdentT Issuer = new();
        public ProtoSSLCertIdentT Subject = new();

        public string strGoodFrom = "";
        public string strGoodTill = "";

        public int iSerialSize;
        public byte[] SerialData = new byte[32];

        public int iSigType;
        public int iSigSize;
        public byte[] SigData = new byte[256];

        public int iKeyType;
        public int iKeyModSize;
        public byte[] KeyModData = new byte[256];

        public int iKeyExpSize;
        public byte[] KeyExpData = new byte[16];

        public int iHashSize;
        public byte[] HashData = new byte[20];
    }

    public sealed class CipherSuiteT
    {
        public byte[] uIdent = new byte[2];
        public byte uKey;
        public byte uEnc;
        public byte uMac;
    }

    public sealed class ProtoSSLSecureState
    {
        public uint uTimer;

        public uint uSendSeqn;
        public int iSendProg;
        public int iSendSize;

        public uint uRecvSeqn;
        public int iRecvProg;
        public int iRecvSize;
        public int iRecvBase;
        public int iRecvDone;

        public CipherSuiteT? pCipher = new CipherSuiteT();

        public byte[] ClientRandom = new byte[32];
        public byte[] ServerRandom = new byte[32];

        public byte[] PreMasterKey = new byte[48];
        public byte[] MasterKey = new byte[48];
        public byte[] KeyBlock = new byte[128];

        public byte[]? pServerMAC;
        public byte[]? pClientMAC;
        public byte[]? pServerKey;
        public byte[]? pClientKey;

        public CryptMD5 HandshakeMD5 = new CryptMD5();
        public CryptSHA1 HandshakeSHA = new CryptSHA1();
        public CryptArc4 ReadArc4 = new CryptArc4();
        public CryptArc4 WriteArc4 = new CryptArc4();

        public X509CertificateT Cert = new();

        public byte[] SendData = new byte[ProtoSSLConstants.SSL_SNDMAX_PACKET];
        public byte[] RecvData = new byte[ProtoSSLConstants.SSL_RCVMAX_PACKET];
    }

    public sealed class ProtoSSLRefT
    {
        public Socket? pSock = null;
        public DirtyNetPS3.HostentT? pHost = new DirtyNetPS3.HostentT();

        public int iMemGroup;
        public object? pMemGroupUserData;

        public string strHost = "";
        public System.Net.EndPoint? PeerAddr;

        public int iState;
        public int iClosed;

        public ProtoSSLSecureState? pSecure = new ProtoSSLSecureState();

        public byte bAllowAnyCert;
    }

    public sealed class ProtoSSL
    {
        public static ProtoSSLRefT? ProtoSSLCreate()
        {
            int iMemGroup = 0;
            object? pMemGroupUserData = null;

            //DirtyMem.DirtyMemGroupQuery(out iMemGroup, out pMemGroupUserData);

            ProtoSSLRefT pState;
            try
            {
                //pState = DirtyMemAlloc(...);
                pState = new ProtoSSLRefT();
            }
            catch (OutOfMemoryException)
            {
                // NetPrintf(("protossl: could not allocate module state\n"));
                return null;
            }

            pState.iMemGroup = iMemGroup;
            pState.pMemGroupUserData = pMemGroupUserData;

            return pState;
        }

        public static void ProtoSSLReset(ProtoSSLRefT pState)
        {
            _ResetState(pState, 0);
        }

        public static void ProtoSSLDestroy(ProtoSSLRefT pState)
        {
            _ResetState(pState, 0);

            // В C# сборщик мусора освобождает память объекта.
            // DirtyMemFree для самого pState не требуется.
        }

        public static int ProtoSSLBind(ProtoSSLRefT pState, EndPoint pAddr)
        {
            if (pState.pSock != null)
            {
                DirtyNetPS3.SocketClose(pState.pSock);
                pState.pSock = null;
            }

            pState.pSock = DirtyNetPS3.SocketOpen(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
            if (pState.pSock == null)
                return DirtyNetPS3.SOCKERR_OTHER;

            return DirtyNetPS3.SocketBind(pState.pSock, pAddr);
        }

        public static int ProtoSSLConnect(ProtoSSLRefT pState, int iSecure, string? pAddr, uint uAddr, int iPort)
        {
            int iError = _ResetState(pState, iSecure);
            if (iError != DirtyNetPS3.SOCKERR_NONE)
            {
                return iError;
            }

            pState.pSock = DirtyNetPS3.SocketOpen(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);

            if (pState.pSock == null)
            {
                return DirtyNetPS3.SOCKERR_NORSRC;
            }

            pAddr ??= string.Empty;

            int iColon = pAddr.IndexOf(':');
            int iHostEnd = iColon >= 0 ? iColon : pAddr.Length;
            int iHostLength = Math.Min(iHostEnd, 255);

            pState.strHost = pAddr.Substring(0, iHostLength);

            IPAddress ipAddress = IPAddress.Any;
            if (IPAddress.TryParse(pState.strHost, out IPAddress? parsedAddress))
            {
                ipAddress = parsedAddress;
            }

            if (ipAddress.Equals(IPAddress.Any) && uAddr != 0)
            {
                ipAddress = new IPAddress((long)uAddr);
            }

            int iPortValue;

            if (iColon >= 0 && iColon < 255)
            {
                iPortValue = _ParseAtoi(pAddr.Substring(iColon + 1));
            }
            else
            {
                iPortValue = iPort;
            }

            pState.PeerAddr = new IPEndPoint(ipAddress, iPortValue);

            if (ipAddress.Equals(IPAddress.Any))
            {
                pState.pHost = DirtyNetPS3.SocketLookup(pState.strHost, 30 * 1000);

                pState.iState = ProtoSSLConstants.ST_ADDR;
            }
            else
            {
                pState.iState = ProtoSSLConstants.ST_CONN;
            }

            return DirtyNetPS3.SOCKERR_NONE;
        }

        public static int ProtoSSLListen(ProtoSSLRefT pState, int iBacklog)
        {
            if (pState.pSock == null)
                return DirtyNetPS3.SOCKERR_INVALID;
            return DirtyNetPS3.SocketListen(pState.pSock, iBacklog);
        }

        public static int ProtoSSLDisconnect(ProtoSSLRefT pState)
        {
            //if (DEBUG_ENC_PERF && pState.pSecure != null && pState.pSecure.uTimer != 0)
            //{
            //    Tools.NetPrintf($"protossl: SSL Perf: closed {Tools.NetTick() - pState.pSecure.uTimer}ms");
            //    pState.pSecure.uTimer = 0;
            //}

            _ResetState(pState, pState.pSecure != null ? 1 : 0);
            return DirtyNetPS3.SOCKERR_NONE;
        }

        private static int _ProtoSSLUpdateSendClientHello(ProtoSSLRefT pState)
        {
            ProtoSSLSecureState pSecure = pState.pSecure
                ?? throw new InvalidOperationException("Secure state is not initialized.");

            byte[] strHead = new byte[4];
            byte[] strBody = new byte[256];
            int offset = 0;

        #if DEBUG_ENC_PERF
            pSecure.uTimer = Tools.NetTick();
        #endif

            // SSL3_VERSION (big-endian)
            strBody[offset++] = (byte)(ProtoSSLConstants.SSL3_VERSION >> 8);
            strBody[offset++] = (byte)(ProtoSSLConstants.SSL3_VERSION & 0xFF);

            // Generate and append client random.
            _GenerateRandom(
                pSecure.ClientRandom,
                pSecure.ClientRandom.Length,
                pSecure.ReadArc4);

            Buffer.BlockCopy(
                pSecure.ClientRandom, 0,
                strBody, offset,
                pSecure.ClientRandom.Length);

            offset += 32;

            // Session ID length = 0.
            strBody[offset++] = 0;

            // Cipher suites length (in bytes).
            strBody[offset++] = 0;
            strBody[offset++] = (byte)(_SSL3_CipherSuite.Length * 2);

            for (int i = 0; i < _SSL3_CipherSuite.Length; ++i)
            {
                strBody[offset++] = _SSL3_CipherSuite[i].uIdent[0];
                strBody[offset++] = _SSL3_CipherSuite[i].uIdent[1];
            }

            // Compression methods: one method, null compression.
            strBody[offset++] = 1;
            strBody[offset++] = 0;

            // Handshake header.
            strHead[0] = ProtoSSLConstants.SSL3_MSG_CLIENT_HELLO;
            strHead[1] = 0;
            strHead[2] = (byte)((offset >> 8) & 0xFF);
            strHead[3] = (byte)(offset & 0xFF);

            _SendPacket(
                pState,
                ProtoSSLConstants.SSL3_REC_HANDSHAKE,
                strHead,
                strHead.Length,
                strBody,
                offset);

            return ProtoSSLConstants.ST3_RECV_HELLO;
        }

        private static int _ProtoSSLUpdateRecvServerHello(ProtoSSLRefT pState, byte[] pData)
        {
            ProtoSSLSecureState pSecure = pState.pSecure
                ?? throw new InvalidOperationException("Secure state is not initialized.");

        #if DEBUG_MSG_LIST
            NetPrintf("protossl: SSL Msg: Process Server Hello\n");
        #endif

            if ((pData[0] != (byte)(ProtoSSLConstants.SSL3_VERSION >> 8)) ||
                (pData[1] != (byte)(ProtoSSLConstants.SSL3_VERSION & 255)))
            {
        #if DEBUG_MSG_LIST
                NetPrintf($"protossl: _ServerHello: version {pData[0]},{pData[1]}\n");
        #endif
                return ProtoSSLConstants.ST_FAIL_SETUP;
            }

            int iOffset = 2;

            Buffer.BlockCopy(pData, iOffset, pSecure.ServerRandom, 0, pSecure.ServerRandom.Length);
            iOffset += 32;

            // Skip session ID: its length is stored in the first byte
            iOffset += pData[iOffset] + 1;

            pSecure.pCipher = null;

            for (int iIndex = 0; iIndex < _SSL3_CipherSuite.Length; ++iIndex)
            {
                CipherSuiteT cipher = _SSL3_CipherSuite[iIndex];

                if ((pData[iOffset] == cipher.uIdent[0]) &&
                    (pData[iOffset + 1] == cipher.uIdent[1]))
                {
                    pSecure.pCipher = cipher;
                    break;
                }
            }

        #if DEBUG_MSG_LIST
            if (pSecure.pCipher == null)
            {
                NetPrintf($"protossl: SSL Msg: No matching cipher (ident={pData[iOffset]},{pData[iOffset + 1]})\n");
            }
            else
            {
                NetPrintf(
                    $"protossl: SSL Msg: Cipher {pData[iOffset]},{pData[iOffset + 1]} selected " +
                    $"(enc={pSecure.pCipher.uEnc} mac={pSecure.pCipher.uMac})\n");
            }
        #endif

            return ProtoSSLConstants.ST3_RECV_HELLO;
        }

        private static int _ProtoSSLUpdateRecvServerCert(ProtoSSLRefT pState, byte[] pData)
        {
            ProtoSSLSecureState pSecure = pState.pSecure
                ?? throw new InvalidOperationException("Secure state is not initialized.");

        #if DEBUG_MSG_LIST
            NetPrintf("protossl: SSL Msg: Process Server Cert\n");
        #endif

            int iSize1 = (pData[0] << 16) | (pData[1] << 8) | pData[2];
            int iSize2 = (pData[3] << 16) | (pData[4] << 8) | pData[5];

            if (iSize2 > iSize1 - 3)
            {
                Tools.NetPrintf($"protossl: _ServerCert: first certificate is larger than envelope ({iSize1}/{iSize2})\n");
                return ProtoSSLConstants.ST_FAIL_SETUP;
            }

            // В C: pData + 6, iSize2.
            // В C# передаём срез, начиная со смещения 6.
            byte[] certData = pData.AsSpan(6, iSize2).ToArray();

            int iParse = _ParseCertificate(pSecure.Cert, certData, iSize2);

            if (iParse < 0)
            {
                Tools.NetPrintf($"protossl: _ServerCert: x509 cert invalid (error={iParse})\n");
                return ProtoSSLConstants.ST_FAIL_CERT;
            }

            if (pState.bAllowAnyCert == 0)
            {
                if (_WildcardMatchNoCase(
                        pState.strHost,
                        pSecure.Cert.Subject.strCommon) != 0)
                {
                    Tools.NetPrintf(
                        $"protossl: _ServerCert: certificate not issued to this host " +
                        $"({pState.strHost} != {pSecure.Cert.Subject.strCommon})\n");

                    return ProtoSSLConstants.ST_FAIL_CERT;
                }

                iParse = _VerifyCertificate(pSecure.Cert, 0);

                if (iParse < 0)
                {
                    Tools.NetPrintf($"protossl: _ServerCert: x509 cert untrusted (error={iParse})\n");
                    return ProtoSSLConstants.ST_FAIL_CERT;
                }
            }

            return ProtoSSLConstants.ST3_RECV_HELLO;
        }

        private static int _ProtoSSLUpdateRecvServerKey(ProtoSSLRefT pState, byte[] pData)
        {
        #if DEBUG_MSG_LIST
            NetPrintf("protossl: SSL Msg: Process Server Key\n");
        #endif

            if (pData[0] != 1)
            {
                Tools.NetPrintf($"protossl: _ServerKey: wrong key alg {pData[0]}\n");
                return ProtoSSLConstants.ST_FAIL_SETUP;
            }

            return ProtoSSLConstants.ST3_RECV_HELLO;
        }

        private static int _ProtoSSLUpdateRecvServerDone(ProtoSSLRefT pState, byte[] pData)
        {
        #if DEBUG_MSG_LIST
            NetPrintf("protossl: SSL Msg: Process Server Done\n");
        #endif

            return ProtoSSLConstants.ST3_SEND_KEY;
        }

        private static int _ProtoSSLUpdateSendClientKey(ProtoSSLRefT pState)
        {
            ProtoSSLSecureState pSecure = pState.pSecure
                ?? throw new InvalidOperationException("Secure state is not initialized.");

        #if DEBUG_ENC_PERF
            uint uTick = NetTick();
        #endif

        #if DEBUG_MSG_LIST
            NetPrintf("protossl: SSL Msg: Send Client Key\n");
        #endif

            // Generate PreMasterKey
            _GenerateRandom(
                pSecure.PreMasterKey,
                pSecure.PreMasterKey.Length,
                pSecure.ReadArc4);

            pSecure.PreMasterKey[0] = (byte)(ProtoSSLConstants.SSL3_VERSION >> 8);
            pSecure.PreMasterKey[1] = (byte)(ProtoSSLConstants.SSL3_VERSION & 255);

            // Encrypt PreMasterKey using the server's RSA public key
            var RSAContext = new CryptRSA();

            RSAContext.Init(
                pSecure.Cert.KeyModData,
                pSecure.Cert.iKeyModSize,
                pSecure.Cert.KeyExpData,
                pSecure.Cert.iKeyExpSize);

            RSAContext.InitMaster(
                pSecure.PreMasterKey,
                pSecure.PreMasterKey.Length);

            RSAContext.Encrypt();

        #if DEBUG_ENC_PERF
            NetPrintf($"protossl: SSL Perf: RSA Key {NetTick() - uTick}ms\n");
        #endif

            byte[] strBody = new byte[256];

            // Generate MasterKey (48 bytes)
            for (int iLoop = 0; iLoop < 3; ++iLoop)
            {
                var MD5Context = new CryptMD5();
                var SHA1Context = new CryptSHA1();

                MD5Context.Init();
                MD5Context.Update(pSecure.PreMasterKey, pSecure.PreMasterKey.Length);

                strBody[0] = strBody[1] = strBody[2] = (byte)('A' + iLoop);

                SHA1Context.Init();
                SHA1Context.Update(strBody, (uint)(iLoop + 1));
                SHA1Context.Update(pSecure.PreMasterKey, (uint)pSecure.PreMasterKey.Length);
                SHA1Context.Update(pSecure.ClientRandom, (uint)pSecure.ClientRandom.Length);
                SHA1Context.Update(pSecure.ServerRandom, (uint)pSecure.ServerRandom.Length);
                SHA1Context.Final(strBody, 20);

                MD5Context.Update(strBody, 20);
                byte[] hash = new byte[16];
                MD5Context.Final(hash, 16);
                Buffer.BlockCopy(hash, 0, pSecure.MasterKey, iLoop * 16, 16);
            }

        #if DEBUG_RAW_DATA
            NetPrintMem(pSecure.PreMasterKey, pSecure.PreMasterKey.Length, "PreMaster");
            NetPrintMem(pSecure.MasterKey, pSecure.MasterKey.Length, "Master");
        #endif

            Array.Clear(pSecure.PreMasterKey, 0, pSecure.PreMasterKey.Length);

            // Generate KeyBlock
            for (int iLoop = 0; iLoop < pSecure.KeyBlock.Length / 16; ++iLoop)
            {
                var MD5Context = new CryptMD5();
                var SHA1Context = new CryptSHA1();

                MD5Context.Init();
                MD5Context.Update(pSecure.MasterKey, pSecure.MasterKey.Length);

                Array.Fill(strBody, (byte)('A' + iLoop), 0, iLoop + 1);

                SHA1Context.Init();
                SHA1Context.Update(strBody, (uint)(iLoop + 1));
                SHA1Context.Update(pSecure.MasterKey, (uint)pSecure.MasterKey.Length);
                SHA1Context.Update(pSecure.ServerRandom, (uint)pSecure.ServerRandom.Length);
                SHA1Context.Update(pSecure.ClientRandom, (uint)pSecure.ClientRandom.Length);
                SHA1Context.Final(strBody, 20);

                MD5Context.Update(strBody, 20);
                byte[] hash = new byte[16];
                MD5Context.Final(hash, 16);
                Buffer.BlockCopy(hash, 0, pSecure.KeyBlock, iLoop * 16, 16);
            }

        #if DEBUG_RAW_DATA
            NetPrintMem(pSecure.KeyBlock, pSecure.KeyBlock.Length, "Key Block");
        #endif

            // Assign MAC keys and encryption keys
            int iOffset = 0;

            pSecure.pClientMAC = pSecure.KeyBlock.AsSpan(
                iOffset, pSecure.pCipher!.uMac).ToArray();
            iOffset += pSecure.pCipher.uMac;

            pSecure.pServerMAC = pSecure.KeyBlock.AsSpan(
                iOffset, pSecure.pCipher.uMac).ToArray();
            iOffset += pSecure.pCipher.uMac;

            pSecure.pClientKey = pSecure.KeyBlock.AsSpan(iOffset, 16).ToArray();
            iOffset += 16;

            pSecure.pServerKey = pSecure.KeyBlock.AsSpan(iOffset, 16).ToArray();

            // Build and send Client Key handshake message
            byte[] strHead = new byte[4];

            strHead[0] = ProtoSSLConstants.SSL3_MSG_CLIENT_KEY;
            strHead[1] = 0;
            strHead[2] = (byte)(pSecure.Cert.iKeyModSize >> 8);
            strHead[3] = (byte)(pSecure.Cert.iKeyModSize >> 0);

            _SendPacket(
                pState,
                ProtoSSLConstants.SSL3_REC_HANDSHAKE,
                strHead,
                strHead.Length,
                RSAContext.EncryptBlock,
                pSecure.Cert.iKeyModSize);

            return ProtoSSLConstants.ST3_SEND_CHANGE;
        }

        private static int _ProtoSSLUpdateSendChange(ProtoSSLRefT pState)
        {
            ProtoSSLSecureState pSecure = pState.pSecure
                ?? throw new InvalidOperationException("Secure state is not initialized.");

        #if DEBUG_MSG_LIST
            NetPrintf("protossl: SSL Msg: Send Cipher Change\n");
        #endif

            pSecure.WriteArc4.Init(
                pSecure.pClientKey!,
                16,
                1);

            byte[] strHead = new byte[4];
            strHead[0] = 1;

            _SendPacket(
                pState,
                ProtoSSLConstants.SSL3_REC_CIPHER,
                strHead,
                1,
                null,
                0);

            pSecure.uSendSeqn = 0;

            return ProtoSSLConstants.ST3_SEND_FINISH;
        }

        private static int _ProtoSSLUpdateSendAlert(ProtoSSLRefT pState, int iLevel, int iDescription)
        {
        #if DEBUG_MSG_LIST
            NetPrintf($"protossl: SSL Msg: Send Alert: level={iLevel} desc={iDescription}\n");
        #endif

            byte[] strHead = new byte[4];

            strHead[0] = (byte)iLevel;
            strHead[1] = (byte)iDescription;

            _SendPacket(
                pState,
                ProtoSSLConstants.SSL3_REC_ALERT,
                strHead,
                2,
                null,
                0);

            return pState.iState;
        }

        private static int _ProtoSSLUpdateSendClientFinish(ProtoSSLRefT pState)
        {
            byte[] strHead = new byte[4];
            byte[] strBody = new byte[256];
            CryptMD5 MD5Context = new CryptMD5();
            CryptSHA1 SHAContext = new CryptSHA1();
            byte[] MacTemp = new byte[20];

            ProtoSSLSecureState pSecure = pState.pSecure!;

            #if DEBUG_MSG_LIST
            NetPrintf("protossl: SSL Msg: Send Client Finished\n");
            #endif

            // Calculate MD5 handshake finish
            // memcpy(&MD5Context, &pSecure->HandshakeMD5, sizeof(MD5Context));
            MD5Context = pSecure.HandshakeMD5.Clone();
            MD5Context.Update(System.Text.Encoding.ASCII.GetBytes("CLNT"), 4);
            MD5Context.Update(pSecure.MasterKey, pSecure.MasterKey.Length);
            MD5Context.Update(_SSL3_Pad1, 48);
            MD5Context.Final(MacTemp, 16);

            MD5Context.Init();
            MD5Context.Update(pSecure.MasterKey, pSecure.MasterKey.Length);
            MD5Context.Update(_SSL3_Pad2, 48);
            MD5Context.Update(MacTemp, 16);
            MD5Context.Final(strBody, 16);

        #if DEBUG_RAW_DATA
            Tools.NetPrintMem(strBody, 16, "HS finish MD5");
        #endif

            // Calculate SHA-1 handshake finish
            // memcpy(&SHAContext, &pSecure->HandshakeSHA, sizeof(SHAContext));
            SHAContext = pSecure.HandshakeSHA.Clone();

            SHAContext.Update(System.Text.Encoding.ASCII.GetBytes("CLNT"), 4);
            SHAContext.Update(pSecure.MasterKey, (uint)pSecure.MasterKey.Length);
            SHAContext.Update(_SSL3_Pad1, 40);
            SHAContext.Final(MacTemp, 20);

            SHAContext.Init();
            SHAContext.Update(pSecure.MasterKey, (uint)pSecure.MasterKey.Length);
            SHAContext.Update(_SSL3_Pad2, 40);
            SHAContext.Update(MacTemp, 20);
            byte[] shaHash = new byte[20];
            SHAContext.Final(shaHash, 20);
            Array.Copy(shaHash, 0, strBody, 16, 20);

        #if DEBUG_RAW_DATA
            Tools.NetPrintMem(strBody, 20, "HS finish SHA");
        #endif

            // Build Finished handshake message.
            strHead[0] = ProtoSSLConstants.SSL3_MSG_FINISHED;
            strHead[1] = 0;
            strHead[2] = 0;
            strHead[3] = 16 + 20;

            _SendPacket(
                pState,
                ProtoSSLConstants.SSL3_REC_HANDSHAKE,
                strHead,
                4,
                strBody,
                16 + 20);

            return ProtoSSLConstants.ST3_RECV_CHANGE;
        }

        private static int _ProtoSSLUpdateRecvChange(ProtoSSLRefT pState, byte[] pData)
        {
            ProtoSSLSecureState pSecure = pState.pSecure!;

        #if DEBUG_MSG_LIST
            Tools.NetPrintf("protossl: SSL Msg: Process Cipher Change\n");
        #endif

            pSecure.ReadArc4.Init(pSecure.pServerKey, 16, 1);
            pSecure.uRecvSeqn = 0;

            return ProtoSSLConstants.ST3_RECV_FINISH;
        }

        private static int _ProtoSSLUpdateRecvServerFinish(ProtoSSLRefT pState, byte[] pData)
        {
            byte[] MacTemp = new byte[20];
            byte[] strMD5 = new byte[16];
            byte[] strSHA = new byte[20];

            ProtoSSLSecureState pSecure = pState.pSecure!;

        #if DEBUG_MSG_LIST
            Tools.NetPrintf("protossl: SSL Msg: Process Client Finish\n");
        #endif

            // Calculate server MD5 handshake verification
            var MD5Context = pSecure.HandshakeMD5.Clone();
            MD5Context.Update(System.Text.Encoding.ASCII.GetBytes("SRVR"), 4);
            MD5Context.Update(pSecure.MasterKey, pSecure.MasterKey.Length);
            MD5Context.Update(_SSL3_Pad1, 48);
            MD5Context.Final(MacTemp, 16);

            MD5Context.Init();
            MD5Context.Update(pSecure.MasterKey, pSecure.MasterKey.Length);
            MD5Context.Update(_SSL3_Pad2, 48);
            MD5Context.Update(MacTemp, 16);
            MD5Context.Final(strMD5, 16);

            // Calculate server SHA-1 handshake verification
            var SHAContext = pSecure.HandshakeSHA.Clone();
            SHAContext.Update(System.Text.Encoding.ASCII.GetBytes("SRVR"), 4);
            SHAContext.Update(pSecure.MasterKey, (uint)pSecure.MasterKey.Length);
            SHAContext.Update(_SSL3_Pad1, 40);
            SHAContext.Final(MacTemp, 20u);

            SHAContext.Init();
            SHAContext.Update(pSecure.MasterKey, (uint)pSecure.MasterKey.Length);
            SHAContext.Update(_SSL3_Pad2, 40);
            SHAContext.Update(MacTemp, 20);
            SHAContext.Final(strSHA, 20u);

            // Compare calculated hashes against received data
            if (!strMD5.AsSpan().SequenceEqual(pData.AsSpan(0, 16)) ||
                !strSHA.AsSpan().SequenceEqual(pData.AsSpan(16, 20)))
            {
                //Tools.NetPrintMem(strMD5, strMD5.Length, "Server Final MD5 Calc");
                //Tools.NetPrintMem(pData, 16, "Server Final MD5 Recv");
                //Tools.NetPrintMem(strSHA, strSHA.Length, "Server Final SHA Calc");
                //Tools.NetPrintMem(pData.AsSpan(16, 20).ToArray(), 20, "Server Final SHA Recv");

                return ProtoSSLConstants.ST_FAIL_SETUP;
            }

        #if DEBUG_ENC_PERF
            {
                uint uTick = Tools.NetTick();
                Tools.NetPrintf($"protossl: SSL Perf: setup {uTick - pSecure.uTimer}ms\n");
                pSecure.uTimer = uTick;
            }
        #endif

            return ProtoSSLConstants.ST3_SECURE;
        }

        public static void ProtoSSLUpdate(ProtoSSLRefT pState)
        {
            int iXfer;
            int iResult;
            byte[]? pData;
            ProtoSSLSecureState? pSecure = pState.pSecure;

            // Resolve hostname
            if (pState.iState == ProtoSSLConstants.ST_ADDR)
            {
                if (pState.pHost != null && pState.pHost.Status != 0)
                {
                    if (pState.pHost!.Address == null)
                    {
                        pState.iState = ProtoSSLConstants.ST_FAIL_DNS;
                    }
                    else
                    {
                        pState.iState = ProtoSSLConstants.ST_CONN;
                        DirtyNet.SockaddrInSetAddr(ref pState.PeerAddr, pState.pHost.Address);
                    }

                    pState.pHost = null;
                }
            }

            // Initiate connection
            if (pState.iState == ProtoSSLConstants.ST_CONN)
            {
                Tools.NetPrintf("SocketConnect");
                DirtyNetPS3.SocketConnect(pState.pSock!, pState.PeerAddr!);
                pState.iState = ProtoSSLConstants.ST_WAIT;
            }

            // Preserve original timing behavior
            Thread.Sleep(500);

            // Wait for connection
            if (pState.iState == ProtoSSLConstants.ST_WAIT)
            {
                iResult = DirtyNetPS3.SocketInfo(pState.pSock!, Tools.FourCC("stat"), 0, IntPtr.Zero, 0);
                Tools.NetPrintf($"SocketInfo iResult == {iResult}");

                if (iResult > 0)
                {
                    pState.iState = pSecure != null
                        ? ProtoSSLConstants.ST3_SEND_HELLO
                        : ProtoSSLConstants.ST_UNSECURE;

                    pState.iClosed = 0;
                }

                if (iResult < 0)
                {
                    pState.iState = ProtoSSLConstants.ST_FAIL_CONN;
                    pState.iClosed = 1;
                }
            }

            // SSL handshake and secure data processing
            while (pState.pSock != null &&
                pState.iState >= ProtoSSLConstants.ST3_SEND_HELLO &&
                pState.iState <= ProtoSSLConstants.ST3_SECURE)
            {
                pSecure = pState.pSecure;

                if (pSecure == null)
                    break;

                iXfer = 0;

                // Generate the next outgoing SSL message
                if (pSecure.iSendProg == pSecure.iSendSize)
                {
                    if (pState.iState == ProtoSSLConstants.ST3_SEND_HELLO)
                    {
                        pState.iState = _ProtoSSLUpdateSendClientHello(pState);
                    }
                    else if (pState.iState == ProtoSSLConstants.ST3_SEND_KEY)
                    {
                        pState.iState = _ProtoSSLUpdateSendClientKey(pState);
                    }
                    else if (pState.iState == ProtoSSLConstants.ST3_SEND_CHANGE)
                    {
                        pState.iState = _ProtoSSLUpdateSendChange(pState);
                    }
                    else if (pState.iState == ProtoSSLConstants.ST3_SEND_FINISH)
                    {
                        pState.iState = _ProtoSSLUpdateSendClientFinish(pState);
                    }
                }

                // Send pending bytes
                if (pSecure.iSendProg < pSecure.iSendSize)
                {
                    Tools.NetPrintf("SocketSend");

                    int remaining = pSecure.iSendSize - pSecure.iSendProg;

                    byte[] sendBuffer = pSecure.SendData
                        .AsSpan(pSecure.iSendProg, remaining)
                        .ToArray();

                    iResult = DirtyNetPS3.SocketSend(pState.pSock!, sendBuffer, sendBuffer.Length, 0);
                    if (iResult > 0)
                    {
                        pSecure.iSendProg += iResult;
                        iXfer = 1;
                    }

                    if (pSecure.iSendProg == pSecure.iSendSize)
                    {
                        pSecure.iSendProg = 0;
                        pSecure.iSendSize = 0;
                    }
                }

                Thread.Sleep(500);

                // Receive the initial SSL record header
                if (pSecure.iRecvSize < ProtoSSLConstants.SSL_MIN_PACKET)
                {
                    int remaining =
                        ProtoSSLConstants.SSL_MIN_PACKET - pSecure.iRecvSize;

                    byte[] recvBuffer = new byte[remaining];

                    iResult = DirtyNetPS3.SocketRecv(pState.pSock!, recvBuffer, remaining, 0);
                    if (iResult > 0)
                    {
                        Array.Copy(recvBuffer, 0, pSecure.RecvData, pSecure.iRecvSize, iResult);
                        pSecure.iRecvSize += iResult;
                        pSecure.iRecvProg = pSecure.iRecvSize;
                    }

                    if (iResult < 0)
                    {
                        pState.iClosed = 1;
                    }
                }

                // Determine the complete SSL record size
                if (pSecure.iRecvSize == ProtoSSLConstants.SSL_MIN_PACKET)
                {
                    if (pSecure.RecvData[1] !=
                            (ProtoSSLConstants.SSL3_VERSION >> 8) ||
                        pSecure.RecvData[2] !=
                            (ProtoSSLConstants.SSL3_VERSION & 255))
                    {
                        pSecure.RecvData[3] = 0;
                        pSecure.RecvData[4] = 0;
                    }

                    pSecure.iRecvSize +=
                        (pSecure.RecvData[3] << 8) |
                        pSecure.RecvData[4];

                    if (pSecure.iRecvSize > ProtoSSLConstants.SSL_RCVMAX_PACKET)
                    {
                        Tools.NetPrintf(
                            $"protossl: received oversized packet " +
                            $"({pSecure.iRecvSize}/" +
                            $"{ProtoSSLConstants.SSL_RCVMAX_PACKET}); " +
                            "terminating connection\n");

                        pState.iClosed = 1;

                        pSecure.iRecvProg = 0;
                        pSecure.iRecvSize = 0;
                        pSecure.iRecvBase = 0;
                        pSecure.iRecvDone = 0;

                        pState.iState = ProtoSSLConstants.ST_FAIL_SECURE;
                    }
                }

                // Receive the remaining record bytes
                if (pSecure.iRecvProg < pSecure.iRecvSize)
                {
                    int remaining = pSecure.iRecvSize - pSecure.iRecvProg;
                    byte[] recvBuffer = new byte[remaining];
                    iResult = DirtyNetPS3.SocketRecv(pState.pSock!, recvBuffer, remaining, 0);
                    if (iResult > 0)
                    {
                        Array.Copy(
                            recvBuffer, 0,
                            pSecure.RecvData, pSecure.iRecvProg,
                            iResult);

                        pSecure.iRecvProg += iResult;
                        iXfer = 1;

                        if (pSecure.iRecvProg == pSecure.iRecvSize)
                        {
                            iResult = _RecvPacket(pState);
                        }
                    }

                    if (iResult < 0)
                    {
                        pState.iClosed = 1;

                        if (pState.pSecure != null &&
                            pState.pSecure.uTimer != 0)
                        {
                            Tools.NetPrintf(
                                $"protossl: SSL Perf: closed " +
                                $"{Tools.NetTick() - pState.pSecure.uTimer}ms\n");

                            pState.pSecure.uTimer = 0;
                        }
                    }
                }

                // Process a complete received record
                if (pSecure.iRecvProg == pSecure.iRecvSize && pSecure.iRecvBase < pSecure.iRecvSize)
                {
                    if (pSecure.RecvData[0] == ProtoSSLConstants.SSL3_REC_ALERT)
                    {
                        if (pSecure.RecvData[5] == ProtoSSLConstants.SSL3_ALERT_LEVEL_WARNING &&
                            pSecure.RecvData[6] == ProtoSSLConstants.SSL3_ALERT_DESC_CLOSE_NOTIFY)
                        {
                            pState.iClosed = 1;

                            pSecure.iRecvProg = 0;
                            pSecure.iRecvSize = 0;
                            pSecure.iRecvBase = 0;
                            pSecure.iRecvDone = 0;

                            if (pState.pSecure != null &&
                                pState.pSecure.uTimer != 0)
                            {
                                Tools.NetPrintf(
                                    $"protossl: SSL Perf: closed " +
                                    $"{Tools.NetTick() - pState.pSecure.uTimer}ms\n");

                                pState.pSecure.uTimer = 0;
                            }
                        }
                        else
                        {
                            //_DebugAlert(pState, pSecure.RecvData[5], pSecure.RecvData[6]);
                            pState.iState = ProtoSSLConstants.ST_FAIL_SETUP;
                        }
                    }
                    else if (pState.iState == ProtoSSLConstants.ST3_RECV_HELLO)
                    {
                        pData = _RecvHandshake(pState, ProtoSSLConstants.SSL3_MSG_SERVER_HELLO);

                        if (pData != null)
                        {
                            pState.iState = _ProtoSSLUpdateRecvServerHello(pState, pData);
                        }
                        else if ((pData = _RecvHandshake(pState, ProtoSSLConstants.SSL3_MSG_CERTIFICATE)) != null)
                        {
                            pState.iState = _ProtoSSLUpdateRecvServerCert(pState, pData);
                        }
                        else if ((pData = _RecvHandshake(pState, ProtoSSLConstants.SSL3_MSG_SERVER_KEY)) != null)
                        {
                            pState.iState = _ProtoSSLUpdateRecvServerKey(pState, pData);
                        }
                        else if ((pData = _RecvHandshake(pState, ProtoSSLConstants.SSL3_MSG_CERT_REQ)) != null)
                        {
                            pState.iState = _ProtoSSLUpdateSendAlert(
                                pState,
                                ProtoSSLConstants.SSL3_ALERT_LEVEL_WARNING,
                                ProtoSSLConstants.SSL3_ALERT_DESC_NO_CERTIFICATE);
                        }
                        else if ((pData = _RecvHandshake(pState, ProtoSSLConstants.SSL3_MSG_SERVER_DONE)) != null)
                        {
                            pState.iState = _ProtoSSLUpdateRecvServerDone(pState, pData);
                        }
                    }
                    else if (pState.iState == ProtoSSLConstants.ST3_RECV_CHANGE)
                    {
                        if (pSecure.RecvData[0] == ProtoSSLConstants.SSL3_REC_CIPHER)
                        {
                            byte[] changeData = pSecure.RecvData
                                .AsSpan(pSecure.iRecvBase)
                                .ToArray();

                            pState.iState =
                                _ProtoSSLUpdateRecvChange(pState, changeData);

                            pSecure.iRecvBase = pSecure.iRecvSize;
                        }
                    }
                    else if (pState.iState == ProtoSSLConstants.ST3_RECV_FINISH)
                    {
                        pData = _RecvHandshake(pState, ProtoSSLConstants.SSL3_MSG_FINISHED);
                        if (pData != null)
                        {
                            pState.iState = _ProtoSSLUpdateRecvServerFinish(pState, pData);
                        }
                    }

                    if (pSecure.iRecvBase >= pSecure.iRecvSize)
                    {
                        pSecure.iRecvProg = 0;
                        pSecure.iRecvSize = 0;
                        pSecure.iRecvBase = 0;
                        pSecure.iRecvDone = 0;
                    }
                }

                if (iXfer == 0)
                {
                    break;
                }
            }
        }

        public static int ProtoSSLSend(ProtoSSLRefT pState, byte[] pBuffer, int iLength)
        {
            int iResult = -1;
            ProtoSSLSecureState? pSecure = pState.pSecure;

            if (iLength < 0)
            {
                int iNullIndex = Array.IndexOf(pBuffer, (byte)0);
                iLength = iNullIndex >= 0 ? iNullIndex : pBuffer.Length;
            }

            if (pState.iState == ProtoSSLConstants.ST3_SECURE)
            {
                iResult = 0;

                if (pSecure!.iSendSize == 0)
                {
                    if (iLength > ProtoSSLConstants.SSL_SNDLIM_PACKET)
                    {
                        iLength = ProtoSSLConstants.SSL_SNDLIM_PACKET;
                    }

                    _SendPacket(
                        pState,
                        ProtoSSLConstants.SSL3_REC_APPLICATION,
                        null,
                        0,
                        pBuffer,
                        iLength);

                    iResult = iLength;

                    ProtoSSLUpdate(pState);
                }
            }

            if (pState.iState == ProtoSSLConstants.ST_UNSECURE)
            {
                iResult = DirtyNetPS3.SocketSend(
                    pState.pSock!,
                    pBuffer,
                    iLength,
                    0);
            }

            return iResult;
        }

        public static int ProtoSSLRecv(ProtoSSLRefT pState, byte[] pBuffer, int iLength)
        {
            int iResult = -1;
            ProtoSSLSecureState? pSecure = pState.pSecure;

            if (pState.iState == ProtoSSLConstants.ST3_SECURE)
            {
                iResult = 0;

                if ((pSecure!.iRecvProg == 0) ||
                    (pSecure.iRecvProg != pSecure.iRecvSize))
                {
                    ProtoSSLUpdate(pState);
                }

                if (((pSecure.iRecvSize < ProtoSSLConstants.SSL_MIN_PACKET) ||
                    (pSecure.iRecvProg < pSecure.iRecvSize)) &&
                    pState.iClosed != 0)
                {
                    iResult = DirtyNetPS3.SOCKERR_CLOSED;
                }
                else if ((pSecure.iRecvProg == pSecure.iRecvSize) &&
                        (pSecure.iRecvBase < pSecure.iRecvSize) &&
                        (pSecure.RecvData[0] == ProtoSSLConstants.SSL3_REC_APPLICATION) &&
                        (pSecure.iRecvDone != 0))
                {
                    iResult = pSecure.iRecvSize - pSecure.iRecvBase;

                    if (iResult > iLength)
                    {
                        iResult = iLength;
                    }

                    Array.Copy(
                        pSecure.RecvData,
                        pSecure.iRecvBase,
                        pBuffer,
                        0,
                        iResult);

                    pSecure.iRecvBase += iResult;

                    if ((pSecure.iRecvBase >= pSecure.iRecvSize) &&
                        (pSecure.iRecvDone != 0))
                    {
                        pSecure.iRecvProg = 0;
                        pSecure.iRecvSize = 0;
                        pSecure.iRecvBase = 0;
                        pSecure.iRecvDone = 0;
                    }
                }
            }

            if (pState.iState == ProtoSSLConstants.ST_UNSECURE)
            {
                iResult = DirtyNetPS3.SocketRecv(
                    pState.pSock!,
                    pBuffer,
                    iLength,
                    0);
            }

            if ((iResult > 0) && (iResult < iLength))
            {
                pBuffer[iResult] = 0;
            }

            return iResult;
        }

        public static int ProtoSSLControl(ProtoSSLRefT pState, int iSelect, int iValue) // int32_t iValue2, void *pValue)
        {
            if (iSelect == Tools.FourCC("ncrt"))
            {
                pState.bAllowAnyCert = (byte)iValue;
                return 0;
            }
            return -1;
        }

        // --------------------------------------------------------

        private static int _ParseAtoi(string value)
        {
            int i = 0;
            while (i < value.Length && char.IsWhiteSpace(value[i]))
            {
                i++;
            }

            int sign = 1;

            if (i < value.Length && (value[i] == '+' || value[i] == '-'))
            {
                if (value[i] == '-')
                {
                    sign = -1;
                }

                i++;
            }

            int result = 0;
            bool hasDigits = false;

            while (i < value.Length && value[i] >= '0' && value[i] <= '9')
            {
                hasDigits = true;

                result = unchecked(result * 10 + (value[i] - '0'));
                i++;
            }

            return hasDigits ? unchecked(result * sign) : 0;
        }

        private static readonly byte[] _SSL3_Pad1 = new byte[48]
        {
            0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
            0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
            0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36
        };

        private static readonly byte[] _SSL3_Pad2 = new byte[48]
        {
            0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
            0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
            0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c
        };

        private static readonly byte[] _JunkModulus = new byte[128]
        {
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc,
            0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc, 0xbc
        };

        private static readonly ProtoSSLCACertT _ProtoSSL_CACerts =
            new ProtoSSLCACertT
            {
                Subject = new ProtoSSLCertIdentT
                {
                    strCountry = "UnInit",
                    strState = "UnInit",
                    strCity = "UnInit",
                    strOrg = "UnInit",
                    strUnit = "UnInit",
                    strCommon = "UnInit"
                },

                iKeyModSize = 128,
                pKeyModData = _JunkModulus,

                iKeyExpSize = 1,
                KeyExpData = new byte[] { 0x03 },

                iMemGroup = 0,
                pMemGroupUserData = null,
                pNext = null
            };

        private static readonly CipherSuiteT[] _SSL3_CipherSuite =
        {
            new CipherSuiteT
            {
                uIdent = new byte[] { 0, 5 },
                uKey = ProtoSSLConstants.SSL3_KEY_RSA,
                uEnc = ProtoSSLConstants.SSL3_ENC_RC4,
                uMac = ProtoSSLConstants.SSL3_MAC_SHA
            },
            new CipherSuiteT
            {
                uIdent = new byte[] { 0, 4 },
                uKey = ProtoSSLConstants.SSL3_KEY_RSA,
                uEnc = ProtoSSLConstants.SSL3_ENC_RC4,
                uMac = ProtoSSLConstants.SSL3_MAC_MD5
            }
        };

        private const int ASN_OBJ_NONE = 0;
        private const int ASN_OBJ_COUNTRY = 1;
        private const int ASN_OBJ_STATE = 2;
        private const int ASN_OBJ_CITY = 3;
        private const int ASN_OBJ_ORGANIZATION = 4;
        private const int ASN_OBJ_UNIT = 5;
        private const int ASN_OBJ_COMMON = 6;
        private const int ASN_OBJ_RSA_PKCS_KEY = 7;
        private const int ASN_OBJ_RSA_PKCS_MD2 = 8;
        private const int ASN_OBJ_RSA_PKCS_MD5 = 9;
        private const int ASN_OBJ_RSA_PKCS_SHA1 = 10;

        private sealed class SSLObjectT
        {
            public int iType;
            public int iSize;
            public byte[] strData;

            public SSLObjectT(int iType, int iSize, byte[] strData)
            {
                this.iType = iType;
                this.iSize = iSize;
                this.strData = strData;
            }
        }

        private static readonly SSLObjectT[] _SSL_ObjectList =
        {
            new(ASN_OBJ_COUNTRY, 3, new byte[] { 0x55, 0x04, 0x06 }),
            new(ASN_OBJ_CITY, 3, new byte[] { 0x55, 0x04, 0x07 }),
            new(ASN_OBJ_STATE, 3, new byte[] { 0x55, 0x04, 0x08 }),
            new(ASN_OBJ_ORGANIZATION, 3, new byte[] { 0x55, 0x04, 0x0a }),
            new(ASN_OBJ_UNIT, 3, new byte[] { 0x55, 0x04, 0x0b }),
            new(ASN_OBJ_COMMON, 3, new byte[] { 0x55, 0x04, 0x03 }),

            new(ASN_OBJ_RSA_PKCS_KEY, 9, new byte[]
                { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }),

            new(ASN_OBJ_RSA_PKCS_MD2, 9, new byte[]
                { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02 }),

            new(ASN_OBJ_RSA_PKCS_MD5, 9, new byte[]
                { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04 }),

            new(ASN_OBJ_RSA_PKCS_SHA1, 9, new byte[]
                { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 }),

            new(ASN_OBJ_NONE, 0, new byte[] { 0 })
        };

        private static int _WildcardMatchNoCase(string pString1, string pString2)
        {
            int r;
            char c1, c2;
            int i1 = 0;
            int i2 = 0;

            do
            {
                c1 = i1 < pString1.Length ? pString1[i1++] : '\0';

                if ((c1 >= 'A') && (c1 <= 'Z'))
                    c1 = (char)(c1 ^ 32);

                c2 = i2 < pString2.Length ? pString2[i2] : '\0';

                if ((c2 >= 'A') && (c2 <= 'Z'))
                    c2 = (char)(c2 ^ 32);

                if ((c2 == '*') && (c1 != '.'))
                {
                    r = _WildcardMatchNoCase(
                        pString1.Substring(i1),
                        pString2.Substring(i2 + 1));

                    if (r == 0)
                    {
                        break;
                    }

                    r = 0;
                }
                else
                {
                    i2 += 1;
                    r = c1 - c2;
                }
            }
            while ((c1 != '\0') && (c2 != '\0') && (r == 0));

            return r;
        }

        private static readonly uint[] _ProtoSSL_Random = new uint[4];

        private static void _GenerateRandom(byte[]? pRandomBuf, int iRandomLen, CryptArc4? pArc4)
        {
            if (_ProtoSSL_Random[0] == 0)
            {
                _ProtoSSL_Random[0] = Tools.NetTick();
            }

            _ProtoSSL_Random[1] = unchecked(
                _ProtoSSL_Random[1] + Tools.NetTick());

            _ProtoSSL_Random[2] = unchecked(
                _ProtoSSL_Random[2] + 1);

            for (int iCount = 0; iCount < 32; ++iCount)
            {
                // There was in the original code:
                // _ProtoSSL_Random[3] += (&iCount)[iCount];
                // Seems like an additional random info from the stack
                // So, I just add some random values
                _ProtoSSL_Random[3] += BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
            }

            if (pRandomBuf != null)
            {
                if (pArc4 == null)
                {
                    throw new ArgumentNullException(nameof(pArc4));
                }

                byte[] randomKey = new byte[16];

                for (int i = 0; i < 4; ++i)
                {
                    byte[] word = BitConverter.GetBytes(_ProtoSSL_Random[i]);
                    Buffer.BlockCopy(word, 0, randomKey, i * 4, 4);
                }

                pArc4.Init(randomKey, randomKey.Length, 3);

                byte[] randomData = new byte[iRandomLen];
                pArc4.Apply(randomData, iRandomLen);

                Buffer.BlockCopy(randomData, 0, pRandomBuf, 0, iRandomLen);
            }
        }

        private static int _ResetState(ProtoSSLRefT pState, int iSecure)
        {
            ProtoSSLSecureState? pSecure;

            if (pState.pSock != null)
            {
                DirtyNetPS3.SocketClose(pState.pSock);
                pState.pSock = null;
            }

            if (pState.pHost != null)
            {
                pState.pHost = null;
            }

            pState.iState = ProtoSSLConstants.ST_IDLE;
            pState.iClosed = 1;

            if (iSecure == 0 && pState.pSecure != null)
            {
                //DirtyMem.DirtyMemFree(...);
                pState.pSecure = null;
            }

            if (iSecure != 0 && pState.pSecure == null)
            {
                try
                {
                    pState.pSecure = new ProtoSSLSecureState();
                }
                catch (OutOfMemoryException)
                {
                    pState.pSecure = null;
                }
            }

            pSecure = pState.pSecure;
            if (pSecure != null)
            {
                _GenerateRandom(null, 0, pSecure.ReadArc4);

                pSecure.iSendProg = 0;
                pSecure.iSendSize = 0;
                pSecure.uSendSeqn = 0;

                pSecure.iRecvProg = 0;
                pSecure.iRecvSize = 0;
                pSecure.uRecvSeqn = 0;

                pSecure.HandshakeMD5.Init();
                pSecure.HandshakeSHA.Init();
            }

            return (iSecure != 0 && pSecure == null) ? DirtyNetPS3.SOCKERR_NOMEM : DirtyNetPS3.SOCKERR_NONE;
        }

        private static int _SendPacket(ProtoSSLRefT pState, byte uType, byte[]? pHeadPtr, int iHeadLen, byte[]? pBodyPtr, int iBodyLen)
        {
            ProtoSSLSecureState pSecure = pState.pSecure
                ?? throw new InvalidOperationException("Secure state is not initialized.");

            byte[] pSend = pSecure.SendData;
            int iSize = 0;

            pSend[0] = uType;
            pSend[1] = (byte)((ProtoSSLConstants.SSL3_VERSION >> 8) & 0xFF);
            pSend[2] = (byte)(ProtoSSLConstants.SSL3_VERSION & 0xFF);

            // Payload starts at offset 5; the first five bytes are the record header.
            const int iSendOffset = 5;

            if (iHeadLen > 0)
            {
                if (pHeadPtr == null)
                    throw new ArgumentNullException(nameof(pHeadPtr));

                Buffer.BlockCopy(pHeadPtr, 0, pSend, iSendOffset + iSize, iHeadLen);
                iSize += iHeadLen;
            }

            if (iBodyLen > 0)
            {
                if (pBodyPtr == null)
                    throw new ArgumentNullException(nameof(pBodyPtr));

                Buffer.BlockCopy(pBodyPtr, 0, pSend, iSendOffset + iSize, iBodyLen);
                iSize += iBodyLen;
            }

            if (uType == ProtoSSLConstants.SSL3_REC_HANDSHAKE)
            {
                pSecure.HandshakeMD5.Update(pSend, iSize);
                pSecure.HandshakeSHA.Update(pSend, (uint)iSize);
            }

            if ((pState.iState >= ProtoSSLConstants.ST3_SEND_FINISH) &&
                (pState.iState <= ProtoSSLConstants.ST3_SECURE) &&
                (pSecure.pCipher != null))
            {
                byte[] macTemp = new byte[20];

                // MacData: uint64 sequence number + type + uint16 payload length.
                byte[] macData = new byte[11];

                macData[0] = 0;
                macData[1] = 0;
                macData[2] = 0;
                macData[3] = 0;
                macData[4] = (byte)((pSecure.uSendSeqn >> 24) & 255);
                macData[5] = (byte)((pSecure.uSendSeqn >> 16) & 255);
                macData[6] = (byte)((pSecure.uSendSeqn >> 8) & 255);
                macData[7] = (byte)(pSecure.uSendSeqn & 255);
                macData[8] = pSend[0];
                macData[9] = (byte)((iSize >> 8) & 255);
                macData[10] = (byte)(iSize & 255);

                if (pSecure.pCipher.uMac == ProtoSSLConstants.SSL3_MAC_MD5)
                {
                    byte[] clientMac = pSecure.pClientMAC
                        ?? throw new InvalidOperationException("Client MAC key is not initialized.");

                    var md5context = new CryptMD5();
                    md5context.Init();
                    md5context.Update(clientMac, 16);
                    md5context.Update(_SSL3_Pad1, 48);
                    md5context.Update(macData, macData.Length);
                    md5context.Update(pSend, iSize);
                    md5context.Final(macTemp, 16);

                    md5context.Init();
                    md5context.Update(clientMac, 16);
                    md5context.Update(_SSL3_Pad2, 48);
                    md5context.Update(macTemp, 16);

                    byte[] macResult = new byte[16];
                    md5context.Final(macResult, 16);
                    Buffer.BlockCopy(macResult, 0, pSend, iSendOffset + iSize, 16);

                    iSize += 16;
                }

                if (pSecure.pCipher.uMac == ProtoSSLConstants.SSL3_MAC_SHA)
                {
                    byte[] clientMac = pSecure.pClientMAC
                        ?? throw new InvalidOperationException("Client MAC key is not initialized.");

                    var sha1context = new CryptSHA1();
                    sha1context.Init();
                    sha1context.Update(clientMac, 20);
                    sha1context.Update(_SSL3_Pad1, 40);
                    sha1context.Update(macData, (uint)macData.Length);
                    sha1context.Update(pSend, iSendOffset, (uint)iSize);
                    sha1context.Final(macTemp, 20);

                    sha1context.Init();
                    sha1context.Update(clientMac, 20);
                    sha1context.Update(_SSL3_Pad2, 40);
                    sha1context.Update(macTemp, 20);

                    byte[] macResult = new byte[20];
                    sha1context.Final(macResult, 20);
                    Buffer.BlockCopy(macResult, 0, pSend, iSendOffset + iSize, 20);
                    
                    iSize += 20;
                }

                if (pSecure.pCipher.uEnc == ProtoSSLConstants.SSL3_ENC_RC4)
                {
                    byte[] encryptedData = new byte[iSize];
                    Buffer.BlockCopy(pSend, iSendOffset, encryptedData, 0, iSize);
                    pSecure.WriteArc4.Apply(encryptedData, iSize);
                    Buffer.BlockCopy(encryptedData, 0, pSend, iSendOffset, iSize);
                }
            }

            pSend[3] = (byte)((iSize >> 8) & 255);
            pSend[4] = (byte)(iSize & 255);

            pSecure.iSendProg = 0;
            pSecure.iSendSize = iSize + 5;

            pSecure.uSendSeqn = unchecked(pSecure.uSendSeqn + 1);

            return 0;
        }

        private static int _RecvPacket(ProtoSSLRefT pState)
        {
            ProtoSSLSecureState pSecure = pState.pSecure
                ?? throw new InvalidOperationException("Secure state is not initialized.");

            byte[] pRecv = pSecure.RecvData;
            int iSize;

            pSecure.iRecvBase = pSecure.iRecvSize;

            if (pSecure.iRecvProg != pSecure.iRecvSize)
            {
                return -1;
            }

            if ((pRecv[0] < ProtoSSLConstants.SSL3_REC_CIPHER) ||
                (pRecv[0] > ProtoSSLConstants.SSL3_REC_APPLICATION))
            {
                return -2;
            }

            if ((pRecv[1] != (byte)(ProtoSSLConstants.SSL3_VERSION >> 8)) ||
                (pRecv[2] != (byte)(ProtoSSLConstants.SSL3_VERSION & 255)))
            {
                return -3;
            }

            iSize = (pRecv[3] << 8) | pRecv[4];

            if (pSecure.iRecvSize != iSize + 5)
            {
                return -4;
            }

            pSecure.iRecvBase = 5;

            if ((pState.iState >= ProtoSSLConstants.ST3_RECV_FINISH) &&
                (pState.iState <= ProtoSSLConstants.ST3_SECURE) &&
                (pSecure.pCipher != null))
            {
                byte[] macTemp = new byte[20];

                byte[] macData = new byte[11];

                macData[0] = 0;
                macData[1] = 0;
                macData[2] = 0;
                macData[3] = 0;
                macData[4] = (byte)((pSecure.uRecvSeqn >> 24) & 255);
                macData[5] = (byte)((pSecure.uRecvSeqn >> 16) & 255);
                macData[6] = (byte)((pSecure.uRecvSeqn >> 8) & 255);
                macData[7] = (byte)(pSecure.uRecvSeqn & 255);
                macData[8] = pRecv[0];

                if (pSecure.pCipher.uEnc == ProtoSSLConstants.SSL3_ENC_RC4)
                {
                    int encryptedLength = pSecure.iRecvSize - pSecure.iRecvBase;

                    byte[] encryptedData = new byte[encryptedLength];

                    Buffer.BlockCopy(
                        pRecv,
                        pSecure.iRecvBase,
                        encryptedData,
                        0,
                        encryptedLength);

                    pSecure.ReadArc4.Apply(encryptedData, encryptedLength);

                    Buffer.BlockCopy(
                        encryptedData,
                        0,
                        pRecv,
                        pSecure.iRecvBase,
                        encryptedLength);
                }

                iSize = pSecure.iRecvSize - pSecure.iRecvBase;

                if (iSize < pSecure.pCipher.uMac)
                {
                    return -4;
                }

                iSize -= pSecure.pCipher.uMac;

                pSecure.iRecvProg = pSecure.iRecvSize =
                    pSecure.iRecvBase + iSize;

                macData[9] = (byte)((iSize >> 8) & 255);
                macData[10] = (byte)(iSize & 255);

                // MAC вычисляется только по полезной нагрузке, без заголовка записи.
                byte[] payload = new byte[iSize];

                Buffer.BlockCopy(
                    pRecv,
                    pSecure.iRecvBase,
                    payload,
                    0,
                    iSize);

                if (pSecure.pCipher.uMac == ProtoSSLConstants.SSL3_MAC_MD5)
                {
                    byte[] serverMac = pSecure.pServerMAC
                        ?? throw new InvalidOperationException(
                            "Server MAC key is not initialized.");

                    var md5context = new CryptMD5();

                    md5context.Init();
                    md5context.Update(serverMac, 16);
                    md5context.Update(_SSL3_Pad1, 48);
                    md5context.Update(macData, macData.Length);
                    md5context.Update(payload, payload.Length);
                    md5context.Final(macTemp, 16);

                    md5context.Init();
                    md5context.Update(serverMac, 16);
                    md5context.Update(_SSL3_Pad2, 48);
                    md5context.Update(macTemp, 16);
                    md5context.Final(macTemp, 16);

                    byte[] receivedMac = new byte[16];

                    Buffer.BlockCopy(
                        pRecv,
                        pSecure.iRecvSize,
                        receivedMac,
                        0,
                        receivedMac.Length);

                    if (!receivedMac.SequenceEqual(
                            macTemp.Take(16)))
                    {
                        return -5;
                    }
                }

                if (pSecure.pCipher.uMac == ProtoSSLConstants.SSL3_MAC_SHA)
                {
                    byte[] serverMac = pSecure.pServerMAC
                        ?? throw new InvalidOperationException(
                            "Server MAC key is not initialized.");

                    var sha1context = new CryptSHA1();

                    sha1context.Init();
                    sha1context.Update(serverMac, 20);
                    sha1context.Update(_SSL3_Pad1, 40);
                    sha1context.Update(macData, (uint)macData.Length);
                    sha1context.Update(payload, (uint)payload.Length);
                    sha1context.Final(macTemp, 20);

                    sha1context.Init();
                    sha1context.Update(serverMac, 20);
                    sha1context.Update(_SSL3_Pad2, 40);
                    sha1context.Update(macTemp, 20);
                    sha1context.Final(macTemp, 20);

                    byte[] receivedMac = new byte[20];

                    Buffer.BlockCopy(
                        pRecv,
                        pSecure.iRecvSize,
                        receivedMac,
                        0,
                        receivedMac.Length);

                    if (!receivedMac.SequenceEqual(
                            macTemp.Take(20)))
                    {
                        return -6;
                    }
                }
            }
            else
            {
                //#if DEBUG_MSG_LIST
                //NetPrintf(("protossl: _RecvPacket (unsecure): type=%d, size=%d, seq=%d\n", pSecure->RecvData[0], iSize, pSecure->uRecvSeqn));
                //#endif
                //#if (DEBUG_RAW_DATA > 1)
                //NetPrintMem(pSecure->RecvData, pSecure->iRecvSize, "_RecvPacket");
                //#endif
            }

            if ((pRecv[0] == ProtoSSLConstants.SSL3_REC_HANDSHAKE) &&
                (pState.iState < ProtoSSLConstants.ST3_RECV_FINISH))
            {
                int handshakeLength =
                    pSecure.iRecvSize - pSecure.iRecvBase;

                byte[] handshakeData = new byte[handshakeLength];

                Buffer.BlockCopy(
                    pRecv,
                    pSecure.iRecvBase,
                    handshakeData,
                    0,
                    handshakeLength);

                pSecure.HandshakeMD5.Update(
                    handshakeData,
                    handshakeData.Length);

                pSecure.HandshakeSHA.Update(
                    handshakeData,
                    (uint)handshakeData.Length);
            }

            pSecure.uRecvSeqn = unchecked(pSecure.uRecvSeqn + 1);
            pSecure.iRecvDone = 1;

            return 0;
        }

        private static byte[]? _RecvHandshake(ProtoSSLRefT pState, byte uType)
        {
            ProtoSSLSecureState pSecure = pState.pSecure
                ?? throw new InvalidOperationException("Secure state is not initialized.");

            byte[] pRecv = pSecure.RecvData;
            int iBase = pSecure.iRecvBase;

            if (pRecv[iBase] != uType)
            {
                return null;
            }

            int iSize =
                (pRecv[iBase + 1] << 16) |
                (pRecv[iBase + 2] << 8) |
                (pRecv[iBase + 3] << 0);

            if (iBase + 4 + iSize > pSecure.iRecvSize)
            {
                return null;
            }

            pSecure.iRecvBase += iSize + 4;

            byte[] pResult = new byte[iSize];

            Buffer.BlockCopy(
                pRecv,
                iBase + 4,
                pResult,
                0,
                iSize);

            return pResult;
        }

        private static ArraySegment<byte>? _FindPEMSignature(byte[] pCertData, int iCertSize, string pSigText)
        {
            int iSigLen = pSigText.Length;

            for (int iCertIdx = 0; iCertIdx < iCertSize; iCertIdx++)
            {
                if ((pCertData[iCertIdx] == (byte)pSigText[0]) &&
                    ((iCertSize - iCertIdx) >= iSigLen))
                {
                    bool bMatch = true;

                    for (int i = 0; i < iSigLen; i++)
                    {
                        if (pCertData[iCertIdx + i] != (byte)pSigText[i])
                        {
                            bMatch = false;
                            break;
                        }
                    }

                    if (bMatch)
                    {
                        return new ArraySegment<byte>(
                            pCertData,
                            iCertIdx,
                            iCertSize - iCertIdx);
                    }
                }
            }

            return null;
        }

        private static int _FindPEMCertificateData(byte[] pCertData, int iCertSize, out ArraySegment<byte> pCertBeg, out ArraySegment<byte> pCertEnd)
        {
            const string strPemBeg = "-----BEGIN CERTIFICATE-----";
            const string strPemEnd = "-----END CERTIFICATE-----";
            const string str509Beg = "-----BEGIN X509 CERTIFICATE-----";
            const string str509End = "-----END X509 CERTIFICATE-----";

            pCertBeg = default;
            pCertEnd = default;

            ArraySegment<byte>? pemBeg =
                _FindPEMSignature(pCertData, iCertSize, strPemBeg);

            if (pemBeg.HasValue)
            {
                int begOffset = pemBeg.Value.Offset;
                int remaining = iCertSize - begOffset;

                byte[] remainingData = new byte[remaining];
                Buffer.BlockCopy(pCertData, begOffset, remainingData, 0, remaining);

                ArraySegment<byte>? pemEnd =
                    _FindPEMSignature(remainingData, remaining, strPemEnd);

                if (pemEnd.HasValue)
                {
                    int endOffset = begOffset + pemEnd.Value.Offset;

                    pCertBeg = new ArraySegment<byte>(
                        pCertData,
                        begOffset + strPemBeg.Length,
                        iCertSize - begOffset - strPemBeg.Length);

                    pCertEnd = new ArraySegment<byte>(
                        pCertData,
                        endOffset,
                        iCertSize - endOffset);

                    return endOffset - pCertBeg.Offset;
                }
            }

            ArraySegment<byte>? x509Beg =
                _FindPEMSignature(pCertData, iCertSize, str509Beg);

            if (x509Beg.HasValue)
            {
                int begOffset = x509Beg.Value.Offset;
                int remaining = iCertSize - begOffset;

                byte[] remainingData = new byte[remaining];
                Buffer.BlockCopy(pCertData, begOffset, remainingData, 0, remaining);

                ArraySegment<byte>? x509End =
                    _FindPEMSignature(remainingData, remaining, str509End);

                if (x509End.HasValue)
                {
                    int endOffset = begOffset + x509End.Value.Offset;

                    pCertBeg = new ArraySegment<byte>(
                        pCertData,
                        begOffset + str509Beg.Length,
                        iCertSize - begOffset - str509Beg.Length);

                    pCertEnd = new ArraySegment<byte>(
                        pCertData,
                        endOffset,
                        iCertSize - endOffset);

                    return endOffset - pCertBeg.Offset;
                }
            }

            return 0;
        }

        private static int _CompareIdent(ProtoSSLCertIdentT pIdent1, ProtoSSLCertIdentT pIdent2)
        {
            return
                string.CompareOrdinal(pIdent1.strCountry, pIdent2.strCountry) != 0 ||
                string.CompareOrdinal(pIdent1.strState, pIdent2.strState) != 0 ||
                string.CompareOrdinal(pIdent1.strCity, pIdent2.strCity) != 0 ||
                string.CompareOrdinal(pIdent1.strOrg, pIdent2.strOrg) != 0 ||
                string.CompareOrdinal(pIdent1.strUnit, pIdent2.strUnit) != 0 ||
                string.CompareOrdinal(pIdent1.strCommon, pIdent2.strCommon) != 0
                    ? 1
                    : 0;
        }

        private static ArraySegment<byte>? _ParseHeader(ArraySegment<byte>? pData, ArraySegment<byte> pLast, out int iType, out uint uSize)
        {
            uSize = 0;
            iType = 0;

            if (!pData.HasValue)
                return null;

            ArraySegment<byte> data = pData.Value;

            int dataEnd = data.Offset + data.Count;
            int lastEnd = pLast.Offset + pLast.Count;

            if (data.Offset == pLast.Offset)
                return null;

            iType = data.Array![data.Offset];
            int offset = data.Offset + 1;

            if (offset == pLast.Offset)
                return null;

            uint len = data.Array[offset++];

            if (len > 127)
            {
                int count = (int)(len & 127);
                len = 0;

                for (; count > 0; --count)
                {
                    if (offset == pLast.Offset)
                        return null;

                    len = (len << 8) | data.Array[offset++];
                }
            }

            uSize = len;

            return new ArraySegment<byte>(
                data.Array!,
                offset,
                dataEnd - offset);
        }

        private static int _ParseObject(byte[] pData, int iSize)
        {
            for (int iIndex = 0; _SSL_ObjectList[iIndex].iType != ASN_OBJ_NONE; ++iIndex)
            {
                SSLObjectT obj = _SSL_ObjectList[iIndex];

                if (iSize >= obj.iSize &&
                    pData.AsSpan(0, obj.iSize).SequenceEqual(
                        obj.strData.AsSpan(0, obj.iSize)))
                {
                    return obj.iType;
                }
            }

            return 0;
        }

        private static int _ParseObjectAt(byte[] pData, int iOffset, int iSize)
        {
            return _ParseObject(
                pData.AsSpan(iOffset, iSize).ToArray(),
                iSize);
        }

        private static void _ParseString(byte[] pData, int iSize, byte[] pString, int iLength)
        {
            int iDataIndex = 0;
            int iStringIndex = 0;

            for (; (iSize > 0) && (iLength > 1);
                --iSize, --iLength)
            {
                pString[iStringIndex++] = pData[iDataIndex++];
            }

            if (iLength > 0)
            {
                pString[iStringIndex] = 0;
            }
        }

        private static void _ParseStringMulti(byte[] pData, int iSize, byte[] pString, int iLength)
        {
            int iStringIndex = 0;
            int iDataIndex = 0;

            for (; (iStringIndex < pString.Length) &&
                (pString[iStringIndex] != 0) &&
                (iLength > 1);
                --iLength)
            {
                iStringIndex++;
            }

            for (; (iSize > 0) && (iLength > 1);
                --iSize, --iLength)
            {
                pString[iStringIndex++] = pData[iDataIndex++];
            }

            if (iLength > 0)
            {
                pString[iStringIndex] = 0;
            }
        }

        private static int _ParseCertificate(X509CertificateT pCert, byte[] pData, int iSize)
        {
            int iType = 0;
            int iObjType;
            int iKeySize;
            int iKeyOffset;

            int pLast = iSize;

            // memset(pCert, 0, sizeof(*pCert));
            pCert.Issuer = new ProtoSSLCertIdentT();
            pCert.Subject = new ProtoSSLCertIdentT();
            pCert.strGoodFrom = "";
            pCert.strGoodTill = "";
            pCert.iSerialSize = 0;
            Array.Clear(pCert.SerialData);
            pCert.iSigType = 0;
            pCert.iSigSize = 0;
            Array.Clear(pCert.SigData);
            pCert.iKeyType = 0;
            pCert.iKeyModSize = 0;
            Array.Clear(pCert.KeyModData);
            pCert.iKeyExpSize = 0;
            Array.Clear(pCert.KeyExpData);
            pCert.iHashSize = 0;
            Array.Clear(pCert.HashData);

            int offset = 0;

            int? ParseHeader(
                int position,
                int last,
                out int type,
                out int size)
            {
                type = 0;
                size = 0;

                if (position < 0 || position == last)
                    return null;

                type = pData[position++];

                if (position == last)
                    return null;

                uint len = pData[position++];

                if (len > 127)
                {
                    int count = (int)(len & 127);
                    len = 0;

                    for (; count > 0; --count)
                    {
                        if (position >= last)
                            return null;

                        len = (len << 8) | pData[position++];
                    }
                }

                size = unchecked((int)len);
                return position;
            }

            bool HasRange(int start, int length, int end)
            {
                return start >= 0 &&
                    length >= 0 &&
                    start <= end &&
                    length <= end - start &&
                    end <= pData.Length;
            }

            string ReadAscii(int start, int length, int maxLength)
            {
                if (!HasRange(start, length, pLast))
                    return "";

                int count = Math.Min(length, Math.Max(0, maxLength - 1));
                int actual = 0;

                while (actual < count && pData[start + actual] != 0)
                    actual++;

                return System.Text.Encoding.Latin1.GetString(
                    pData, start, actual);
            }

            void CopyBytes(byte[] destination, int destinationOffset,
                int sourceOffset, int count)
            {
                if (count > 0)
                    Buffer.BlockCopy(
                        pData, sourceOffset,
                        destination, destinationOffset,
                        count);
            }

            void SetIssuerField(int objectType, int start, int length)
            {
                string value;

                switch (objectType)
                {
                    case ASN_OBJ_COUNTRY:
                        value = ReadAscii(start, length, 4);
                        pCert.Issuer.strCountry = value;
                        break;

                    case ASN_OBJ_STATE:
                        value = ReadAscii(start, length, 64);
                        pCert.Issuer.strState = value;
                        break;

                    case ASN_OBJ_CITY:
                        value = ReadAscii(start, length, 64);
                        pCert.Issuer.strCity = value;
                        break;

                    case ASN_OBJ_ORGANIZATION:
                        value = ReadAscii(start, length, 64);
                        pCert.Issuer.strOrg = value;
                        break;

                    case ASN_OBJ_UNIT:
                        value = ReadAscii(start, length, 64);
                        pCert.Issuer.strUnit =
                            string.IsNullOrEmpty(pCert.Issuer.strUnit)
                                ? value
                                : pCert.Issuer.strUnit + ", " + value;
                        break;

                    case ASN_OBJ_COMMON:
                        value = ReadAscii(start, length, 64);
                        pCert.Issuer.strCommon = value;
                        break;
                }
            }

            void SetSubjectField(int objectType, int start, int length)
            {
                string value;

                switch (objectType)
                {
                    case ASN_OBJ_COUNTRY:
                        value = ReadAscii(start, length, 4);
                        pCert.Subject.strCountry = value;
                        break;

                    case ASN_OBJ_STATE:
                        value = ReadAscii(start, length, 64);
                        pCert.Subject.strState = value;
                        break;

                    case ASN_OBJ_CITY:
                        value = ReadAscii(start, length, 64);
                        pCert.Subject.strCity = value;
                        break;

                    case ASN_OBJ_ORGANIZATION:
                        value = ReadAscii(start, length, 64);
                        pCert.Subject.strOrg = value;
                        break;

                    case ASN_OBJ_UNIT:
                        value = ReadAscii(start, length, 64);
                        pCert.Subject.strUnit =
                            string.IsNullOrEmpty(pCert.Subject.strUnit)
                                ? value
                                : pCert.Subject.strUnit + ", " + value;
                        break;

                    case ASN_OBJ_COMMON:
                        value = ReadAscii(start, length, 64);
                        pCert.Subject.strCommon = value;
                        break;
                }
            }

            // Base sequence
            int? next = ParseHeader(offset, pLast, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT))
                return -1;

            offset = next.Value;
            int last = offset + iSize;

            // Certificate info sequence
            int infOffset = offset;
            next = ParseHeader(offset, pLast, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT))
                return -2;

            offset = next.Value;
            int infSkip = offset + iSize;

            if (offset >= pLast)
                return -3;

            if (pData[offset] != (ProtoSSLConstants.ASN_TYPE_INTEGER + ProtoSSLConstants.ASN_PRIMITIVE))
            {
                next = ParseHeader(offset, pLast, out _, out iSize);
                if (next == null)
                    return -3;

                offset = next.Value + iSize;
            }

            // Serial number
            next = ParseHeader(offset, infSkip, out iType, out iSize);
            if (next == null ||
                iSize < 0 ||
                iSize > pCert.SerialData.Length ||
                !HasRange(next ?? 0, iSize, infSkip))
                return -4;

            offset = next.Value;
            pCert.iSerialSize = iSize;
            CopyBytes(pCert.SerialData, 0, offset, iSize);
            offset += iSize;

            // Signature algorithm sequence
            next = ParseHeader(offset, infSkip, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT))
                return -5;

            offset = next.Value;
            int sigSkip = offset + iSize;

            next = ParseHeader(offset, infSkip, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_OBJECT + ProtoSSLConstants.ASN_PRIMITIVE))
                return -6;

            offset = next.Value;
            pCert.iSigType = _ParseObjectAt(pData, offset, iSize);

            if (pCert.iSigType == ASN_OBJ_NONE)
                return -7;

            offset += iSize;

            // Issuer sequence
            next = ParseHeader(sigSkip, infSkip, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT))
                return -8;

            offset = next.Value;
            int issSkip = offset + iSize;

            iObjType = 0;

            while ((next = ParseHeader(offset, issSkip, out iType, out iSize)) != null)
            {
                offset = next.Value;

                if ((iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT)) &&
                    (iType != (ProtoSSLConstants.ASN_TYPE_SET + ProtoSSLConstants.ASN_CONSTRUCT)))
                {
                    if (iType == (ProtoSSLConstants.ASN_TYPE_OBJECT + ProtoSSLConstants.ASN_PRIMITIVE))
                        iObjType = _ParseObjectAt(pData, offset, iSize);

                    if ((iType == (ProtoSSLConstants.ASN_TYPE_PRINTSTR + ProtoSSLConstants.ASN_PRIMITIVE)) ||
                        (iType == (ProtoSSLConstants.ASN_TYPE_UTF8STR + ProtoSSLConstants.ASN_PRIMITIVE)) ||
                        (iType == (ProtoSSLConstants.ASN_TYPE_T61 + ProtoSSLConstants.ASN_PRIMITIVE)))
                    {
                        SetIssuerField(iObjType, offset, iSize);
                        iObjType = 0;
                    }

                    offset += iSize;
                }
            }

            // Validity sequence
            next = ParseHeader(issSkip, pLast, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT))
                return -9;

            offset = next.Value;

            next = ParseHeader(offset, pLast, out iType, out iSize);
            if (next == null ||
                (iType != ProtoSSLConstants.ASN_TYPE_UTCTIME &&
                iType != ProtoSSLConstants.ASN_TYPE_GENERALIZEDTIME))
                return -10;

            offset = next.Value;
            pCert.strGoodFrom = ReadAscii(offset, iSize, 32);
            offset += iSize;

            next = ParseHeader(offset, pLast, out iType, out iSize);
            if (next == null ||
                (iType != ProtoSSLConstants.ASN_TYPE_UTCTIME &&
                iType != ProtoSSLConstants.ASN_TYPE_GENERALIZEDTIME))
                return -11;

            offset = next.Value;
            pCert.strGoodTill = ReadAscii(offset, iSize, 32);
            offset += iSize;

            // Subject sequence
            next = ParseHeader(offset, pLast, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT))
                return -12;

            offset = next.Value;
            int subSkip = offset + iSize;

            iObjType = 0;

            while ((next = ParseHeader(offset, subSkip, out iType, out iSize)) != null)
            {
                offset = next.Value;

                if ((iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT)) &&
                    (iType != (ProtoSSLConstants.ASN_TYPE_SET + ProtoSSLConstants.ASN_CONSTRUCT)))
                {
                    if (iType == (ProtoSSLConstants.ASN_TYPE_OBJECT + ProtoSSLConstants.ASN_PRIMITIVE))
                        iObjType = _ParseObjectAt(pData, offset, iSize);

                    if ((iType == (ProtoSSLConstants.ASN_TYPE_PRINTSTR + ProtoSSLConstants.ASN_PRIMITIVE)) ||
                        (iType == (ProtoSSLConstants.ASN_TYPE_UTF8STR + ProtoSSLConstants.ASN_PRIMITIVE)) ||
                        (iType == (ProtoSSLConstants.ASN_TYPE_T61 + ProtoSSLConstants.ASN_PRIMITIVE)))
                    {
                        SetSubjectField(iObjType, offset, iSize);
                        iObjType = 0;
                    }

                    offset += iSize;
                }
            }

            // Public key sequence
            next = ParseHeader(subSkip, pLast, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT))
                return -13;

            offset = next.Value;

            next = ParseHeader(offset, pLast, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT))
                return -14;

            offset = next.Value;
            int keySkip = offset + iSize;

            next = ParseHeader(offset, keySkip, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_OBJECT + ProtoSSLConstants.ASN_PRIMITIVE))
                return -15;

            offset = next.Value;
            pCert.iKeyType = _ParseObjectAt(pData, offset, iSize);

            // Public key bit string
            next = ParseHeader(keySkip, pLast, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_BITSTRING + ProtoSSLConstants.ASN_PRIMITIVE) ||
                iSize < 1)
                return -16;

            offset = next.Value;
            iKeyOffset = offset + 1;
            iKeySize = iSize - 1;
            offset += iSize;

            // Outer signature algorithm
            next = ParseHeader(infSkip, sigSkip, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT))
                return -18;

            offset = next.Value;
            sigSkip = offset + iSize;

            next = ParseHeader(offset, sigSkip, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_OBJECT + ProtoSSLConstants.ASN_PRIMITIVE))
                return -19;

            offset = next.Value;
            pCert.iSigType = _ParseObjectAt(pData, offset, iSize);

            // Signature bit string
            next = ParseHeader(sigSkip, pLast, out iType, out iSize);
            if (next == null ||
                iType != (ProtoSSLConstants.ASN_TYPE_BITSTRING + ProtoSSLConstants.ASN_PRIMITIVE) ||
                iSize < 1)
                return -20;

            offset = next.Value;

            if (iSize > pCert.SigData.Length + 1)
                return -21;

            pCert.iSigSize = iSize - 1;
            CopyBytes(pCert.SigData, 0, offset + 1, iSize - 1);
            offset += iSize;

            // RSA public key
            if (pCert.iKeyType == ASN_OBJ_RSA_PKCS_KEY)
            {
                int keyModSize;
                int keyExpSize;
                int keyModOffset;
                int keyExpOffset;

                next = ParseHeader(iKeyOffset, iKeyOffset + iKeySize, out iType, out iSize);
                if (next == null ||
                    iType != (ProtoSSLConstants.ASN_TYPE_SEQN + ProtoSSLConstants.ASN_CONSTRUCT))
                    return -22;

                offset = next.Value;

                next = ParseHeader(offset, iKeyOffset + iKeySize, out iType, out iSize);
                if (next == null ||
                    iType != (ProtoSSLConstants.ASN_TYPE_INTEGER + ProtoSSLConstants.ASN_PRIMITIVE) ||
                    iSize < 4)
                    return -23;

                offset = next.Value;
                keyModOffset = offset;
                keyModSize = iSize;

                if (pData[keyModOffset] == 0)
                {
                    keyModOffset++;
                    keyModSize--;
                }

                if (keyModSize > pCert.KeyModData.Length)
                    return -24;

                pCert.iKeyModSize = keyModSize;
                CopyBytes(pCert.KeyModData, 0, keyModOffset, keyModSize);
                offset += iSize;

                next = ParseHeader(offset, iKeyOffset + iKeySize, out iType, out iSize);
                if (next == null ||
                    iType != (ProtoSSLConstants.ASN_TYPE_INTEGER + ProtoSSLConstants.ASN_PRIMITIVE) ||
                    iSize < 1)
                    return -25;

                offset = next.Value;
                keyExpOffset = offset;
                keyExpSize = iSize;

                if (pData[keyExpOffset] == 0)
                {
                    keyExpOffset++;
                    keyExpSize--;
                }

                if (keyExpSize > pCert.KeyExpData.Length)
                    return -26;

                pCert.iKeyExpSize = keyExpSize;
                CopyBytes(pCert.KeyExpData, 0, keyExpOffset, keyExpSize);
                offset += iSize;
            }

            // Hash the TBSCertificate bytes, matching the original algorithm
            int hashLength = infSkip - infOffset;

            switch (pCert.iSigType)
            {
                case ASN_OBJ_RSA_PKCS_MD5:
                {
                    var md5ctx = new CryptMD5();
                    md5ctx.Init();
                    md5ctx.Update(pData, infOffset, hashLength);
                    md5ctx.Final(pCert.HashData, 16);
                    break;
                }

                case ASN_OBJ_RSA_PKCS_SHA1:
                {
                    var sha1ctx = new CryptSHA1();
                    sha1ctx.Init();
                    sha1ctx.Update(pData, infOffset, (uint)hashLength);
                    sha1ctx.Final(pCert.HashData, 16);
                    break;
                }

                case ASN_OBJ_RSA_PKCS_MD2:
                    var md2ctx = new CryptMD2();
                    md2ctx.Init();
                    md2ctx.Update(pData, infOffset, hashLength);
                    md2ctx.Final(pCert.HashData, 16);
                    break;

                default:
                    pCert.iHashSize = 0;
                    break;
            }

            return 0;
        }

        private static int _VerifyCertificate(X509CertificateT pCert, int iSelfSigned)
        {
            var RSA = new CryptRSA();

            int iKeyModSize;
            int iKeyExpSize;

            byte[] pKeyModData;
            byte[] pKeyExpData;

            ProtoSSLCACertT? pCACert;

            if (iSelfSigned != 0 && _CompareIdent(pCert.Subject, pCert.Issuer) == 0)
            {
                pKeyModData = pCert.KeyModData;
                iKeyModSize = pCert.iKeyModSize;

                pKeyExpData = pCert.KeyExpData;
                iKeyExpSize = pCert.iKeyExpSize;

                pCACert = null;
            }
            else
            {
                pCACert = _ProtoSSL_CACerts;
                while (pCACert != null && _CompareIdent(pCACert.Subject, pCert.Issuer) != 0)
                {
                    pCACert = pCACert.pNext;
                }

                if (pCACert == null)
                {
                    //_DebugPrintCert(pCert, "_VerifyCertificate() -- no CA available for this certificate");

                    return -28;
                }

                if (pCACert.iKeyModSize != pCert.iSigSize)
                {
                    return -29;
                }

                pKeyModData = pCACert.pKeyModData;
                iKeyModSize = pCACert.iKeyModSize;

                pKeyExpData = pCACert.KeyExpData;
                iKeyExpSize = pCACert.iKeyExpSize;
            }

            RSA.Init(
                pKeyModData,
                iKeyModSize,
                pKeyExpData,
                iKeyExpSize);

            RSA.InitSignature(
                pCert.SigData,
                pCert.iSigSize);

            RSA.Encrypt();

            int iHashOffset =
                (pCert.iSigSize & 65534) - pCert.iHashSize;

            if (iHashOffset < 0 ||
                iHashOffset + pCert.iHashSize > RSA.EncryptBlock.Length ||
                pCert.iHashSize > pCert.HashData.Length)
            {
                return -30;
            }

            if (!pCert.HashData.AsSpan(0, pCert.iHashSize).SequenceEqual(
                    RSA.EncryptBlock.AsSpan(iHashOffset, pCert.iHashSize)))
            {
                //_DebugPrintCert(pCert, "failed cert");

                if (pCACert != null)
                {
                    //_DebugPrintCertIdent(pCACert.Subject, "parent ca");
                }

                return -30;
            }

            return 0;
        }

        private static void _AddCertificate(
            X509CertificateT pCert,
            int iMemGroup,
            object? pMemGroupUserData)
        {
            ProtoSSLCACertT? pCACert;

            // Проверяем, не добавлен ли уже такой сертификат.
            for (pCACert = _ProtoSSL_CACerts;
                pCACert != null &&
                _CompareIdent(pCACert.Subject, pCert.Subject) != 0;
                pCACert = pCACert.pNext)
            {
            }

            if (pCACert != null)
            {
                //_DebugPrintCert(pCert, "ignoring redundant add of CA cert");
                return;
            }

            // Находим последний элемент списка.
            pCACert = _ProtoSSL_CACerts;
            if (pCACert == null)
            {
                //_DebugPrintCert(pCert, "failed to allocate memory for cert");
                return;
            }

            while (pCACert.pNext != null)
            {
                pCACert = pCACert.pNext;
            }

            // Создаём новый узел списка.
            ProtoSSLCACertT pNewCert;

            try
            {
                pNewCert = new ProtoSSLCACertT();
            }
            catch (OutOfMemoryException)
            {
                //_DebugPrintCert(pCert, "failed to allocate memory for cert");
                return;
            }

            // Копируем Subject.
            pNewCert.Subject = new ProtoSSLCertIdentT
            {
                strCountry = pCert.Subject.strCountry,
                strState = pCert.Subject.strState,
                strCity = pCert.Subject.strCity,
                strOrg = pCert.Subject.strOrg,
                strUnit = pCert.Subject.strUnit,
                strCommon = pCert.Subject.strCommon
            };

            // Копируем открытый ключ RSA.
            pNewCert.iKeyExpSize = pCert.iKeyExpSize;
            Buffer.BlockCopy(
                pCert.KeyExpData, 0,
                pNewCert.KeyExpData, 0,
                pNewCert.iKeyExpSize);

            pNewCert.iKeyModSize = pCert.iKeyModSize;
            pNewCert.pKeyModData = new byte[pNewCert.iKeyModSize];

            Buffer.BlockCopy(
                pCert.KeyModData, 0,
                pNewCert.pKeyModData, 0,
                pNewCert.iKeyModSize);

            pNewCert.iMemGroup = iMemGroup;
            pNewCert.pMemGroupUserData = pMemGroupUserData;
            pNewCert.pNext = null;

            // Добавляем в конец связного списка.
            pCACert.pNext = pNewCert;

            //_DebugPrintCert(pCert, "added new certificate authority");
        }
    }
}