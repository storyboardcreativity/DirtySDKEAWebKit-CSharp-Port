using System;

namespace DirtySDKEAWebKit
{
    public sealed class CryptArc4
    {
        private readonly byte[] state = new byte[256];
        private byte walk;
        private byte swap;

        public CryptArc4()
        {
        }

        public void Init(byte[] keyBuf, int keyLen, int iter)
        {
            if (iter < 1)
            {
                iter = 1;
            }

            walk = 0;
            swap = 0;

            for (int i = 0; i < 256; ++i)
            {
                state[i] = (byte)i;
            }

            if (keyLen > 0)
            {
                byte uSwap = 0;

                for (; iter > 0; --iter)
                {
                    for (int uWalk = 0; uWalk < 256; ++uWalk)
                    {
                        uSwap = unchecked((byte)(
                            uSwap + state[uWalk] +
                            keyBuf[uWalk % keyLen]));

                        byte uTemp0 = state[uWalk];
                        byte uTemp1 = state[uSwap];

                        state[uWalk] = uTemp1;
                        state[uSwap] = uTemp0;
                    }
                }
            }
        }

        public void Apply(byte[] buffer, int length)
        {
            int uWalk = walk;
            int uSwap = swap;

            for (int i = 0; i < length; ++i)
            {
                uWalk = (uWalk + 1) & 255;
                uSwap = (uSwap + state[uWalk]) & 255;

                byte uTemp0 = state[uWalk];
                byte uTemp1 = state[uSwap];

                state[uWalk] = uTemp1;
                state[uSwap] = uTemp0;

                buffer[i] ^= state[(uTemp0 + uTemp1) & 255];
            }

            walk = (byte)uWalk;
            swap = (byte)uSwap;
        }

        public void Advance(int length)
        {
            int uWalk = walk;
            int uSwap = swap;

            for (; length > 0; --length)
            {
                uWalk = (uWalk + 1) & 255;
                uSwap = (uSwap + state[uWalk]) & 255;

                byte uTemp0 = state[uWalk];
                byte uTemp1 = state[uSwap];

                state[uWalk] = uTemp1;
                state[uSwap] = uTemp0;
            }

            walk = (byte)uWalk;
            swap = (byte)uSwap;
        }
    }
}