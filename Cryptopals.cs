//Author: Gregory Morse
//Class: ELTE Cryptography Protocols
//Task: C# cryptopals.com sets 1 and 2 implementations
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
//https://www.nuget.org/packages/Security.Cryptography/
//using CLR Security for fast AES GCM however this project originally at http://clrsecurity.codeplex.com and now https://github.com/MicrosoftArchive/clrsecurity is discontinued
//BouncyCastle has an implementation
//.NET Core 3.0 might have an implementation
using System.Text;

namespace ELTECSharp
{
    public class MD4 : HashAlgorithm
    {
        private uint _a;
        private uint _b;
        private uint _c;
        private uint _d;
        private uint[] _x;
        private ulong _bytesProcessed;
        private bool _dontInit = false;
        public MD4()
        {
            _x = new uint[16];
            Initialize();
        }
        public void InitFromHashLen(byte [] h, int blocks)
        {
            _a = BitConverter.ToUInt32(h, 0);
            _b = BitConverter.ToUInt32(h, 4);
            _c = BitConverter.ToUInt32(h, 8);
            _d = BitConverter.ToUInt32(h, 12);
            _bytesProcessed = (ulong)blocks * 64;
            _dontInit = true;
        }
        static public byte[] MD4Pad(byte[] message_array, int PriorBlocks = 0)
        {
            int r = message_array.Length % 64;
            return message_array.Concat(new byte[] { 0x80 }).Concat(Enumerable.Repeat((byte)0, 55 - r)).Concat(BitConverter.GetBytes((ulong)(message_array.Length * 8 + PriorBlocks * 64 * 8))).ToArray();
        }
        public override void Initialize()
        {
            if (!_dontInit)
            {
                _a = 0x67452301;
                _b = 0xefcdab89;
                _c = 0x98badcfe;
                _d = 0x10325476;

                _bytesProcessed = 0;
            }
            else _dontInit = false;
        }

        protected override void HashCore(byte[] array, int offset, int length)
        {
            ProcessMessage(array.Skip(offset).Take(length).ToArray());
        }

        protected override byte[] HashFinal()
        {
            try
            {
                ProcessMessage(Padding());

                return new uint[] { _a, _b, _c, _d }.SelectMany(word => BitConverter.GetBytes(word)).ToArray();
            }
            finally
            {
                Initialize();
            }
        }

        private void ProcessMessage(IEnumerable<byte> bytes)
        {
            foreach (byte b in bytes)
            {
                int c = (int)(_bytesProcessed & 63);
                int i = c >> 2;
                int s = (c & 3) << 3;

                _x[i] = (_x[i] & ~((uint)255 << s)) | ((uint)b << s);

                if (c == 63)
                {
                    Process16WordBlock();
                }

                _bytesProcessed++;
            }
        }
        private IEnumerable<byte> Padding()
        {
            return Enumerable.Repeat((byte)128, 1)
               .Concat(Enumerable.Repeat((byte)0, (int)(((_bytesProcessed + 8) & 0x7fffffc0) + 55 - _bytesProcessed)))
               .Concat(BitConverter.GetBytes((ulong)(_bytesProcessed << 3)));
        }

        private void Process16WordBlock()
        {
            uint aa = _a;
            uint bb = _b;
            uint cc = _c;
            uint dd = _d;

            foreach (int k in new[] { 0, 4, 8, 12 })
            {
                aa = Round1Operation(aa, bb, cc, dd, _x[k], 3);
                dd = Round1Operation(dd, aa, bb, cc, _x[k + 1], 7);
                cc = Round1Operation(cc, dd, aa, bb, _x[k + 2], 11);
                bb = Round1Operation(bb, cc, dd, aa, _x[k + 3], 19);
            }

            foreach (int k in new[] { 0, 1, 2, 3 })
            {
                aa = Round2Operation(aa, bb, cc, dd, _x[k], 3);
                dd = Round2Operation(dd, aa, bb, cc, _x[k + 4], 5);
                cc = Round2Operation(cc, dd, aa, bb, _x[k + 8], 9);
                bb = Round2Operation(bb, cc, dd, aa, _x[k + 12], 13);
            }

            foreach (int k in new[] { 0, 2, 1, 3 })
            {
                aa = Round3Operation(aa, bb, cc, dd, _x[k], 3);
                dd = Round3Operation(dd, aa, bb, cc, _x[k + 8], 9);
                cc = Round3Operation(cc, dd, aa, bb, _x[k + 4], 11);
                bb = Round3Operation(bb, cc, dd, aa, _x[k + 12], 15);
            }

            unchecked
            {
                _a += aa;
                _b += bb;
                _c += cc;
                _d += dd;
            }
        }

        private static uint ROL(uint value, int numberOfBits)
        {
            return (value << numberOfBits) | (value >> (32 - numberOfBits));
        }

        private static uint Round1Operation(uint a, uint b, uint c, uint d, uint xk, int s)
        {
            unchecked
            {
                return ROL(a + ((b & c) | (~b & d)) + xk, s);
            }
        }

        private static uint Round2Operation(uint a, uint b, uint c, uint d, uint xk, int s)
        {
            unchecked
            {
                return ROL(a + ((b & c) | (b & d) | (c & d)) + xk + 0x5a827999, s);
            }
        }
        private static uint Round3Operation(uint a, uint b, uint c, uint d, uint xk, int s)
        {
            unchecked
            {
                return ROL(a + (b ^ c ^ d) + xk + 0x6ed9eba1, s);
            }
        }
        private static uint ROR(uint value, int numberOfBits)
        {
            return (value >> numberOfBits) | (value << (32 - numberOfBits));
        }
        private static uint Unround1Operation(uint a, uint b, uint c, uint d, uint xk, int s)
        {
            unchecked
            {
                return ROR(xk, s) - a - ((b & c) | (~b & d));
            }
        }
        private static uint Unround2Operation(uint a, uint b, uint c, uint d, uint xk, int s)
        {
            unchecked
            {
                return ROR(xk, s) - a - ((b & c) | (b & d) | (c & d)) - 0x5a827999;
            }
        }
        private static uint Unround3Operation(uint a, uint b, uint c, uint d, uint xk, int s)
        {
            unchecked
            {
                return ROR(xk, s) - a - (b ^ c ^ d) - 0x6ed9eba1;
            }
        }
        public static byte[] ApplyWangDifferential(byte [] bytes)
        {
            uint[] x = new uint[16];
            int processed = 0;
            //padding can be added for short messages...
            //Enumerable.Repeat((byte)128, 1)
            //.Concat(Enumerable.Repeat((byte)0, (int)(((_bytesProcessed + 8) & 0x7fffffc0) + 55 - _bytesProcessed)))
            //.Concat(BitConverter.GetBytes((ulong)(_bytesProcessed << 3)));
            foreach (byte b in bytes) {
                int i = processed >> 2;
                int s = (processed & 3) << 3;
                x[i] = (x[i] & ~((uint)255 << s)) | ((uint)b << s);
                if (processed == 63) break;
                processed++;
            }
            unchecked
            {
                x[1] += ((uint)1 << 31);
                x[2] += ((uint)1 << 31) - (1 << 28);
                x[12] -= ((uint)1 << 16);
            }
            return x.SelectMany((b) => BitConverter.GetBytes(b)).ToArray();
        }
        public static bool VerifyConditions(uint[] x, uint a0, uint b0, uint c0, uint d0, uint a1, uint b1, uint c1, uint d1, uint a2, uint b2, uint c2, uint d2, uint a3, uint b3, uint c3, uint d3, uint a4, uint b4, uint c4, uint d4)
        {
            return a1 == Round1Operation(a0, b0, c0, d0, x[0], 3) &&
                d1 == Round1Operation(d0, a1, b0, c0, x[1], 7) &&
                c1 == Round1Operation(c0, d1, a1, b0, x[2], 11) &&
                b1 == Round1Operation(b0, c1, d1, a1, x[3], 19) &&
                a2 == Round1Operation(a1, b1, c1, d1, x[4], 3) &&
                d2 == Round1Operation(d1, a2, b1, c1, x[5], 7) &&
                c2 == Round1Operation(c1, d2, a2, b1, x[6], 11) &&
                b2 == Round1Operation(b1, c2, d2, a2, x[7], 19) &&
                a3 == Round1Operation(a2, b2, c2, d2, x[8], 3) &&
                d3 == Round1Operation(d2, a3, b2, c2, x[9], 7) &&
                c3 == Round1Operation(c2, d3, a3, b2, x[10], 11) &&
                b3 == Round1Operation(b2, c3, d3, a3, x[11], 19) &&
                a4 == Round1Operation(a3, b3, c3, d3, x[12], 3) &&
                d4 == Round1Operation(d3, a4, b3, c3, x[13], 7) &&
                c4 == Round1Operation(c3, d4, a4, b3, x[14], 11) &&
                b4 == Round1Operation(b3, c4, d4, a4, x[15], 19) &&
                ((a1 & (1 << 6)) == (b0 & (1 << 6))) &&
                (d1 & (1 << 6)) == 0 && (d1 & (1 << 7)) == (a1 & (1 << 7)) && (d1 & (1 << 10)) == (a1 & (1 << 10)) &&
                (c1 & (1 << 6)) != 0 && (c1 & (1 << 7)) != 0 && (c1 & (1 << 10)) == 0 && (c1 & (1 << 25)) == (d1 & (1 << 25)) &&
                (b1 & (1 << 6)) != 0 && (b1 & (1 << 7)) == 0 && (b1 & (1 << 10)) == 0 && (b1 & (1 << 25)) == 0 &&
                (a2 & (1 << 7)) != 0 && (a2 & (1 << 10)) != 0 && (a2 & (1 << 25)) == 0 && (a2 & (1 << 13)) == (b1 & (1 << 13)) &&
                (d2 & (1 << 13)) == 0 && (d2 & (1 << 25)) != 0 && (d2 & (1 << 18)) == (a2 & (1 << 18)) && (d2 & (1 << 19)) == (a2 & (1 << 19)) && (d2 & (1 << 20)) == (a2 & (1 << 20)) && (d2 & (1 << 21)) == (a2 & (1 << 21)) &&
                (c2 & (1 << 13)) == 0 && (c2 & (1 << 18)) == 0 && (c2 & (1 << 19)) == 0 && (c2 & (1 << 21)) == 0 && (c2 & (1 << 20)) != 0 && (c2 & (1 << 12)) == (d2 & (1 << 12)) && (c2 & (1 << 14)) == (d2 & (1 << 14)) &&
                (b2 & (1 << 12)) != 0 && (b2 & (1 << 13)) != 0 && (b2 & (1 << 14)) == 0 && (b2 & (1 << 18)) == 0 && (b2 & (1 << 19)) == 0 && (b2 & (1 << 20)) == 0 && (b2 & (1 << 21)) == 0 && (b2 & (1 << 16)) == (c2 & (1 << 16)) &&
                (a3 & (1 << 12)) != 0 && (a3 & (1 << 13)) != 0 && (a3 & (1 << 14)) != 0 && (a3 & (1 << 21)) != 0 && (a3 & (1 << 16)) == 0 && (a3 & (1 << 18)) == 0 && (a3 & (1 << 19)) == 0 && (a3 & (1 << 20)) == 0 && (a3 & (1 << 22)) == (b2 & (1 << 22)) && (a3 & (1 << 25)) == (b2 & (1 << 25)) &&
                (d3 & (1 << 16)) == 0 && (d3 & (1 << 19)) == 0 && (d3 & (1 << 22)) == 0 && (d3 & (1 << 12)) != 0 && (d3 & (1 << 13)) != 0 && (d3 & (1 << 14)) != 0 && (d3 & (1 << 20)) != 0 && (d3 & (1 << 21)) != 0 && (d3 & (1 << 25)) != 0 && (d3 & (1 << 29)) == (a3 & (1 << 29)) &&
                (c3 & (1 << 19)) == 0 && (c3 & (1 << 20)) == 0 && (c3 & (1 << 21)) == 0 && (c3 & (1 << 22)) == 0 && (c3 & (1 << 25)) == 0 && (c3 & (1 << 16)) != 0 && (c3 & (1 << 29)) != 0 && (c3 & ((uint)1 << 31)) == (d3 & ((uint)1 << 31)) &&
                (b3 & (1 << 20)) != 0 && (b3 & (1 << 21)) != 0 && (b3 & (1 << 25)) != 0 && (b3 & (1 << 19)) == 0 && (b3 & (1 << 29)) == 0 && (b3 & ((uint)1 << 31)) == 0 && (b3 & (1 << 22)) == (c3 & (1 << 22)) &&
                (a4 & (1 << 29)) != 0 && (a4 & (1 << 22)) == 0 && (a4 & (1 << 25)) == 0 && (a4 & ((uint)1 << 31)) == 0 && (a4 & (1 << 26)) == (b3 & (1 << 26)) && (a4 & (1 << 28)) == (b3 & (1 << 28)) &&
                (d4 & (1 << 22)) == 0 && (d4 & (1 << 25)) == 0 && (d4 & (1 << 29)) == 0 && (d4 & (1 << 26)) != 0 && (d4 & (1 << 28)) != 0 && (d4 & ((uint)1 << 31)) != 0 &&
                (c4 & (1 << 26)) == 0 && (c4 & (1 << 28)) == 0 && (c4 & (1 << 29)) == 0 && (c4 & (1 << 22)) != 0 && (c4 & (1 << 25)) != 0 && (c4 & (1 << 18)) == (d4 & (1 << 18)) &&
                (b4 & (1 << 25)) != 0 && (b4 & (1 << 26)) != 0 && (b4 & (1 << 28)) != 0 &&  (b4 & (1 << 18)) == 0 && (b4 & (1 << 29)) == 0 && (b4 & (1 << 25)) == (c4 & (1 << 25));
        }
        public static byte[] WangsAttack(byte[] bytes, bool bMulti, bool bNaito)
        {
            uint [] x = new uint[16];
            int processed = 0;
            //padding can be added for short messages...
            //Enumerable.Repeat((byte)128, 1)
               //.Concat(Enumerable.Repeat((byte)0, (int)(((_bytesProcessed + 8) & 0x7fffffc0) + 55 - _bytesProcessed)))
               //.Concat(BitConverter.GetBytes((ulong)(_bytesProcessed << 3)));
            foreach (byte b in bytes)
            {
                int i = processed >> 2;
                int s = (processed & 3) << 3;
                x[i] = (x[i] & ~((uint)255 << s)) | ((uint)b << s);
                if (processed == 63) break;
                processed++;
            }

            //step 1 - weak message - single step rules 2^25
            uint a0 = 0x67452301;
            uint b0 = 0xefcdab89;
            uint c0 = 0x98badcfe;
            uint d0 = 0x10325476;
            uint a1, a2, a3, a4, a5, a6, a7, a8, a9, a10;
            uint b1, b2, b3, b4, b5, b6, b7, b8, b9;
            uint c1, c2, c3, c4, c5, c6, c7, c8, c9;
            uint d1, d2, d3, d4, d5, d6, d7, d8, d9;

            //a1,7 = b0,7
            a1 = Round1Operation(a0, b0, c0, d0, x[0], 3);
            a1 ^= (a1 & (1 << 6)) ^ (b0 & (1 << 6));
            //extra condition to allow correcting d5,19 in 2nd round
            if (bMulti && bNaito) a1 ^= (a1 & (1 << 13)) ^ (b0 & (1 << 13));
            x[0] = Unround1Operation(a0, b0, c0, d0, a1, 3);

            //d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
            d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
            d1 &= ~(uint)(1 << 6);
            d1 ^= (d1 & (1 << 7)) ^ (a1 & (1 << 7)) ^ (d1 & (1 << 10)) ^ (a1 & (1 << 10));
            //extra condition to allow correcting d5,19 in 2nd round
            if (bMulti && bNaito) d1 &= ~(uint)(1 << 13);
            x[1] = Unround1Operation(d0, a1, b0, c0, d1, 7);

            //c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
            c1 = Round1Operation(c0, d1, a1, b0, x[2], 11);
            c1 |= (1 << 6) | (1 << 7);
            c1 &= ~(uint)(1 << 10);
            c1 ^= (c1 & (1 << 25)) ^ (d1 & (1 << 25));
            //extra condition to allow correcting d5,19 in 2nd round
            if (bMulti && bNaito) c1 &= ~(uint)(1 << 13);
            x[2] = Unround1Operation(c0, d1, a1, b0, c1, 11);

            //b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
            b1 = Round1Operation(b0, c1, d1, a1, x[3], 19);
            b1 |= (1 << 6);
            b1 &= ~(uint)((1 << 7) | (1 << 10) | (1 << 25));
            //extra condition to allow correcting d5,19 in 2nd round
            if (bMulti && bNaito) b1 &= ~(uint)(1 << 13);
            //extra condition to allow correcting a6,29, a6,30, a6,32 in 2nd round
            if (bMulti && bNaito) b1 |= (1 << 0) | (1 << 1) | (1 << 3);
            x[3] = Unround1Operation(b0, c1, d1, a1, b1, 19);

            //a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
            a2 = Round1Operation(a1, b1, c1, d1, x[4], 3);
            a2 |= (1 << 7) | (1 << 10);
            a2 &= ~(uint)(1 << 25);
            a2 ^= (a2 & (1 << 13)) ^ (b1 & (1 << 13));
            //extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
            if (bMulti) a2 ^= (a2 & (1 << (25 - 9))) ^ (b1 & (1 << (25 - 9))) ^ (a2 & (1 << (26 - 9))) ^ (b1 & (1 << (26 - 9))) ^ (bNaito ? 0 : (a2 & (1 << (28 - 9))) ^ (b1 & (1 << (28 - 9))) ^ (a2 & (1 << (31 - 9))) ^ (b1 & (1 << (31 - 9))));
            x[4] = Unround1Operation(a1, b1, c1, d1, a2, 3);

            //d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
            d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
            d2 &= ~(uint)(1 << 13);
            d2 |= (1 << 25);
            d2 ^= (d2 & (1 << 18)) ^ (a2 & (1 << 18)) ^ (d2 & (1 << 19)) ^ (a2 & (1 << 19)) ^ (d2 & (1 << 20)) ^ (a2 & (1 << 20)) ^ (d2 & (1 << 21)) ^ (a2 & (1 << 21));
            //extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
            if (bMulti) d2 &= ~(uint)((1 << (25 - 9)) | (1 << (26 - 9)) | (bNaito ? 0 : (1 << (28 - 9)) | (1 << (31 - 9))));
            //extra condition to allow correcting c6,32 in 2nd round
            if (bMulti && bNaito) d2 ^= (d2 & (1 << 22)) ^ (a2 & (1 << 22));
            x[5] = Unround1Operation(d1, a2, b1, c1, d2, 7);

            //c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
            c2 = Round1Operation(c1, d2, a2, b1, x[6], 11);
            c2 &= ~(uint)((1 << 13) | (1 << 18) | (1 << 19) | (1 << 21));
            c2 |= (1 << 20);
            c2 ^= (c2 & (1 << 12)) ^ (d2 & (1 << 12)) ^ (c2 & (1 << 14)) ^ (d2 & (1 << 14));
            //extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
            if (bMulti) c2 &= ~(uint)((1 << (25 - 9)) | (1 << (26 - 9)) | (bNaito ? 0 : (1 << (28 - 9)) | (1 << (31 - 9))));
            //extra condition to allow correcting c6,32 in 2nd round
            if (bMulti && bNaito) c2 &= ~(uint)(1 << 22);
            x[6] = Unround1Operation(c1, d2, a2, b1, c2, 11);

            //b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0, b2,20 = 0, b2,21 = 0, b2,22 = 0
            b2 = Round1Operation(b1, c2, d2, a2, x[7], 19);
            b2 |= (1 << 12) | (1 << 13);
            b2 &= ~(uint)((1 << 14) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21));
            b2 ^= (b2 & (1 << 16)) ^ (c2 & (1 << 16));
            //extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
            if (bMulti) b2 &= ~(uint)((1 << (25 - 9)) | (1 << (26 - 9)) | (bNaito ? 0 : (1 << (28 - 9)) | (1 << (31 - 9))));
            //extra condition to allow correcting d6,29 in 2nd round
            if (bMulti && bNaito) b2 |= (1 << 30);
            //extra condition to allow correcting c6,32 in 2nd round
            if (bMulti && bNaito) b2 &= ~(uint)(1 << 22);
            x[7] = Unround1Operation(b1, c2, d2, a2, b2, 19);

            //a3,13 = 1, a3,14 = 1, a3,15 = 1, a3,17 = 0, a3,19 = 0, a3,20 = 0, a3,21 = 0, a3,23 = b2,23, a3,22 = 1, a3,26 = b2,26
            a3 = Round1Operation(a2, b2, c2, d2, x[8], 3);
            a3 |= (1 << 12) | (1 << 13) | (1 << 14) | (1 << 21);
            a3 &= ~(uint)((1 << 16) | (1 << 18) | (1 << 19) | (1 << 20));
            a3 ^= (a3 & (1 << 22)) ^ (b2 & (1 << 22)) ^ (a3 & (1 << 25)) ^ (b2 & (1 << 25));
            x[8] = Unround1Operation(a2, b2, c2, d2, a3, 3);

            //d3,13 = 1, d3,14 = 1, d3,15 = 1, d3,17 = 0, d3,20 = 0, d3,21 = 1, d3,22 = 1, d3,23 = 0, d3,26 = 1, d3,30 = a3,30
            d3 = Round1Operation(d2, a3, b2, c2, x[9], 7);
            d3 &= ~(uint)((1 << 16) | (1 << 19) | (1 << 22));
            d3 |= (1 << 12) | (1 << 13) | (1 << 14) | (1 << 20 | (1 << 21) | (1 << 25));
            d3 ^= (d3 & (1 << 29)) ^ (a3 & (1 << 29));
            //extra condition to allow correcting b5,29, b5,32 in 2nd round
            if (bMulti && bNaito) d3 ^= (d3 & (1 << 15)) ^ (a3 & (1 << 15)) ^ (d3 & (1 << 18)) ^ (a3 & (1 << 18));
            x[9] = Unround1Operation(d2, a3, b2, c2, d3, 7);

            //c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 = 0, c3,23 = 0, c3,26 = 0, c3,30 = 1, c3,32 = d3,32
            c3 = Round1Operation(c2, d3, a3, b2, x[10], 11);
            c3 &= ~(uint)((1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 25));
            c3 |= (1 << 16) | (1 << 29);
            c3 ^= (c3 & ((uint)1 << 31)) ^ (d3 & ((uint)1 << 31));
            //extra condition to allow correcting c5,29, c5,32 in 2nd round
            if (bMulti && bNaito) c3 &= ~(uint)((1 << 15) | (1 << 18));
            //extra conditions to allow 3rd round corrections in x[11]
            if (bMulti && bNaito) c3 ^= (c3 & (1 << 0)) ^ (c3 & (1 << 1)) ^ (c3 & (1 << 2)) ^ (c3 & (1 << 3)) ^ (c3 & (1 << 4)) ^ (c3 & (1 << 5)) ^ (c3 & (1 << 6)) ^ (c3 & (1 << 7)) ^ (c3 & (1 << 8)) ^ (c3 & (1 << 9)) ^ (c3 & (1 << 10)) ^ (c3 & (1 << 11)) ^ (c3 & (1 << 12)) ^ (c3 & (1 << 13)) ^ (c3 & (1 << 14)) ^ (c3 & (1 << 17)) ^ (c3 & (1 << 23)) ^ (c3 & (1 << 24)) ^ (c3 & (1 << 30)) ^ (d3 & (1 << 0)) ^ (d3 & (1 << 1)) ^ (d3 & (1 << 2)) ^ (d3 & (1 << 3)) ^ (d3 & (1 << 4)) ^ (d3 & (1 << 5)) ^ (d3 & (1 << 6)) ^ (d3 & (1 << 7)) ^ (d3 & (1 << 8)) ^ (d3 & (1 << 9)) ^ (d3 & (1 << 10)) ^ (d3 & (1 << 11)) ^ (d3 & (1 << 12)) ^ (d3 & (1 << 13)) ^ (d3 & (1 << 14)) ^ (d3 & (1 << 17)) ^ (d3 & (1 << 23)) ^ (d3 & (1 << 24)) ^ (d3 & (1 << 30));
            x[10] = Unround1Operation(c2, d3, a3, b2, c3, 11);

            //b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1, b3,30 = 0, b3,32 = 0
            b3 = Round1Operation(b2, c3, d3, a3, x[11], 19);
            b3 |= (1 << 20) | (1 << 21) | (1 << 25);
            b3 &= ~(uint)((1 << 19) | (1 << 29) | ((uint)1 << 31));
            b3 ^= (b3 & (1 << 22)) ^ (c3 & (1 << 22));
            //extra condition to allow correcting c5,29, c5,32 in 2nd round
            if (bMulti && bNaito) b3 |= (1 << 15) | (1 << 18);
            //extra condition to allow correcting b5,30 in 2nd round
            if (bMulti && bNaito) b3 &= ~(uint)(1 << 16);
            //extra condition to allow correcting c6,29, c6,30 in 2nd round
            if (bMulti && bNaito) b3 |= (1 << 26) | (1 << 27);
            x[11] = Unround1Operation(b2, c3, d3, a3, b3, 19);

            //a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
            a4 = Round1Operation(a3, b3, c3, d3, x[12], 3);
            a4 |= (1 << 29);
            a4 &= ~(uint)((1 << 22) | (1 << 25) | ((uint)1 << 31));
            a4 ^= (a4 & (1 << 26)) ^ (b3 & (1 << 26)) ^ (a4 & (1 << 28)) ^ (b3 & (1 << 28));
            //extra condition to allow correcting c5,29, c5,32 in 2nd round
            if (bMulti && bNaito) a4 |= (1 << 15) | (1 << 18);
            //extra condition to allow correcting b5,30 in 2nd round
            if (bMulti && bNaito) a4 &= ~(uint)(1 << 16);
            //extra conditions to allow 3rd round corrections in x[11]
            if (bMulti && bNaito) a4 &= ~(uint)((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30));
            x[12] = Unround1Operation(a3, b3, c3, d3, a4, 3);

            //d4,23 = 0, d4,26 = 0, d4,27 = 1, d4,29 = 1, d4,30 = 0, d4,32 = 1
            d4 = Round1Operation(d3, a4, b3, c3, x[13], 7);
            d4 &= ~(uint)((1 << 22) | (1 << 25) | (1 << 29));
            d4 |= (1 << 26) | (1 << 28) | ((uint)1 << 31);
            //extra condition to allow correcting c5,29, c5,32 in 2nd round
            if (bMulti && bNaito) d4 ^= (d4 & (1 << 19)) ^ (a4 & (1 << 19)) ^ (d4 & (1 << 22)) ^ (a4 & (1 << 22));
            //extra condition to allow correcting b5,30 in 2nd round
            if (bMulti && bNaito) d4 |= (1 << 16);
            //extra conditions to allow 3rd round corrections in x[11]
            if (bMulti && bNaito) d4 &= ~(uint)((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30));
            x[13] = Unround1Operation(d3, a4, b3, c3, d4, 7);

            //c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
            c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
            c4 &= ~(uint)((1 << 26) | (1 << 28) | (1 << 29));
            c4 |= (1 << 22) | (1 << 25);
            c4 ^= (c4 & (1 << 18)) ^ (d4 & (1 << 18));
            //extra condition to allow correcting c5,29, c5,32 in 2nd round
            if (bMulti && bNaito) c4 &= ~(uint)((1 << 19) | (1 << 22)); //Note: this is a problem with the c5,32 correction in Naito where we stomp on a first round condition which is required now to be correct in the second round but not guaranteed!
            x[14] = Unround1Operation(c3, d4, a4, b3, c4, 11);

            //b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
            b4 = Round1Operation(b3, c4, d4, a4, x[15], 19);
            b4 |= (1 << 25) | (1 << 26) | (1 << 28);
            b4 &= ~(uint)((1 << 18) | (1 << 29));
            b4 ^= (b4 & (1 << 25)) ^ (c4 & (1 << 25));
            //newly discovered condition: b4,32 = c4,32
            if (bNaito) b4 ^= (b4 & ((uint)1 << 31)) ^ (c4 & ((uint)1 << 31));
            //extra condition to allow correcting c5,29, c5,32 in 2nd round
            if (bMulti && bNaito) b4 ^= (b4 & (1 << 19)) ^ (d4 & (1 << 19)) ^ (b4 & (1 << 22)) ^ (d4 & (1 << 22));
            x[15] = Unround1Operation(b3, c4, d4, a4, b4, 19);

            if (bMulti) {
                //round/step 2 and 3 - multi-step modification
                //must not "stomp" on the first round conditions
                int n = 0;
                uint[] bk = new uint[10];
                if (!bNaito)
                {
                    Array.Copy(x, bk, 10);
                    //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4)) { }
                }
                do
                    {
                    //a5,19 = c4,19, a5,26 = 1, a5,27 = 0, a5,29 = 1, a5,32 = 1
                    //must do these in exact order as arithmetic over and underflows must be handled
                    a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                    if ((a5 & (1 << 18)) != (c4 & (1 << 18)) || (a5 & (1 << 25)) == 0 || (a5 & (1 << 28)) == 0 || (a5 & ((uint)1 << 31)) == 0 || (a5 & (1 << 26)) != 0 || (bNaito && ((a5 & (1 << 19)) != (b4 & (1 << 19)) || (a5 & (1 << 22)) != (b4 & (1 << 22)))))
                    {
                        if ((a5 & (1 << 18)) != (c4 & (1 << 18))) {
                            x[0] = ((a1 & (1 << 18)) == 0) ? x[0] + (1 << 15) : x[0] - (1 << 15);
                            a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                        }
                        //extra condition to allow correcting c5,29, c5,32
                        if (bNaito)
                        {
                            if ((a5 & (1 << 19)) != (b4 & (1 << 19))) {
                                x[0] = ((a1 & (1 << 19)) == 0) ? x[0] + (1 << 16) : x[0] - (1 << 16);
                                a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                            }
                            if ((a5 & (1 << 22)) != (b4 & (1 << 22))) {
                                x[0] = ((a1 & (1 << 22)) == 0) ? x[0] + (1 << 19) : x[0] - (1 << 19);
                                a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                            }
                        }
                        if ((a5 & (1 << 25)) == 0) {
                            x[0] = x[0] + (1 << 22);
                            a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                        }
                        if ((a5 & (1 << 26)) != 0) {
                            x[0] = x[0] - (1 << 23);
                            a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                        }
                        if ((a5 & (1 << 28)) == 0) {
                            x[0] = x[0] + (1 << 25);
                            a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                        }
                        if ((a5 & ((uint)1 << 31)) == 0) {
                            x[0] = x[0] + (1 << 28);
                            a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                        }
                        a1 = Round1Operation(a0, b0, c0, d0, x[0], 3);
                        x[1] = Unround1Operation(d0, a1, b0, c0, d1, 7);
                        x[2] = Unround1Operation(c0, d1, a1, b0, c1, 11);
                        x[3] = Unround1Operation(b0, c1, d1, a1, b1, 19);
                        x[4] = Unround1Operation(a1, b1, c1, d1, a2, 3);
                    }
                    //x[0] = Unround2Operation(a4, b4, c4, d4, a5, 3);

                    //d5,19 = a5,19, d5,26 = b4,26, d5,27 = b4,27, d5,29 = b4,29, d5,32 = b4,32
                    d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                    if ((d5 & (1 << 18)) != (a5 & (1 << 18)) || (d5 & (1 << 25)) != (b4 & (1 << 25)) || (d5 & (1 << 26)) != (b4 & (1 << 26)) || (d5 & (1 << 28)) != (b4 & (1 << 28)) ||
                        (bNaito && (d5 & ((uint)1 << 31)) != (b4 & ((uint)1 << 31))))
                    {
                        if ((d5 & (1 << 18)) != (a5 & (1 << 18))) {
                            if (bNaito) {
                                x[1] = (d1 & (1 << 13)) == 0 ? x[1] + (1 << 6) : x[1] - (1 << 6);
                                d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
                                x[4] = Unround1Operation(a1, b1, c1, d1, a2, 3);
                            } else {
                                x[4] = ((a2 & (1 << 16)) == 0) ? x[4] + (1 << 13) : x[4] - (1 << 13);
                            }
                            d5 = Round2Operation(d4, a5, b4, c4, x[4], 5); //stomps on c5,26 extra condition a2,17=b2,17 if d5,19 not properly modified
                        }
                        if ((d5 & (1 << 25)) != (b4 & (1 << 25))) {
                            x[4] = ((a2 & (1 << 23)) == 0) ? x[4] + (1 << 20) : x[4] - (1 << 20);
                            d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                        }
                        if ((d5 & (1 << 26)) != (b4 & (1 << 26))) {
                            x[4] = ((a2 & (1 << 24)) == 0) ? x[4] + (1 << 21) : x[4] - (1 << 21);
                            d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                        }
                        if ((d5 & (1 << 28)) != (b4 & (1 << 28))) {
                            x[4] = ((a2 & (1 << 26)) == 0) ? x[4] + (1 << 23) : x[4] - (1 << 23);
                            d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                        }
                        if (bNaito)
                        {
                            if ((d5 & ((uint)1 << 31)) != (b4 & ((uint)1 << 31))) {
                                x[4] = ((a2 & (1 << 29)) == 0) ? x[4] + (1 << 26) : x[4] - (1 << 26);
                                d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                            }
                        }
                        a2 = Round1Operation(a1, b1, c1, d1, x[4], 3);
                        x[5] = Unround1Operation(d1, a2, b1, c1, d2, 7);
                        x[6] = Unround1Operation(c1, d2, a2, b1, c2, 11);
                        x[7] = Unround1Operation(b1, c2, d2, a2, b2, 19);
                        x[8] = Unround1Operation(a2, b2, c2, d2, a3, 3);
                    }
                    //d5 ^= (d5 & ((uint)1 << 31)) ^ (b4 & ((uint)1 << 31));
                    //x[4] = Unround2Operation(d4, a5, b4, c4, d5, 5);

                    //c5,26 = d5,26, c5,27 = d5,27, c5,29 = d5,29, c5,30 = d5,30, c5,32 = d5,32
                    c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                    //c5,26 when not equal to d5,19 and c5,29 are stomping on first round conditions and must have more modifications to correct
                    if ((c5 & (1 << 25)) != (d5 & (1 << 25))) {
                        x[5] = x[5] + (1 << 9);
                        d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                        x[8] = Unround1Operation(a2, b2, c2, d2, a3, 3);
                        c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                    }                    
                    if ((c5 & (1 << 26)) != (d5 & (1 << 26))) {
                        x[5] = x[5] + (1 << 10);
                        d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                        x[8] = Unround1Operation(a2, b2, c2, d2, a3, 3);
                        c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                    }
                    if (bNaito) {
                        if ((c5 & (1 << 28)) != (d5 & (1 << 28))) {
                            x[14] = x[14] + (1 << 8);
                            c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
                            c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                        }
                        if ((c5 & (1 << 29)) != (d5 & (1 << 29))) {
                            if ((c5 & (1 << 29)) != (d5 & (1 << 29))) x[8] = ((a3 & (1 << 23)) == 0) ? x[8] + (1 << 20) : x[8] - (1 << 20);
                            a3 = Round1Operation(a2, b2, c2, d2, x[8], 3);
                            //x[9] = Unround1Operation(d2, a3, b2, c2, d3, 7);
                            x[10] = Unround1Operation(c2, d3, a3, b2, c3, 11);
                            x[11] = Unround1Operation(b2, c3, d3, a3, b3, 19);
                            x[12] = Unround1Operation(a3, b3, c3, d3, a4, 3);
                            c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                        }
                        if ((c5 & ((uint)1 << 31)) != (d5 & ((uint)1 << 31)))
                        {
                            x[14] = x[14] + (1 << 11);
                            c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
                            c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                        }
                    } else {
                        //Naito already has this corrected by prior modifications
                        if ((c5 & (1 << 28)) != (d5 & (1 << 28))) {
                            x[5] = x[5] + (1 << 12);
                            d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                            x[8] = Unround1Operation(a2, b2, c2, d2, a3, 3);
                            c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                        }
                        if ((c5 & (1 << 31)) != (d5 & (1 << 31))) {
                            x[5] = x[5] + (1 << 15);
                            d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                            x[8] = Unround1Operation(a2, b2, c2, d2, a3, 3);
                            c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                        }
                    }
                    d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                    x[9] = Unround1Operation(d2, a3, b2, c2, d3, 7);
                    //c5 ^= (c5 & (1 << 29)) ^ (d5 & (1 << 29));
                    //x[8] = Unround2Operation(c4, d5, a5, b4, c5, 9);

                    if (!bNaito) {
                        b5 = Round2Operation(b4, c5, d5, a5, x[12], 13);
                        a6 = Round2Operation(a5, b5, c5, d5, x[1], 3);
                        d6 = Round2Operation(d5, a6, b5, c5, x[5], 5);
                        c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                        b6 = Round2Operation(b5, c6, d6, a6, x[13], 13);
                        a7 = Round2Operation(a6, b6, c6, d6, x[2], 3);
                        d7 = Round2Operation(d6, a7, b6, c6, x[6], 5);
                        c7 = Round2Operation(c6, d7, a7, b6, x[10], 9);
                        b7 = Round2Operation(b6, c7, d7, a7, x[14], 13);
                        a8 = Round2Operation(a7, b7, c7, d7, x[3], 3);
                        d8 = Round2Operation(d7, a8, b7, c7, x[7], 5);
                        c8 = Round2Operation(c7, d8, a8, b7, x[11], 9);
                        b8 = Round2Operation(b7, c8, d8, a8, x[15], 13);
                        a9 = Round3Operation(a8, b8, c8, d8, x[0], 3);
                        d9 = Round3Operation(d8, a9, b8, c8, x[8], 9);
                        c9 = Round3Operation(c8, d9, a9, b8, x[4], 11);
                        b9 = Round3Operation(b8, c9, d9, a9, x[12], 15);
                        a10 = Round3Operation(a9, b9, c9, d9, x[2], 3);
                        if (((a5 & (1 << 18)) != (c4 & (1 << 18)) || (a5 & (1 << 25)) == 0 || (a5 & (1 << 28)) == 0 || (a5 & ((uint)1 << 31)) == 0 || (a5 & (1 << 26)) != 0 || (bNaito && ((a5 & (1 << 19)) != (b4 & (1 << 19)) || (a5 & (1 << 22)) != (b4 & (1 << 22))))) ||
    ((d5 & (1 << 18)) != (a5 & (1 << 18)) || (d5 & (1 << 25)) != (b4 & (1 << 25)) || (d5 & (1 << 26)) != (b4 & (1 << 26)) || (d5 & (1 << 28)) != (b4 & (1 << 28)) ||
        (bNaito && (d5 & ((uint)1 << 31)) != (b4 & ((uint)1 << 31)))) ||
    ((c5 & (1 << 25)) != (d5 & (1 << 25)) || (c5 & (1 << 26)) != (d5 & (1 << 26)) || (c5 & (1 << 28)) != (d5 & (1 << 28)) || (c5 & (1 << 29)) != (d5 & (1 << 29)) || (c5 & ((uint)1 << 31)) != (d5 & ((uint)1 << 31))) ||
    ((b5 & (1 << 28)) != (c5 & (1 << 28)) || (b5 & (1 << 29)) == 0 || (b5 & ((uint)1 << 31)) != 0) ||
    ((a6 & (1 << 28)) == 0 || (a6 & (1 << 29)) != 0 || (a6 & ((uint)1 << 31)) == 0) ||
    (d6 & (1 << 28)) != (b5 & (1 << 28)) ||
    ((c6 & (1 << 28)) != (d6 & (1 << 28)) || (c6 & (1 << 29)) == (d6 & (1 << 29)) || (c6 & (1 << 31)) == (d6 & (1 << 31))) ||
    ((b9 & ((uint)1 << 31)) == 0 || (a10 & ((uint)1 << 31)) == 0) ||
    !VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4)
    )
                        {
                            Array.Copy(bk, x, 10); //restore x[0]-x[9]
                            a1 = Round1Operation(a0, b0, c0, d0, x[0], 3);
                            a2 = Round1Operation(a1, b1, c1, d1, x[4], 3);
                            d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                            byte[] b = new byte[8];
                            rng.GetBytes(b);
                            x[14] = BitConverter.ToUInt32(b, 0);
                            x[15] = BitConverter.ToUInt32(b, 4);
                            //c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
                            c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
                            c4 &= ~(uint)((1 << 26) | (1 << 28) | (1 << 29));
                            c4 |= (1 << 22) | (1 << 25);
                            c4 ^= (c4 & (1 << 18)) ^ (d4 & (1 << 18));
                            //extra condition to allow correcting c5,29, c5,32 in 2nd round
                            if (bMulti && bNaito) c4 &= ~(uint)((1 << 19) | (1 << 22));
                            x[14] = Unround1Operation(c3, d4, a4, b3, c4, 11);

                            //b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
                            b4 = Round1Operation(b3, c4, d4, a4, x[15], 19);
                            b4 |= (1 << 25) | (1 << 26) | (1 << 28);
                            b4 &= ~(uint)((1 << 18) | (1 << 29));
                            b4 ^= (b4 & (1 << 25)) ^ (c4 & (1 << 25));
                            //newly discovered condition: b4,32 = c4,32
                            if (bNaito) b4 ^= (b4 & ((uint)1 << 31)) ^ (c4 & ((uint)1 << 31));
                            //extra condition to allow correcting c5,29, c5,32 in 2nd round
                            if (bMulti && bNaito) b4 ^= (b4 & (1 << 19)) ^ (d4 & (1 << 19)) ^ (b4 & (1 << 22)) ^ (d4 & (1 << 22));
                            x[15] = Unround1Operation(b3, c4, d4, a4, b4, 19);
                            n++;
                        }
                        else { Console.WriteLine(n); break; }
                    }
                } while (!bNaito);
                if (bNaito) {
                    //b5,29 = c5,29, b5,30 = 1, b5,32 = 0
                    b5 = Round2Operation(b4, c5, d5, a5, x[12], 13);
                    if ((b5 & (1 << 28)) != (c5 & (1 << 28)))
                    {
                        x[10] = (c3 & (1 << 15)) == 0 ? x[10] + (1 << 4) : x[10] - (1 << 4);
                        c3 = Round1Operation(c2, d3, a3, b2, x[10], 11);
                        x[12] = Unround1Operation(a3, b3, c3, d3, a4, 3);
                        b5 = Round2Operation(b4, c5, d5, a5, x[12], 13);
                        x[14] = Unround1Operation(c3, d4, a4, b3, c4, 11);
                    }
                    if ((b5 & (1 << 29)) == 0)
                    {
                        x[11] = x[11] + (1 << 29);
                        b3 = Round1Operation(b2, c3, d3, a3, x[11], 19);
                        x[12] = Unround1Operation(a3, b3, c3, d3, a4, 3);
                        b5 = Round2Operation(b4, c5, d5, a5, x[12], 13);
                        x[15] = Unround1Operation(b3, c4, d4, a4, b4, 19);
                    }
                    if ((b5 & ((uint)1 << 31)) != 0)
                    {
                        x[10] = (c3 & (1 << 18)) == 0 ? x[10] + (1 << 7) : x[10] - (1 << 7);
                        c3 = Round1Operation(c2, d3, a3, b2, x[10], 11);
                        x[12] = Unround1Operation(a3, b3, c3, d3, a4, 3);
                        b5 = Round2Operation(b4, c5, d5, a5, x[12], 13);
                        x[14] = Unround1Operation(c3, d4, a4, b3, c4, 11);
                    }

                    //b5 |= (1 << 29);
                //b5 &= ~(uint)(((uint)1 << 31));
                //b5 ^= (b5 & (1 << 28)) ^ (c5 & (1 << 28));
                //x[12] = Unround2Operation(b4, c5, d5, a5, b5, 13);

                //a6,29 = 1, a6,32 = 1
                //newly discovered condition: a6,30 = 0
                a6 = Round2Operation(a5, b5, c5, d5, x[1], 3);
                    if ((a6 & (1 << 28)) == 0)
                    {
                        x[1] = (d1 & (1 << 0)) == 0 ? x[1] + (1 << 25) : x[1] - (1 << 25);
                        d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
                        a6 = Round2Operation(a5, b5, c5, d5, x[1], 3);
                        x[2] = Unround1Operation(c0, d1, a1, b0, c1, 11);
                        x[3] = Unround1Operation(b0, c1, d1, a1, b1, 19);
                        x[5] = Unround1Operation(d1, a2, b1, c1, d2, 7);
                    }
                    if ((a6 & (1 << 29)) != 0)
                    {
                        x[1] = (d1 & (1 << 1)) == 0 ? x[1] + (1 << 26) : x[1] - (1 << 26);
                        d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
                        a6 = Round2Operation(a5, b5, c5, d5, x[1], 3);
                        x[2] = Unround1Operation(c0, d1, a1, b0, c1, 11);
                        x[3] = Unround1Operation(b0, c1, d1, a1, b1, 19);
                        x[5] = Unround1Operation(d1, a2, b1, c1, d2, 7);
                    }
                    if ((a6 & ((uint)1 << 31)) == 0)
                    {
                        x[1] = (d1 & (1 << 3)) == 0 ? x[1] + (1 << 28) : x[1] - (1 << 28);
                        d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
                        a6 = Round2Operation(a5, b5, c5, d5, x[1], 3);
                        x[2] = Unround1Operation(c0, d1, a1, b0, c1, 11);
                        x[3] = Unround1Operation(b0, c1, d1, a1, b1, 19);
                        x[5] = Unround1Operation(d1, a2, b1, c1, d2, 7);
                    }
                //a6 |= (1 << 28) | ((uint)1 << 31);
                //x[1] = Unround2Operation(a5, b5, c5, d5, a6, 3);
                
                //d6,29 = b5,29
                d6 = Round2Operation(d5, a6, b5, c5, x[5], 5);
                    if ((d6 & (1 << 28)) != (b5 & (1 << 28)))
                    {
                        x[5] = ((d2 & (1 << 30)) == 0) ? x[5] + (1 << 23) : x[5] - (1 << 23);
                        d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                        d6 = Round2Operation(d5, a6, b5, c5, x[5], 5);
                        x[6] = Unround1Operation(c1, d2, a2, b1, c2, 11);
                        x[7] = Unround1Operation(b1, c2, d2, a2, b2, 19);
                        x[9] = Unround1Operation(d2, a3, b2, c2, d3, 7);
                    }
                //d6 ^= (d6 & (1 << 28)) ^ (b5 & (1 << 28));
                //x[5] = Unround2Operation(d5, a6, b5, c5, d6, 5);

                //c6,29 = d6,29, c6,30 = d6,30 + 1, c6,32 = d6,32 + 1
                c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                    if ((c6 & (1 << 28)) != (d6 & (1 << 28)))
                    {
                        x[9] = (d3 & (1 << 26)) == 0 ? x[9] + (1 << 19) : x[9] - (1 << 19);
                        d3 = Round1Operation(d2, a3, b2, c2, x[9], 7);
                        c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                        x[10] = Unround1Operation(c2, d3, a3, b2, c3, 11);
                        x[11] = Unround1Operation(b2, c3, d3, a3, b3, 19);
                        x[13] = Unround1Operation(d3, a4, b3, c3, d4, 7);
                    }
                    if ((c6 & (1 << 29)) == (d6 & (1 << 29)))
                    {
                        x[9] = (d3 & (1 << 27)) == 0 ? x[9] + (1 << 20) : x[9] - (1 << 20);
                        d3 = Round1Operation(d2, a3, b2, c2, x[9], 7);
                        c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                        x[10] = Unround1Operation(c2, d3, a3, b2, c3, 11);
                        x[11] = Unround1Operation(b2, c3, d3, a3, b3, 19);
                        x[13] = Unround1Operation(d3, a4, b3, c3, d4, 7);
                    }
                    if ((c6 & (1 << 31)) == (d6 & (1 << 31)))
                    {
                        x[6] = (c2 & (1 << 22)) == 0 ? x[6] + (1 << 11) : x[6] - (1 << 11);
                        c2 = Round1Operation(c1, d2, a2, b1, x[6], 11);
                        x[9] = Unround1Operation(d2, a3, b2, c2, d3, 7);
                        c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                        x[10] = Unround1Operation(c2, d3, a3, b2, c3, 11);
                    }
                    //c6 ^= (c6 & (1 << 28)) ^ (d6 & (1 << 28)) ^ (c6 & (1 << 29)) ^ (d6 & (1 << 29)) ^ (1 << 29) ^ (c6 & ((uint)1 << 31)) ^ (d6 & ((uint)1 << 31)) ^ ((uint)1 << 31);
                    //x[9] = Unround2Operation(c5, d6, a6, b5, c6, 9);

                    //...round 3 modifications for exact collision not known how to hold without stomping on rounds 1 and 2
                    b6 = Round2Operation(b5, c6, d6, a6, x[13], 13);
                    a7 = Round2Operation(a6, b6, c6, d6, x[2], 3);
                    d7 = Round2Operation(d6, a7, b6, c6, x[6], 5);
                    c7 = Round2Operation(c6, d7, a7, b6, x[10], 9);
                    b7 = Round2Operation(b6, c7, d7, a7, x[14], 13);
                    a8 = Round2Operation(a7, b7, c7, d7, x[3], 3);
                    d8 = Round2Operation(d7, a8, b7, c7, x[7], 5);
                    c8 = Round2Operation(c7, d8, a8, b7, x[11], 9);
                    b8 = Round2Operation(b7, c8, d8, a8, x[15], 13);
                    a9 = Round3Operation(a8, b8, c8, d8, x[0], 3);
                    d9 = Round3Operation(d8, a9, b8, c8, x[8], 9);
                    c9 = Round3Operation(c8, d9, a9, b8, x[4], 11);
                    if (((a5 & (1 << 18)) != (c4 & (1 << 18)) || (a5 & (1 << 25)) == 0 || (a5 & (1 << 28)) == 0 || (a5 & ((uint)1 << 31)) == 0 || (a5 & (1 << 26)) != 0 || (bNaito && ((a5 & (1 << 19)) != (b4 & (1 << 19)) || (a5 & (1 << 22)) != (b4 & (1 << 22))))) ||
    ((d5 & (1 << 18)) != (a5 & (1 << 18)) || (d5 & (1 << 25)) != (b4 & (1 << 25)) || (d5 & (1 << 26)) != (b4 & (1 << 26)) || (d5 & (1 << 28)) != (b4 & (1 << 28)) ||
        (bNaito && (d5 & ((uint)1 << 31)) != (b4 & ((uint)1 << 31)))) ||
    ((c5 & (1 << 25)) != (d5 & (1 << 25)) || (c5 & (1 << 26)) != (d5 & (1 << 26)) || (c5 & (1 << 28)) != (d5 & (1 << 28)) || (c5 & (1 << 29)) != (d5 & (1 << 29)) || (c5 & ((uint)1 << 31)) != (d5 & ((uint)1 << 31))) ||
    ((b5 & (1 << 28)) != (c5 & (1 << 28)) || (b5 & (1 << 29)) == 0 || (b5 & ((uint)1 << 31)) != 0) ||
    ((a6 & (1 << 28)) == 0 || (a6 & (1 << 29)) != 0 || (a6 & ((uint)1 << 31)) == 0) ||
    (d6 & (1 << 28)) != (b5 & (1 << 28)) ||
    ((c6 & (1 << 28)) != (d6 & (1 << 28)) || (c6 & (1 << 29)) == (d6 & (1 << 29)) || (c6 & (1 << 31)) == (d6 & (1 << 31))) ||
    !VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4)
    )
                    {
                        a1++; a1--; return x.SelectMany((b) => BitConverter.GetBytes(b)).ToArray();
                    }
                        //return x.SelectMany((b) => BitConverter.GetBytes(b)).ToArray();
                        //for all values except b3,20, b3,21, b3,22, b3,23, b3,26, b3,30, b3,32 + b3,27, b3,29 + b3,16, b3,17, b3,19, b3,28
                        //cannot stomp on these first round bit positions either: 10, 12, 29 + 7, 9, 10, 28, 31 + 0, 3, 7, 9, 12, 29
                        int[] permutebits = new int[] { 4, 5, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 30 }; //{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17, 23, 24, 30 };
                    uint b3init = b3;
                    for (int i = 0; i < (1 << 19); i++) {
                        //b9,32 = 1
                        b9 = Round3Operation(b8, c9, d9, a9, x[12], 15);
                        //b9 |= ((uint)1 << 31);
                        //x[12] = Unround3Operation(b8, c9, d9, a9, b9, 15);

                        //a10,32 = 1
                        a10 = Round3Operation(a9, b9, c9, d9, x[2], 3);
                        //a10 |= ((uint)1 << 31);
                        //x[2] = Unround3Operation(a9, b9, c9, d9, a10, 3);
                        if ((b9 & ((uint)1 << 31)) != 0 && (a10 & ((uint)1 << 31)) != 0) break;

                        b3 = b3init;
                        for (int c = 0; c < 19; c++) {
                            if ((i & (1 << c)) != 0) {
                                x[11] = (b3 & ((uint)1 << ((19 + permutebits[c]) % 32))) == 0 ? x[11] + ((uint)1 << (0 + permutebits[c])) : x[11] - ((uint)1 << (0 + permutebits[c]));
                                b3 = Round1Operation(b2, c3, d3, a3, x[11], 19);
                            }
                        }
                        x[15] = Unround1Operation(b3, c4, d4, a4, b4, 19);
                        if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4))
                        {
                            a1++; a1--;
                        }
                        /*a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                        d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                        c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                        b5 = Round2Operation(b4, c5, d5, a5, x[12], 13);
                        a6 = Round2Operation(a5, b5, c5, d5, x[1], 3);
                        d6 = Round2Operation(d5, a6, b5, c5, x[5], 5);
                        c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                        b6 = Round2Operation(b5, c6, d6, a6, x[13], 13);
                        a7 = Round2Operation(a6, b6, c6, d6, x[2], 3);
                        d7 = Round2Operation(d6, a7, b6, c6, x[6], 5);
                        c7 = Round2Operation(c6, d7, a7, b6, x[10], 9);
                        b7 = Round2Operation(b6, c7, d7, a7, x[14], 13);
                        a8 = Round2Operation(a7, b7, c7, d7, x[3], 3);
                        d8 = Round2Operation(d7, a8, b7, c7, x[7], 5);*/
                        c8 = Round2Operation(c7, d8, a8, b7, x[11], 9);
                        b8 = Round2Operation(b7, c8, d8, a8, x[15], 13);
                        a9 = Round3Operation(a8, b8, c8, d8, x[0], 3);
                        d9 = Round3Operation(d8, a9, b8, c8, x[8], 9);
                        c9 = Round3Operation(c8, d9, a9, b8, x[4], 11);
                    }
                }

            }

            return x.SelectMany((b) => BitConverter.GetBytes(b)).ToArray();
        }
    }
    public class SHA1_Algo
    {
        static UInt32 SHA1HashSize = 20;
        enum SHA_enum
        {
            shaSuccess = 0,
            shaNull,            /* Null pointer parameter */
            shaInputTooLong,    /* input data too long */
            shaStateError       /* called Input after Result */
        };

        static public int SHA1ResetFromHashLen(SHA1Context context, byte [] h, int blocks)
        {
            if (context == null)
            {
                return (int)SHA_enum.shaNull;
            }

            context.Length_Low = (uint)blocks * 64 * 8;
            context.Length_High = 0;
            context.Message_Block_Index = 0;

            context.Intermediate_Hash[0] = BitConverter.ToUInt32(h.Reverse().ToArray(), 16);
            context.Intermediate_Hash[1] = BitConverter.ToUInt32(h.Reverse().ToArray(), 12);
            context.Intermediate_Hash[2] = BitConverter.ToUInt32(h.Reverse().ToArray(), 8);
            context.Intermediate_Hash[3] = BitConverter.ToUInt32(h.Reverse().ToArray(), 4);
            context.Intermediate_Hash[4] = BitConverter.ToUInt32(h.Reverse().ToArray(), 0);

            context.Computed = 0;
            context.Corrupted = 0;
            return (int)SHA_enum.shaSuccess;
        }
        
        static public byte[] SHA1Pad(byte[] message_array, int PriorBlocks = 0)
        {
            int r = message_array.Length % 64;
            return message_array.Concat(new byte[] { 0x80 }).Concat(Enumerable.Repeat((byte)0, (r >= 56 ? 64 : 0) + 55 - r)).Concat(BitConverter.GetBytes((ulong)(message_array.Length * 8 + PriorBlocks * 64 * 8)).Reverse()).ToArray();
        }

        static public int SHA1Reset(SHA1Context context)
        {
            if (context == null)
            {
                return (int)SHA_enum.shaNull;
            }

            context.Length_Low = 0;
            context.Length_High = 0;
            context.Message_Block_Index = 0;

            context.Intermediate_Hash[0] = 0x67452301;
            context.Intermediate_Hash[1] = 0xEFCDAB89;
            context.Intermediate_Hash[2] = 0x98BADCFE;
            context.Intermediate_Hash[3] = 0x10325476;
            context.Intermediate_Hash[4] = 0xC3D2E1F0;

            context.Computed = 0;
            context.Corrupted = 0;
            return (int)SHA_enum.shaSuccess;
        }

        static public int SHA1Input(SHA1Context context, byte[] message_array)
        {
            uint length = (uint)message_array.Length;
            if (length == 0) { return (int)SHA_enum.shaSuccess; }
            if (context == null || message_array == null) { return (int)SHA_enum.shaNull; }

            if (context.Computed != 0)
            {
                context.Corrupted = (int)SHA_enum.shaStateError;
                return (int)SHA_enum.shaStateError;
            }

            if (context.Corrupted != 0) { return context.Corrupted; }

            int i = 0;
            while (length != 0 && context.Corrupted == 0)
            {
                length--;
                context.Message_Block[context.Message_Block_Index++] = (byte)(message_array[i] & 0xFF);
                context.Length_Low += 8;
                if (context.Length_Low == 0)
                {
                    context.Length_High++;
                    if (context.Length_High == 0)
                    {
                        /* Message is too long */
                        context.Corrupted = 1;
                    }
                }

                if (context.Message_Block_Index == 64) { SHA1ProcessMessageBlock(context); }
                i++;
            }
            return (int)SHA_enum.shaSuccess;
        }

        static void SHA1ProcessMessageBlock(SHA1Context context)
        {
            UInt32[] K = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
            int t;                        /* Loop counter                */
            UInt32 temp;                  /* Temporary word value        */
            UInt32[] W = new UInt32[80];  /* Word sequence               */
            UInt32 A, B, C, D, E;         /* Word buffers                */

            /* Initialize the first 16 words in the array W    */
            for (t = 0; t < 16; t++)
            {
                W[t] = ((UInt32)context.Message_Block[t * 4]) << 24;
                W[t] |= (UInt32)context.Message_Block[t * 4 + 1] << 16;
                W[t] |= (UInt32)context.Message_Block[t * 4 + 2] << 8;
                W[t] |= (UInt32)context.Message_Block[t * 4 + 3];
            }

            for (t = 16; t < 80; t++)
            {
                W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
            }

            A = context.Intermediate_Hash[0];
            B = context.Intermediate_Hash[1];
            C = context.Intermediate_Hash[2];
            D = context.Intermediate_Hash[3];
            E = context.Intermediate_Hash[4];

            for (t = 0; t < 20; t++)
            {
                temp = SHA1CircularShift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
                E = D;
                D = C;
                C = SHA1CircularShift(30, B);
                B = A;
                A = temp;
            }

            for (t = 20; t < 40; t++)
            {
                temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
                E = D;
                D = C;
                C = SHA1CircularShift(30, B);
                B = A;
                A = temp;
            }

            for (t = 40; t < 60; t++)
            {
                temp = SHA1CircularShift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
                E = D;
                D = C;
                C = SHA1CircularShift(30, B);
                B = A;
                A = temp;
            }

            for (t = 60; t < 80; t++)
            {
                temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
                E = D;
                D = C;
                C = SHA1CircularShift(30, B);
                B = A;
                A = temp;
            }

            context.Intermediate_Hash[0] += A;
            context.Intermediate_Hash[1] += B;
            context.Intermediate_Hash[2] += C;
            context.Intermediate_Hash[3] += D;
            context.Intermediate_Hash[4] += E;

            context.Message_Block_Index = 0;
        }

        static void SHA1PadMessage(SHA1Context context)
        {
            if (context.Message_Block_Index > 55)
            {
                context.Message_Block[context.Message_Block_Index++] = 0x80;
                while (context.Message_Block_Index < 64)
                {
                    context.Message_Block[context.Message_Block_Index++] = 0;
                }
                SHA1ProcessMessageBlock(context);
                while (context.Message_Block_Index < 56)
                {
                    context.Message_Block[context.Message_Block_Index++] = 0;
                }
            }
            else
            {
                context.Message_Block[context.Message_Block_Index++] = 0x80;
                while (context.Message_Block_Index < 56)
                {
                    context.Message_Block[context.Message_Block_Index++] = 0;
                }
            }

            /*  Store the message length as the last 8 octets     */
            context.Message_Block[56] = (byte)(context.Length_High >> 24);
            context.Message_Block[57] = (byte)(context.Length_High >> 16);
            context.Message_Block[58] = (byte)(context.Length_High >> 8);
            context.Message_Block[59] = (byte)(context.Length_High);
            context.Message_Block[60] = (byte)(context.Length_Low >> 24);
            context.Message_Block[61] = (byte)(context.Length_Low >> 16);
            context.Message_Block[62] = (byte)(context.Length_Low >> 8);
            context.Message_Block[63] = (byte)(context.Length_Low);

            SHA1ProcessMessageBlock(context);
        }

        static public int SHA1Result(SHA1Context context, byte[] Message_Digest)
        {
            int i;

            if (context == null || Message_Digest == null) { return (int)SHA_enum.shaNull; }
            if (context.Corrupted != 0) { return context.Corrupted; }

            if (context.Computed == 0)
            {
                SHA1PadMessage(context);
                for (i = 0; i < 64; ++i)
                {
                    /* message may be sensitive, clear it out */
                    context.Message_Block[i] = 0;
                }
                context.Length_Low = 0;    /* and clear length */
                context.Length_High = 0;
                context.Computed = 1;
            }

            for (i = 0; i < SHA1HashSize; ++i)
            {
                Message_Digest[i] = (byte)(context.Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03)));
            }
            return (int)SHA_enum.shaSuccess;
        }

        static UInt32 SHA1CircularShift(Int32 bits, UInt32 word)
        {
            return ((word << bits) | (word >> (32 - bits)));
        }
    }

    public class SHA1Context
    {
        /* This structure will hold context information for the SHA-1 hashing operation  */
        static UInt32 SHA1HashSize = 20;
        public UInt32[] Intermediate_Hash = new UInt32[SHA1HashSize / 4]; /* Message Digest  */
        public UInt32 Length_Low;                        /* Message length in bits      */
        public UInt32 Length_High;                       /* Message length in bits      */
        public int Message_Block_Index;                  /* Index into message block array   */
        public byte[] Message_Block = new byte[64];      /* 512-bit message blocks      */
        public int Computed;                             /* Is the digest computed?         */
        public int Corrupted;                            /* Is the message digest corrupted? */
    }
    public class ByteArrayComparer : EqualityComparer<byte[]>
    {
        public override bool Equals(byte[] left, byte[] right)
        {
            if (left == null || right == null) {
                return left == right;
            }
            if (ReferenceEquals(left, right)) {
                return true;
            }
            if (left.Length != right.Length) {
                return false;
            }
            return left.SequenceEqual(right);
        }
        public override int GetHashCode(byte[] obj)
        {
            if (obj == null) {
                throw new ArgumentNullException("obj");
            }
            //shortcut which works well for crypto data since hash function must be fast
            if (obj.Length >= 4) {
                return BitConverter.ToInt32(obj, 0);
            }
            // Length occupies at most 2 bits. Might as well store them in the high order byte
            int value = obj.Length;
            foreach (var b in obj) {
                value <<= 8;
                value += b;
            }
            return value;
        }
    }
    public class MersenneTwister
    {
        public uint [] x = new uint[624];
        int index;

        public void Initialize(uint seed)
        {
            index = 624;
            uint i = 1;
            x[0] = seed;
            int j = 0;
            uint _a; uint _b;
            do
            {
                _a = i + 1812433253 * (x[j] ^ (x[j] >> 30));
                x[j + 1] = _a;
                _b = i + 1812433253 * (_a ^ (_a >> 30)) + 1;
                i += 2;
                x[j + 2] = _b;
                j += 2;
            } while (j < 0x26C);
            x[0x26c] = 0; //for reinitialization...or introduces error
            x[0x26d] = 0;
            x[0x26e] = 0;
        }
        public void Splice(uint[] vals)
        {
            index = 0;
            vals.CopyTo(x, 0);
        }
        private uint Twist()
        {
            int top = 397, l = 623;
            uint j = 0;
            int i; uint _c, _out; int _f;
            do
            {
                i = (top - 396) % 624;
                _c = (x[j] ^ (x[j] ^ x[i]) & 0x7FFFFFFF) >> 1;
                if (((x[j] ^ (x[j] ^ x[i])) & 1) != 0)
                    _c ^= 0x9908B0DFu;
                _f = top++;
                _out = _c ^ x[_f % 624];
                x[j] = _out;
                ++j;
                --l;
            } while (l != 0);
            index = 0;
            return _out;
        }
        public uint Unextract(uint value) //untemper
        {
            value = value ^ value >> 18; //inverse of x ^ (x >> 18)
            value = value ^ ((value & 0x1DF8Cu) << 15); //inverse of ((x & 0xFFFFDF8C) << 15) ^ x = (x << 15) & 0xEFC60000 ^ x
            uint t = value; //inverse of ((x & 0xFF3A58AD) << 7) ^ x = ((x << 7) & 0x9D2C5680) ^ x
            t =     ((t & 0x0000002D) << 7) ^ value; //7 bits
            t =     ((t & 0x000018AD) << 7) ^ value; //14 bits
            t =     ((t & 0x001A58AD) << 7) ^ value; //21 bits
            value = ((t & 0x013A58AD) << 7) ^ value; //32-7 bits
            //inverse of x ^ x >> 11
            uint top = value & 0xFFE00000;
            uint mid = value & 0x001FFC00;
            uint low = value & 0x000003ff;
            return top | ((top >> 11) ^ mid) | ((((top >> 11) ^ mid) >> 11) ^ low);
        }
        public uint Extract() //temper
        {
            int i = index;
            if (index >= 624)
            {
                Twist();
                i = index;
            }
            uint e = x[i];
            uint _v = x[i] >> 11;
            index = i + 1;
            uint def = (((_v ^ e) & 0xFF3A58AD) << 7) ^ _v ^ e;
            return ((def & 0xFFFFDF8C) << 15) ^ def ^ ((((def & 0xFFFFDF8Cu) << 15) ^ def) >> 18);
        }
    }
    class Crypto
    {
        static private int GetNextRandom(RandomNumberGenerator rnd, int Maximum)
        {
            int i = GetBitSize(Maximum - 1);
            byte[] tmp = new byte[(i + 7) >> 3];
            int ret;
            do
            {
                rnd.GetBytes(tmp);
                if ((i % 8) != 0) tmp[0] &= (byte)((1 << (i % 8)) - 1);
                ret = BitConverter.ToInt32(tmp.Concat(new byte[] { 0, 0, 0, 0 }).ToArray(), 0);
            } while (Maximum <= ret);
            return ret;
        }
        static private BigInteger GetNextRandomBig(RandomNumberGenerator rnd, BigInteger Maximum)
        {
            int i = GetBitSize(Maximum - 1);
            byte[] tmp = new byte[(i + 7) >> 3];
            BigInteger ret;
            do
            {
                rnd.GetBytes(tmp);
                if ((i % 8) != 0) tmp[0] &= (byte)((1 << (i % 8)) - 1);
                ret = new BigInteger(tmp);
            } while (Maximum <= ret);
            return ret;
        }
        static private string HexEncode(byte[] input)
        {
            return string.Join(string.Empty, input.Select(d => d.ToString("x2")));
        }
        static private byte[] HexDecode(string input)
        {
            return Enumerable.Range(0, input.Length / 2)
                .Select(i => byte.Parse(input.Substring(i * 2, 2),
                    System.Globalization.NumberStyles.AllowHexSpecifier)).ToArray();
        }
        static private byte[] FixedXOR(byte[] a, byte[] b)
        {
            return a.Select((d, i) => (byte)(d ^ b[i])).ToArray();
        }
        static private int CharacterScore(byte[] s)
        {
            //http://academic.regis.edu/jseibert/Crypto/Frequency.pdf a-z/A-Z
            double[] freq = { .082, .015, .028, .043, .127, .022, .020, .061, .070, .002, .008, .040, .024,
                              .067, .075, .019, .001, .060, .063, .091, .028, .010, .023, .001, .020, .001};
            ILookup<byte, byte> j = s.ToLookup(c => c); //group them by frequency
            //30% weight for space or a couple false positives with high weighted letters can win
            //a negative weight for bad characters would make it even better...
            return (int)(((j.Contains((byte)' ') ? .3 * j[(byte)' '].Count() : 0) +
                freq.Select((d, i) => d * ((j.Contains((byte)('a' + i)) ? j[(byte)('a' + i)].Count() : 0) +
                                            (j.Contains((byte)('A' + i)) ? j[(byte)('A' + i)].Count() : 0))).Sum()) * 100);
        }
        //http://norvig.com/mayzner.html
        static private dynamic GetLeastXORBigramScore(byte[] s, byte[] t)
        {
            KeyValuePair<string, double>[] bigraphfreq = new KeyValuePair<string, double>[]
            {   new KeyValuePair<string, double>("TH", 3.56),
                new KeyValuePair<string, double>("HE", 3.07),
                new KeyValuePair<string, double>("IN", 2.43),
                new KeyValuePair<string, double>("ER", 2.05),
                new KeyValuePair<string, double>("AN", 1.99),
                new KeyValuePair<string, double>("RE", 1.85),
                new KeyValuePair<string, double>("ON", 1.76),
                new KeyValuePair<string, double>("AT", 1.49),
                new KeyValuePair<string, double>("EN", 1.45),
                new KeyValuePair<string, double>("ND", 1.35),
                new KeyValuePair<string, double>("TI", 1.34),
                new KeyValuePair<string, double>("ES", 1.34),
                new KeyValuePair<string, double>("OR", 1.28),
                new KeyValuePair<string, double>("TE", 1.20),
                new KeyValuePair<string, double>("OF", 1.17),
                new KeyValuePair<string, double>("ED", 1.17),
                new KeyValuePair<string, double>("IS", 1.13),
                new KeyValuePair<string, double>("IT", 1.12),
                new KeyValuePair<string, double>("AL", 1.09),
                new KeyValuePair<string, double>("AR", 1.07),
                new KeyValuePair<string, double>("ST", 1.05),
                new KeyValuePair<string, double>("TO", 1.04),
                new KeyValuePair<string, double>("NT", 1.04),
                new KeyValuePair<string, double>("NG", 0.95),
                new KeyValuePair<string, double>("SE", 0.93),
                new KeyValuePair<string, double>("HA", 0.93),
                new KeyValuePair<string, double>("AS", 0.87),
                new KeyValuePair<string, double>("OU", 0.87),
                new KeyValuePair<string, double>("IO", 0.83),
                new KeyValuePair<string, double>("LE", 0.83),
                new KeyValuePair<string, double>("VE", 0.83),
                new KeyValuePair<string, double>("CO", 0.79),
                new KeyValuePair<string, double>("ME", 0.79),
                new KeyValuePair<string, double>("DE", 0.76),
                new KeyValuePair<string, double>("HI", 0.76),
                new KeyValuePair<string, double>("RI", 0.73),
                new KeyValuePair<string, double>("RO", 0.73),
                new KeyValuePair<string, double>("IC", 0.70),
                new KeyValuePair<string, double>("NE", 0.69),
                new KeyValuePair<string, double>("EA", 0.69),
                new KeyValuePair<string, double>("RA", 0.69),
                new KeyValuePair<string, double>("CE", 0.65),
                new KeyValuePair<string, double>("LI", 0.62),
                new KeyValuePair<string, double>("CH", 0.60),
                new KeyValuePair<string, double>("LL", 0.58),
                new KeyValuePair<string, double>("BE", 0.58),
                new KeyValuePair<string, double>("MA", 0.57),
                new KeyValuePair<string, double>("SI", 0.55),
                new KeyValuePair<string, double>("OM", 0.55),
                new KeyValuePair<string, double>("UR", 0.54)};
            dynamic[] char1f = Enumerable.Range(0, 256).Select(i =>
               new { index = (byte)i, score = CharacterScore(FixedXOR(s, Enumerable.Repeat((byte)i, s.Length).ToArray())) }).OrderBy((m) => m.score).ToArray();
            dynamic[] char2f = Enumerable.Range(0, 256).Select(i =>
               new { index = (byte)i, score = CharacterScore(FixedXOR(t, Enumerable.Repeat((byte)i, t.Length).ToArray())) }).ToArray();
            for (int top = 0; top < 16; top++) {
                for (int i = 0; i < bigraphfreq.Length - 1; i++) {
                    for (int m = 0; m < s.Length - 1; m++) {
                        if ((char1f[top].index ^ s[m]) == bigraphfreq[i].Key[0] || (char1f[top].index ^ s[m]) == (bigraphfreq[i].Key[0] - 'A' + 'a')) {
                            char1f[top].score += char2f.First((c) => c.index == (bigraphfreq[i].Key[1] ^ t[m]) || c.index == ((bigraphfreq[i].Key[1] - 'A' + 'a') ^ t[m])).score * bigraphfreq[i].Value * 26;
                        }
                    }
                }
            }
            return char1f.OrderBy((c) => c.score).Last();
        }
        static private dynamic GetLeastXORCharacterScore(byte[] s)
        {
            dynamic maxItem = new { index = 0, score = 0 }; //assume 0 is starting maximum is fine in this scenario regardless
            foreach (dynamic val in Enumerable.Range(0, 256).Select(i =>
                new { index = (byte)i, score = CharacterScore(FixedXOR(s, Enumerable.Repeat((byte)i, s.Length).ToArray())) }))
            {
                //Console.WriteLine(val.score.ToString() + " " + System.Text.Encoding.ASCII.GetString(FixedXOR(s, Enumerable.Repeat((byte)val.index, s.Length).ToArray())));
                if (val.score > maxItem.score) { maxItem = val; }
            }
            return maxItem;
        }
        static private int HammingDistance(byte[] a, byte[] b)
        {
            return a.Select((d, i) => {
                int c;
                byte v = (byte)(d ^ b[i]); //Counting bits set, Brian Kernighan's way
                for (c = 0; v != 0; c++) { v &= (byte)(v - 1); }
                return c;
            }).Sum();
        }
        static private byte[] PKCS7Pad(byte[] input, int blocksize)
        {
            return Enumerable.Concat(input, Enumerable.Repeat((byte)(blocksize - (input.Length % blocksize)), blocksize - (input.Length % blocksize))).ToArray();
        }
        static private byte[] encrypt_ecb(byte[] key, byte[] input)
        {
            System.Security.Cryptography.AesManaged aes128 = new System.Security.Cryptography.AesManaged();
            //System.Security.Cryptography.RijndaelManaged aes128 = new System.Security.Cryptography.RijndaelManaged();
            aes128.Key = key;
            aes128.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes128.Padding = System.Security.Cryptography.PaddingMode.None; //critical or cannot do one block at a time...
            byte[] o = new byte[input.Length];
            int offset = 0; //could use a MemoryStream and CryptoStream to make this automated and robust...
            //but the block aspect is encapsulated away which is to be a highlight
            System.Security.Cryptography.ICryptoTransform transform = aes128.CreateEncryptor();
            while (offset < input.Length) {
                if (offset + aes128.BlockSize / 8 <= input.Length) {
                    offset += transform.TransformBlock(input, offset, aes128.BlockSize / 8, o, offset);
                } else {
                    transform.TransformFinalBlock(input, offset, input.Length - offset).CopyTo(o, offset);
                    break;
                }
            }
            return o;
        }
        static private byte[] decrypt_ecb(byte[] key, byte[] input)
        {
            System.Security.Cryptography.AesManaged aes128 = new System.Security.Cryptography.AesManaged();
            //System.Security.Cryptography.RijndaelManaged aes128 = new System.Security.Cryptography.RijndaelManaged();
            aes128.Key = key;
            aes128.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes128.Padding = System.Security.Cryptography.PaddingMode.None; //critical or cannot do one block at a time...
            byte[] o = new byte[input.Length];
            int offset = 0; //could use a MemoryStream and CryptoStream to make this automated and robust...
            //but the block aspect is encapsulated away which is to be a highlight
            System.Security.Cryptography.ICryptoTransform transform = aes128.CreateDecryptor();
            while (offset < input.Length) {
                if (offset + aes128.BlockSize / 8 <= input.Length) {
                    offset += transform.TransformBlock(input, offset, aes128.BlockSize / 8, o, offset);
                } else {
                    transform.TransformFinalBlock(input, offset, input.Length - offset).CopyTo(o, offset);
                    break;
                }
            }
            return o;
        }
        static private byte[] encrypt_cbc(byte[] iv, byte[] key, byte[] input)
        {
            byte[] o = new byte[input.Length];
            byte[] data = new byte[input.Length];
            input.CopyTo(data, 0);
            System.Security.Cryptography.AesManaged aes128 = new System.Security.Cryptography.AesManaged();
            aes128.Key = key;
            aes128.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes128.Padding = System.Security.Cryptography.PaddingMode.None; //critical or cannot do one block at a time...
            int offset = 0;
            System.Security.Cryptography.ICryptoTransform transform = aes128.CreateEncryptor();
            while (offset < input.Length) {
                if (offset + aes128.BlockSize / 8 <= input.Length) {
                    FixedXOR(data.Skip(offset).Take(aes128.BlockSize / 8).ToArray(),
                        (offset != 0) ? o.Skip(offset - aes128.BlockSize / 8).Take(aes128.BlockSize / 8).ToArray() : iv).CopyTo(data, offset);
                    offset += transform.TransformBlock(data, offset, aes128.BlockSize / 8, o, offset);
                } else {
                    FixedXOR(data.Skip(offset).Take(input.Length - offset).ToArray(),
                        (offset != 0) ? o.Skip(offset - aes128.BlockSize / 8).Take(input.Length - offset).ToArray() : iv).CopyTo(data, offset);
                    transform.TransformFinalBlock(data, offset, input.Length - offset).CopyTo(o, offset);
                }
            }
            return o;
        }
        static private byte[] decrypt_cbc(byte[] iv, byte[] key, byte[] input)
        {
            byte[] o = new byte[input.Length];
            System.Security.Cryptography.AesManaged aes128 = new System.Security.Cryptography.AesManaged();
            aes128.Key = key;
            aes128.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes128.Padding = System.Security.Cryptography.PaddingMode.None; //critical or cannot do one block at a time...
            int offset = 0;
            System.Security.Cryptography.ICryptoTransform transform = aes128.CreateDecryptor();
            while (offset < input.Length) {
                if (offset + aes128.BlockSize / 8 <= input.Length) {
                    offset += transform.TransformBlock(input, offset, aes128.BlockSize / 8, o, offset);
                    FixedXOR(o.Skip(offset - aes128.BlockSize / 8).Take(aes128.BlockSize / 8).ToArray(),
                        (offset != aes128.BlockSize / 8) ? input.Skip(offset - aes128.BlockSize / 8 * 2).Take(aes128.BlockSize / 8).ToArray() : iv).CopyTo(o, offset - aes128.BlockSize / 8);
                } else {
                    transform.TransformFinalBlock(input, offset, input.Length - offset).CopyTo(o, offset);
                    FixedXOR(o.Skip(offset - aes128.BlockSize / 8).Take(input.Length - offset).ToArray(),
                        (offset != aes128.BlockSize / 8) ? input.Skip(offset - aes128.BlockSize / 8 * 2).Take(input.Length - offset).ToArray() : iv).CopyTo(o, offset - aes128.BlockSize / 8);
                }
            }
            return o;
        }
        static private byte[] crypt_ctr(ulong nonce, byte[] key, byte[] input)
        {
            byte[] o = new byte[input.Length];
            for (ulong ctr = 0; (int)ctr < input.Length; ctr += 16) {
                //BitConverter uses little endian order
                FixedXOR(input.Skip((int)ctr).Take(Math.Min(input.Length - (int)ctr, 16)).ToArray(), encrypt_ecb(key, BitConverter.GetBytes(nonce).Concat(BitConverter.GetBytes(ctr / 16)).ToArray()).Take(Math.Min(input.Length - (int)ctr, 16)).ToArray()).CopyTo(o, (int)ctr);
            }
            return o;
        }
        static private byte[] encryption_oracle_with_key_cbc(byte[] iv, byte[] key, byte[] prefix, byte[] input, byte[] extra)
        {
            return encrypt_cbc(iv, key, PKCS7Pad(Enumerable.Concat(Enumerable.Concat(prefix, input), extra).ToArray(), 16));
        }
        static private byte[] encryption_oracle_with_key(byte[] key, byte[] prefix, byte[] input, byte[] extra)
        {
            return encryption_oracle_with_key(key, Enumerable.Concat(prefix, input).ToArray(), extra);
        }
        static private byte[] encryption_oracle_with_key(byte[] key, byte[] input, byte[] extra)
        {
            return encrypt_ecb(key, PKCS7Pad(Enumerable.Concat(input, extra).ToArray(), 16));
        }
        static private byte[] encryption_oracle(byte[] input)
        {
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            byte[] first = new byte[5 + GetNextRandom(rnd, 6)];
            byte[] last = new byte[5 + GetNextRandom(rnd, 6)];
            byte[] data = PKCS7Pad(Enumerable.Concat(first, input).Concat(last).ToArray(), 16);
            if (GetNextRandom(rnd, 2) == 1) {
                return encrypt_ecb(key, data);
            } else {
                byte[] iv = new byte[16];
                rnd.GetBytes(iv);
                return encrypt_cbc(iv, key, data);
            }
        }
        static private bool isecbmode(byte[] data)
        {
            HashSet<byte[]> dict = new HashSet<byte[]>(new ByteArrayComparer());
            for (int i = 0; i < data.Length / 16; i++)
            {
                byte[] n = data.Skip(i * 16).Take(16).ToArray();
                if (dict.Contains(n)) {
                    return true; //detected
                } else {
                    dict.Add(n);
                }
            };
            return false;
        }
        static private Dictionary<string, string> parsecookie(string input)
        {
            Dictionary<string, string> dict = new Dictionary<string, string>();
            foreach (string kv in input.Split('&')) {
                string[] kvs = kv.Split('=');
                if (!dict.ContainsKey(kvs[0])) {
                    dict.Add(kvs[0], kvs[1]);
                } else {
                    dict[kvs[0]] = kvs[1];
                }
            }
            return dict;
        }
        static private string profile_for(string name)
        {
            dynamic obj = null;
            if (name == "foo@bar.com") obj = new { email = "foo@bar.com", uid = 10, role = "user" };
            else if (name == "admin@bar.com") obj = new { email = "admin@bar.com", uid = 11, role = "admin" };
            return "email=" + ((string)obj.email).Replace("&", "%" + ((byte)'&').ToString("X2")).Replace("=", "%" + ((byte)'=').ToString("X2")) +
                "&uid=" + obj.uid +
                "&role=" + ((string)obj.role).Replace("&", "%" + ((byte)'&').ToString("X2")).Replace("=", "%" + ((byte)'=').ToString("X2"));
        }
        static private byte[] PKCS7Strip(byte[] inp)
        {
            //on even blocks a padding of a whole block is there so we can always properly strip
            if (inp.Last() >= 1 && inp.Last() <= 16 && new ByteArrayComparer().Equals(inp.Skip(inp.Length - (int)inp.Last()).ToArray(), Enumerable.Repeat(inp.Last(), (int)inp.Last()).ToArray())) return inp.Take(inp.Length - (int)inp.Last()).ToArray();
            throw new ArgumentException();
        }
        static private byte[] MTCipher(ushort seed, byte[] input)
        {
            MersenneTwister mt = new MersenneTwister();
            mt.Initialize((uint)seed);
            return FixedXOR(Enumerable.Range(0, (input.Length >> 2) + (input.Length % 4 == 0 ? 0 : 1)).Select((i) => BitConverter.GetBytes(mt.Extract())).SelectMany((d) => d).Take(input.Length).ToArray(), input);
        }
        static void Set1()
        {
            //SET 1 CHALLENGE 1
            Console.WriteLine("1.1 Decoded hex equals decoded base64: " +
                (Convert.ToBase64String(HexDecode(
"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
)) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"));

            //SET 1 CHALLENGE 2
            Console.WriteLine("1.2 Two values XOR equal third: " + (HexEncode(FixedXOR(
                                HexDecode("1c0111001f010100061a024b53535009181c"),
                                HexDecode("686974207468652062756c6c277320657965"))) ==
                                                        "746865206b696420646f6e277420706c6179"));

            //SET 1 CHALLENGE 3
            byte[] b = HexDecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
            Console.WriteLine("1.3 Recovered text: " + System.Text.Encoding.ASCII.GetString(FixedXOR(b, Enumerable.Repeat((byte)GetLeastXORCharacterScore(b).index, b.Length).ToArray())));

            //SET 1 CHALLENGE 4
            dynamic maxItem = new { index = 0, score = 0 }; //assume 0 is starting maximum is fine in this scenario regardless
            byte[][] lines = Enumerable.Select(System.IO.File.ReadAllLines("../../4.txt"), s => HexDecode(s)).ToArray();
            for (int i = 0; i < lines.Length; i++)
            {
                dynamic val = GetLeastXORCharacterScore(lines[i]);
                //Console.WriteLine(val.score.ToString() + " " + System.Text.Encoding.ASCII.GetString(FixedXOR(lines[i], Enumerable.Repeat((byte)val.index, lines[i].Length).ToArray())));
                if (val.score > maxItem.score) { maxItem = new { origindex = i, index = val.index, score = val.score }; }
            }
            Console.WriteLine("1.4 Recovered line text: " + System.Text.Encoding.ASCII.GetString(FixedXOR(lines[maxItem.origindex], Enumerable.Repeat((byte)maxItem.index, b.Length).ToArray())));

            //SET 1 CHALLENGE 5
            b = System.Text.Encoding.ASCII.GetBytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
            Console.WriteLine("1.5 XOR encryption is correct: " + (HexEncode(FixedXOR(b, Enumerable.Repeat(System.Text.Encoding.ASCII.GetBytes("ICE"), b.Length / 3 + 1).SelectMany(d => d).Take(b.Length).ToArray())) ==
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"));

            //SET 1 CHALLENGE 6
            Console.WriteLine("1.6 Hamming distance correct: " + (HammingDistance(System.Text.Encoding.ASCII.GetBytes("this is a test"), System.Text.Encoding.ASCII.GetBytes("wokka wokka!!!")) == 37));
            b = Enumerable.Select(System.IO.File.ReadAllLines("../../6.txt"), s => Convert.FromBase64String(s)).SelectMany(d => d).ToArray();
            dynamic minItem = new { keysize = 2, hamming = double.MaxValue };
            foreach (dynamic val in Enumerable.Range(2, 39).Select(j => new
            {
                keysize = j, //hamming all neighboring pieces except for the last one if its not a multiple - this is slower but maximal accuracy! must use double for divisions...
                hamming = (double)Enumerable.Range(0, b.Length / j - 1).Select(l =>
                        HammingDistance(b.Skip(l * j).Take(j).ToArray(),
                        b.Skip((l + 1) * j).Take(j).ToArray())).Sum() / ((double)b.Length / (double)j - 1.0) / (double)j
            }))
            {
                if (val.hamming < minItem.hamming) { minItem = val; }
            }
            Console.WriteLine(System.Text.Encoding.ASCII.GetString(FixedXOR(b,
                Enumerable.Repeat(Enumerable.Range(0, (int)minItem.keysize).Select(j =>
                    (byte)GetLeastXORCharacterScore(b.Where((c, i) => i % (int)minItem.keysize == j).ToArray()).index),
                    b.Length / (int)minItem.keysize + 1).SelectMany(d => d).Take(b.Length).ToArray())));

            //SET 1 CHALLENGE 7
            b = System.IO.File.ReadAllLines("../../7.txt").Select(s => Convert.FromBase64String(s)).SelectMany(d => d).ToArray();
            byte[] o = decrypt_ecb(System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), b);
            Console.WriteLine("1.7 Recovered plaintext: " + System.Text.Encoding.ASCII.GetString(o));

            //SET 1 CHALLENGE 8
            lines = System.IO.File.ReadAllLines("../../8.txt").Select(s => HexDecode(s)).ToArray();
            foreach (byte[] l in lines) {
                if (isecbmode(l)) {
                    Console.WriteLine("1.8 Detected AES ECB mode: " + HexEncode(l));
                }
            }
        }
        static void Set2()
        {
            byte[] b;
            byte[] o;
            //SET 2 CHALLENGE 9
            Console.WriteLine("2.9 PKCS#7 padding correct: " + (System.Text.Encoding.ASCII.GetString(PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), 20)) == "YELLOW SUBMARINE\x04\x04\x04\x04"));

            //SET 2 CHALLENGE 10
            b = System.IO.File.ReadAllLines("../../10.txt").Select(s => Convert.FromBase64String(s)).SelectMany(d => d).ToArray();
            o = decrypt_cbc(Enumerable.Repeat((byte)0, 16).ToArray(), System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), b);
            Console.WriteLine("2.10 Text decrypted: " + System.Text.Encoding.ASCII.GetString(o));
            Console.WriteLine("Is equal on re-encryption: " + (new ByteArrayComparer().Equals(b, encrypt_cbc(Enumerable.Repeat((byte)0, 16).ToArray(), System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), o)))); //proved encryption is back to input

            //SET 2 CHALLENGE 11
            Console.WriteLine("2.11 Is in ECB mode: " + isecbmode(encryption_oracle(o)));

            //SET 2 CHALLENGE 12
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            b = Convert.FromBase64String("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
            int startlen = encryption_oracle_with_key(key, o.Take(0).ToArray(), b).Length;
            int ct = 1; //when output size increases, difference will be one block
            while (startlen == encryption_oracle_with_key(key, o.Take(ct).ToArray(), b).Length)
            {
                ct++;
            }
            int blocksize = encryption_oracle_with_key(key, o.Take(ct).ToArray(), b).Length - startlen;
            Console.WriteLine("2.12 block size: " + blocksize);
            //only 2 identical blocks needed since we are at the start of string now
            Console.WriteLine("ECB mode check: " + isecbmode(encryption_oracle_with_key(key, o.Take(blocksize).Concat(o.Take(blocksize)).ToArray(), b)));
            int len = encryption_oracle_with_key(key, new byte[] { }, b).Length - ct;
            byte[] output = new byte[len];
            for (int i = 0; i < len; i++)
            {
                byte[] sample = encryption_oracle_with_key(key, o.Take(blocksize - (1 + i) % blocksize).ToArray(), b).Skip(((1 + i) / blocksize) * blocksize).Take(blocksize).ToArray();
                Dictionary<byte[], byte> dict = new Dictionary<byte[], byte>(new ByteArrayComparer());
                //maintaining a dictionary is not really of any special benefit in this scenario
                for (ct = 0; ct < 256; ct++)
                { //alphanumeric and whitespace would be a shortcut
                  //if (!dict.ContainsKey(encryption_oracle_with_key(key, o.Take(blocksize - (1 + i) % blocksize).Concat(output.Take(i)).Concat(new byte[] { (byte)ct }).ToArray(), b).Skip(((1 + i) / blocksize) * blocksize).Take(blocksize).ToArray())) {
                    dict.Add(encryption_oracle_with_key(key, o.Take(blocksize - (1 + i) % blocksize).Concat(output.Take(i)).Concat(new byte[] { (byte)ct }).ToArray(), b).Skip(((1 + i) / blocksize) * blocksize).Take(blocksize).ToArray(), (byte)ct);
                    //}
                }
                output[i] = (byte)dict[sample]; //no collision and key found is asserted or will crash
            }
            Console.WriteLine("Recovered value: " + System.Text.Encoding.ASCII.GetString(output));

            //SET 2 CHALLENGE 13
            parsecookie("foo=bar&baz=qux&zap=zazzle");
            Console.WriteLine("2.13 profile_for: " + profile_for("foo@bar.com") + " profile_for: " + profile_for("admin@bar.com"));
            key = new byte[16];
            rnd.GetBytes(key);
            b = encrypt_ecb(key, PKCS7Pad(Encoding.ASCII.GetBytes(profile_for("foo@bar.com")), 16));
            parsecookie(System.Text.Encoding.ASCII.GetString(PKCS7Strip(decrypt_ecb(key, b))));
            output = b.Take(16 * (("email=foo@bar.com&uid=10&".Length + 15) / 16)).Concat(encrypt_ecb(key, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes(profile_for("admin@bar.com")), 16)).Skip(16 * (("email=foo@bar.com&uid=10&".Length) / 16))).ToArray();
            Console.WriteLine("Decrypted cut and paste profile: " + System.Text.Encoding.ASCII.GetString(PKCS7Strip(decrypt_ecb(key, output))));
            parsecookie(System.Text.Encoding.ASCII.GetString(decrypt_ecb(key, output)));

            //SET 2 CHALLENGE 14
            key = new byte[16];
            rnd.GetBytes(key);
            byte[] r = new byte[GetNextRandom(rnd, 32)];
            rnd.GetBytes(r);
            b = Convert.FromBase64String("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
            startlen = encryption_oracle_with_key(key, r, o.Take(0).ToArray(), b).Length;
            ct = 1; //when output size increases, difference will be one block
            while (startlen == encryption_oracle_with_key(key, r, o.Take(ct).ToArray(), b).Length)
            {
                ct++;
            }
            blocksize = encryption_oracle_with_key(key, r, o.Take(ct).ToArray(), b).Length - startlen;
            Console.WriteLine("2.14 block size: " + blocksize);
            //need 3 (or in keysize cases 2) identical blocks makes at least 2 aligned blocks when randomly prefixed
            output = encryption_oracle_with_key(key, r, o.Take(blocksize).Concat(o.Take(blocksize)).Concat(o.Take(blocksize)).ToArray(), b);
            Console.WriteLine("ECB mode check: " + isecbmode(output));
            int startblock = 0; //determine startblock by finding first 2 duplicates
            while (!new ByteArrayComparer().Equals(output.Skip(startblock * blocksize).Take(blocksize).ToArray(),
                                                output.Skip((startblock + 1) * blocksize).Take(blocksize).ToArray()))
            {
                startblock++;
            }
            int startinblock = 0; //determine where in the block it was started by scanning increasing controlled data in prior block
            while (!new ByteArrayComparer().Equals(output.Skip((startblock - 1) * blocksize).Take(blocksize).ToArray(),
                                                encryption_oracle_with_key(key, r, o.Take(startinblock).ToArray(), b).Skip((startblock - 1) * blocksize).Take(blocksize).ToArray()))
            {
                startinblock++;
            }
            if (startinblock != 0) { if (startinblock % blocksize != 0) startblock--; startinblock = 16 - startinblock; }
            len = encryption_oracle_with_key(key, r, new byte[] { }, b).Length - ct - startblock * blocksize - startinblock;
            output = new byte[len];
            for (int i = 0; i < len; i++)
            {
                byte[] sample = encryption_oracle_with_key(key, r, o.Take(blocksize - (1 + i + startinblock) % blocksize).ToArray(), b).Skip((startblock + (1 + i + startinblock) / blocksize) * blocksize).Take(blocksize).ToArray();
                Dictionary<byte[], byte> dict = new Dictionary<byte[], byte>(new ByteArrayComparer());
                //maintaining a dictionary is not really of any special benefit in this scenario
                for (ct = 0; ct < 256; ct++)
                { //alphanumeric and whitespace would be a shortcut
                  //if (!dict.ContainsKey(encryption_oracle_with_key(key, o.Take(blocksize - (1 + i + startinblock) % blocksize).Concat(output.Take(i)).Concat(new byte[] { (byte)ct }).ToArray(), b).Skip((startblock + (1 + i + startinblock) / blocksize) * blocksize).Take(blocksize).ToArray())) {
                    dict.Add(encryption_oracle_with_key(key, r, o.Take(blocksize - (1 + i + startinblock) % blocksize).Concat(output.Take(i)).Concat(new byte[] { (byte)ct }).ToArray(), b).Skip((startblock + (1 + i + startinblock) / blocksize) * blocksize).Take(blocksize).ToArray(), (byte)ct);
                    //}
                }
                output[i] = (byte)dict[sample]; //no collision and key found is asserted or will crash
            }
            Console.WriteLine("Recovered value: " + System.Text.Encoding.ASCII.GetString(output));

            //SET 2 CHALLENGE 15
            Console.WriteLine("2.15 Good padding: " + (Encoding.ASCII.GetString(PKCS7Strip(Encoding.ASCII.GetBytes("ICE ICE BABY\x04\x04\x04\x04"))) == "ICE ICE BABY"));
            try
            {
                PKCS7Strip(Encoding.ASCII.GetBytes("ICE ICE BABY\x05\x05\x05\x05"));
            }
            catch
            {
                Console.WriteLine("Bad padding: ICE ICE BABY\x05\x05\x05\x05");
            }
            try
            {
                PKCS7Strip(Encoding.ASCII.GetBytes("ICE ICE BABY\x01\x02\x03\x04"));
            }
            catch
            {
                Console.WriteLine("Bad padding: ICE ICE BABY\x01\x02\x03\x04");
            }

            //SET 2 CHALLENGE 16
            rnd.GetBytes(key);
            byte[] iv = new byte[16];
            rnd.GetBytes(iv);
            b = encryption_oracle_with_key_cbc(iv, key, Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata="), o, Encoding.ASCII.GetBytes(";comment2=%20like%20a%20pound%20of%20bacon"));
            Console.WriteLine("2.16 Is random string admin: " + Encoding.ASCII.GetString(decrypt_cbc(iv, key, b)).Contains(";admin=true;"));
            //first send a block with all 0's to let us determine the output of the next stage
            //output = decrypt_cbc(iv, key, Enumerable.Concat(Enumerable.Concat(b.Take(32), Enumerable.Repeat((byte)0, 16)), b.Skip(48)).ToArray());
            //Console.WriteLine(Encoding.ASCII.GetString(decrypt_cbc(iv, key, Enumerable.Concat(Enumerable.Concat(b.Take(32), FixedXOR(output.Skip(48).Take(16).ToArray(), Encoding.ASCII.GetBytes(";admin=true;    "))), b.Skip(48)).ToArray())).Contains(";admin=true;"));
            Console.WriteLine("Is admin: " + Encoding.ASCII.GetString(decrypt_cbc(iv, key, Enumerable.Concat(Enumerable.Concat(b.Take(32), FixedXOR(o.Skip(16).Take(16).ToArray(), FixedXOR(b.Skip(32).Take(16).ToArray(), Encoding.ASCII.GetBytes(";admin=true;    ")))), b.Skip(48)).ToArray())).Contains(";admin=true;"));
        }
        static void Set3()
        {
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] b;
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            byte[][] lines;
            int ct;
            int startinblock;
            int startblock;
            byte[] output;
            //SET 3 CHALLENGE 17
            string[] rndstrs;
            rndstrs = new string[] { "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"};
            rndstrs = rndstrs.Select((str) => Encoding.ASCII.GetString(Convert.FromBase64String(str))).ToArray();
            rnd.GetBytes(key);
            rnd.GetBytes(iv);
            ct = GetNextRandom(rnd, rndstrs.Length);
            b = encrypt_cbc(iv, key, PKCS7Pad(Encoding.ASCII.GetBytes(rndstrs[ct]), 16));
            output = decrypt_cbc(iv, key, b);
            Console.WriteLine("3.17 Random string encrypts: " + (Encoding.ASCII.GetString(PKCS7Strip(output)) == rndstrs[ct]));
            //now decrypt b with only PKCS7Strip indirectly invoking decrypt_cbc
            //the problem with the last block is that two values for the original pad or new pad could both work
            //must prepend IV to determine first block - how to get IV in general? must have at least a single valid cypher encryption plaintext/cyphertext pair
            b = iv.Concat(b).ToArray();
            for (startblock = b.Length / 16 - 1; startblock >= 1; startblock--)
            {
                byte[] data = new byte[16];
                for (startinblock = 15; startinblock >= 0; startinblock--)
                {
                    for (int j = 15; j > startinblock; j--) { b[(startblock - 1) * 16 + j] ^= (byte)(data[j] ^ (16 - startinblock)); }
                    for (int i = 255; i >= 0; i--)
                    { //avoid problem of original padding on last block by searching backward...
                        try
                        {
                            b[(startblock - 1) * 16 + startinblock] ^= (byte)(i ^ (16 - startinblock));
                            PKCS7Strip(decrypt_cbc(iv, key, b.Take((startblock + 1) * 16).ToArray()));
                            data[startinblock] = (byte)i;
                            b[(startblock - 1) * 16 + startinblock] ^= (byte)(i ^ (16 - startinblock));
                            break;
                        }
                        catch { b[(startblock - 1) * 16 + startinblock] ^= (byte)(i ^ (16 - startinblock)); }
                    }
                    for (int j = 15; j > startinblock; j--) { b[(startblock - 1) * 16 + j] ^= (byte)(data[j] ^ (16 - startinblock)); }
                }
                for (int j = 0; j < 16; j++) { b[startblock * 16 + j] = data[j]; }
            }
            Console.WriteLine("Decrypted value: " + (Encoding.ASCII.GetString(PKCS7Strip(b.Skip(16).ToArray())) == rndstrs[ct]));

            //SET 3 CHALLENGE 18
            Console.WriteLine("3.18 Recovered CTR string: " + System.Text.Encoding.ASCII.GetString(crypt_ctr(0, System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), Convert.FromBase64String("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="))));
            Console.WriteLine("Decrypted and re-encrypted value recovers original encryption: " + ("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==" == Convert.ToBase64String(crypt_ctr(0, System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), crypt_ctr(0, System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), Convert.FromBase64String("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="))))));

            //SET 3 CHALLENGE 19 - WEAK SOLUTION DOES NOT PROPERLY DEAL WITH TRIGRAMS!!!
            rndstrs = new string[] {"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
                        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
                        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
                        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
                        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
                        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
                        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
                        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
                        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
                        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
                        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
                        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
                        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
                        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
                        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
                        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
                        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
                        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
                        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
                        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
                        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
                        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
                        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
                        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
                        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
                        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
                        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
                        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
                        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
                        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
                        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
                        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
                        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
                        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
                        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
                        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
                        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
                        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
                        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
                        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="};
            rnd.GetBytes(key);
            lines = rndstrs.Select((str) => crypt_ctr(0, key, Convert.FromBase64String(str))).ToArray();
            b = new byte[lines.Max((bts) => bts.Length)]; //maximum length of keystream to try to decode
            for (int i = 0; i < b.Length; i++)
            {
                byte[] analysis = lines.Where((bts) => bts.Length > i).Select((bts) => bts[i]).ToArray();
                dynamic val = GetLeastXORCharacterScore(analysis);
                if (analysis.Length <= 13 || val.score <= 80)
                {
                    val = GetLeastXORBigramScore(lines.Where((bts) => bts.Length > i + 1).Select((bts) => bts[i]).ToArray(), lines.Where((bts) => bts.Length > i + 1).Select((bts) => bts[i + 1]).ToArray());
                }
                b[i] = val.index;
            }
            for (int i = 0; i < lines.Length; i++) { Console.WriteLine(System.Text.Encoding.ASCII.GetString(FixedXOR(lines[i], b.Take(lines[i].Length).ToArray()))); }

            //SET 3 CHALLENGE 20 - WEAK SOLUTION DOES NOT PROPERLY DEAL WITH TRIGRAMS!!!
            lines = System.IO.File.ReadAllLines("../../20.txt").Select(s => crypt_ctr(0, key, Convert.FromBase64String(s))).ToArray();
            b = new byte[lines.Max((bts) => bts.Length)]; //maximum length of keystream to try to decode
            for (int i = 0; i < b.Length; i++)
            {
                byte[] analysis = lines.Where((bts) => bts.Length > i).Select((bts) => bts[i]).ToArray();
                dynamic val = GetLeastXORCharacterScore(analysis);
                if (analysis.Length <= 13 || val.score <= 80)
                {
                    val = GetLeastXORBigramScore(lines.Where((bts) => bts.Length > i + 1).Select((bts) => bts[i]).ToArray(), lines.Where((bts) => bts.Length > i + 1).Select((bts) => bts[i + 1]).ToArray());
                }
                b[i] = val.index;
            }
            Console.WriteLine("3.20 Decoded file: ");
            for (int i = 0; i < lines.Length; i++) { Console.WriteLine(System.Text.Encoding.ASCII.GetString(FixedXOR(lines[i], b.Take(lines[i].Length).ToArray()))); }

            //SET 3 CHALLENGE 21
            MersenneTwister mt = new MersenneTwister();
            mt.Initialize(0);
            Console.WriteLine("3.21 Mersenne Twister value with 0 seed: " + mt.Extract());

            //SET 3 CHALLENGE 22
            uint time = (uint)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            mt.Initialize(time);
            uint delay1 = time + 40 + (uint)GetNextRandom(rnd, 961);
            uint firstop = mt.Extract();
            while (true)
            {
                mt.Initialize(delay1);
                if (mt.Extract() == firstop) break;
                delay1--;
            }
            Console.WriteLine("3.22 Inital time seed recovered: " + (time == delay1));

            //SET 3 CHALLENGE 23
            mt.Initialize(0);
            uint[] vals = new uint[624];
            for (ct = 0; ct < 624; ct++) { vals[ct] = mt.Extract(); }
            MersenneTwister mtsplice = new MersenneTwister();
            mtsplice.Initialize(0);
            for (ct = 0; ct < 624; ct++) { vals[ct] = mt.Unextract(vals[ct]); }
            mtsplice.Splice(vals);
            mt.Initialize(0);
            for (ct = 0; ct < 624; ct++) { if (mtsplice.Extract() != mt.Extract()) break; }
            Console.WriteLine("3.23 All values in Mersenne Twister state are the same: " + (ct == 624));

            //SET 3 CHALLENGE 24
            b = new byte[GetNextRandom(rnd, 256)];
            rnd.GetBytes(b);
            b = Enumerable.Concat(b, Enumerable.Repeat((byte)'A', 14)).ToArray();
            firstop = (uint)(GetNextRandom(rnd, ushort.MaxValue));
            output = MTCipher((ushort)firstop, b);
            for (time = 0; time <= ushort.MaxValue; time++) {
                mt.Initialize(time);
                if (new ByteArrayComparer().Equals(Enumerable.Repeat((byte)'A', 14).ToArray(), FixedXOR(Enumerable.Range(0, (output.Length >> 2) + (output.Length % 4 == 0 ? 0 : 1)).Select((i) => BitConverter.GetBytes(mt.Extract())).SelectMany((d) => d).Skip(output.Length - 14).Take(14).ToArray(), output.Skip(output.Length - 14).ToArray()))) break;
            }
            Console.WriteLine("3.24 Found original seed: " + (firstop == time));
            time = (uint)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            mt.Initialize(time); //no difference really from challenge 22...
            firstop = mt.Extract();
            time += 40 + (uint)GetNextRandom(rnd, 961);
            while (true)
            {
                mt.Initialize(time);
                if (mt.Extract() == firstop) break;
                time--;
            }
            Console.WriteLine("Found password token seed: " + (true));
        }
        static byte[] edit(byte[] input, byte[] key, int offset, byte[] plaintext)
        {
            byte[] o = crypt_ctr(0, key, input);
            plaintext.CopyTo(o, offset);
            return crypt_ctr(0, key, o);
        }
        //RFC 2104 HMAC(k,m)=H((K' xor opad) || H((K' xor ipad) || m))
        static byte[] hmac(byte[] key, byte[] message)
        {
            SHA1Context sc = new SHA1Context(); //64 bit block size for SHA-1 and MD4
            if (key.Length > 64)
            {
                SHA1_Algo.SHA1Reset(sc);
                SHA1_Algo.SHA1Input(sc, key);
                key = new byte[64];
                SHA1_Algo.SHA1Result(sc, key);
            } else if (key.Length < 64) {
                key = key.Concat(Enumerable.Repeat((byte)0, 64 - key.Length)).ToArray();
            }
            SHA1_Algo.SHA1Reset(sc);
            byte[] b = new byte[20];
            SHA1_Algo.SHA1Input(sc, FixedXOR(Enumerable.Repeat((byte)0x36, 64).ToArray(), key).Concat(message).ToArray());
            SHA1_Algo.SHA1Result(sc, b);
            SHA1_Algo.SHA1Reset(sc);
            SHA1_Algo.SHA1Input(sc, FixedXOR(Enumerable.Repeat((byte)0x5c, 64).ToArray(), key).Concat(b).ToArray());
            SHA1_Algo.SHA1Result(sc, b);
            return b;
        }
        static bool insecure_compare(byte[] o, byte[] sig, int millisec)
        {
            for (int i = 0; i < o.Length; i++)
            {
                if (o[i] != sig[i]) return false;
                System.Threading.Thread.Sleep(millisec);
            }
            return true;
        }
        static bool openurl(string url, int millisec)
        {
            int iqs = url.IndexOf('?');
            if (iqs >= 0)
            {
                string file = System.Web.HttpUtility.ParseQueryString(url.Substring(iqs + 1))["file"];
                byte[] sig = HexDecode(System.Web.HttpUtility.ParseQueryString(url.Substring(iqs + 1))["signature"]);
                byte[] o = hmac(System.Text.Encoding.ASCII.GetBytes(file), System.Text.Encoding.ASCII.GetBytes("bar"));
                return insecure_compare(o, sig, millisec);
            }
            return false;
        }
        static byte[] breakurlkey(int millisec, int rds)
        {
            byte[] key = Enumerable.Repeat((byte)0, 20).ToArray();
            for (int c = 0; c < 20; c++)
            {
                int gttime = 0;
                long gtspan = 0;
                for (int i = 0; i < 256; i++)
                {
                    key[c] = (byte)i;
                    System.Diagnostics.Stopwatch t = System.Diagnostics.Stopwatch.StartNew();
                    for (int k = 0; k < rds; k++) {
                        openurl("http://localhost:9000/test?file=foo&signature=" + HexEncode(key), millisec);
                    }
                    if (t.ElapsedTicks > gtspan)
                    {
                        gttime = i;
                        gtspan = t.ElapsedTicks;
                    }
                    //System.Diagnostics.Debug.WriteLine(t.ElapsedTicks);
                }
                key[c] = (byte)gttime;
            }
            return key;
        }
        static void Set4()
        {
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];

            //SET 4 CHALLENGE 25
            byte[] b = System.IO.File.ReadAllLines("../../25.txt").Select(s => Convert.FromBase64String(s)).SelectMany(d => d).ToArray();
            rnd.GetBytes(key);
            byte[] o = decrypt_ecb(System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), b);
            b = crypt_ctr(0, key, o);
            Console.WriteLine("4.25 Recovered text: " + System.Text.Encoding.ASCII.GetString(FixedXOR(edit(b, key, 0, Enumerable.Repeat((byte)0, b.Length).ToArray()), b))); //XOR plaintext which is 0 in this case

            //SET 4 CHALLENGE 26
            rnd.GetBytes(key);
            b = crypt_ctr(0, key, Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata=").Concat(o).Concat(Encoding.ASCII.GetBytes(";comment2=%20like%20a%20pound%20of%20bacon")).ToArray());
            Console.WriteLine("4.26 Random string contains admin role: " + Encoding.ASCII.GetString(crypt_ctr(0, key, b)).Contains(";admin=true;"));
            Console.WriteLine("Contains admin role: " + Encoding.ASCII.GetString(crypt_ctr(0, key, Enumerable.Concat(Enumerable.Concat(b.Take(32), FixedXOR(o.Take(16).ToArray(), FixedXOR(b.Skip(32).Take(16).ToArray(), Encoding.ASCII.GetBytes(";admin=true;    ")))), b.Skip(48)).ToArray())).Contains(";admin=true;"));

            //SET 4 CHALLENGE 27
            b = System.IO.File.ReadAllLines("../../10.txt").Select(s => Convert.FromBase64String(s)).SelectMany(d => d).ToArray();
            o = decrypt_cbc(Enumerable.Repeat((byte)0, 16).ToArray(), System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), b);
            rnd.GetBytes(key);
            b = encryption_oracle_with_key_cbc(key, key, Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata="), o, Encoding.ASCII.GetBytes(";comment2=%20like%20a%20pound%20of%20bacon"));
            o = decrypt_cbc(key, key, b.Take(16).Concat(Enumerable.Repeat((byte)0, 16).Concat(b.Take(16))).ToArray());
            Console.WriteLine("4.27 IV and key found: " + (new ByteArrayComparer().Equals(key, FixedXOR(o.Take(16).ToArray(), o.Skip(32).Take(16).ToArray()))));

            //SET 4 CHALLENGE 28
            SHA1Context sc = new SHA1Context();
            SHA1_Algo.SHA1Reset(sc);
            key = System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            b = System.Text.Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
            SHA1_Algo.SHA1Input(sc, key.Concat(b).ToArray());
            o = new Byte[20];
            SHA1_Algo.SHA1Result(sc, o);
            Console.WriteLine("4.28 SHA1 output: " + HexEncode(o));

            //SET 4 CHALLENGE 29
            //message is 77 bytes or just over 1 block so the minimum 2 is a very reasonable guess though a long key would be 3 or more
            SHA1_Algo.SHA1ResetFromHashLen(sc, o, 2);
            byte[] extra = System.Text.Encoding.ASCII.GetBytes(";admin=true");
            SHA1_Algo.SHA1Input(sc, extra);
            byte[] md = new byte[20];
            SHA1_Algo.SHA1Result(sc, md);
            Console.WriteLine("4.29 SHA1 output with new message from intermediate state: " + HexEncode(md));
            SHA1_Algo.SHA1Reset(sc);
            //blocks of 64 immediately processed
            //last block >= 56 = [block + 0x80 + 0x00 .. 0x00] [0x00 .. 0x00 64-bit-bitlen-big-endian]
            //last block < 56 = [block + 0x80 + 0x00 .. 0x00 64-bit-bitlen-big-endian]
            SHA1_Algo.SHA1Input(sc, SHA1_Algo.SHA1Pad(key.Concat(b).ToArray()).Concat(extra).ToArray());
            SHA1_Algo.SHA1Result(sc, o);
            Console.WriteLine("Hash from beginning state: " + HexEncode(o));

            //SET 4 CHALLENGE 30
            //padding nearly identical to SHA1
            HashAlgorithm hash = new MD4();
            o = hash.ComputeHash(key.Concat(b).ToArray());
            Console.WriteLine("4.30 Initial hash: " + HexEncode(o));
            ((MD4)hash).InitFromHashLen(o, 2);
            Console.WriteLine("MD4 output with new message from intermediate state: " + HexEncode(hash.ComputeHash(extra)));
            o = hash.ComputeHash(MD4.MD4Pad(key.Concat(b).ToArray()).Concat(extra).ToArray());
            Console.WriteLine("Hash from beginning state: " + HexEncode(o));

            //SET 4 CHALLENGE 31
            //46b4ec586117154dacd49d664e5d63fdc88efb51
            key = breakurlkey(50, 1);
            openurl("http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51", 0); //initialize/precompile
            Console.WriteLine("4.31 Recovered key: " + HexEncode(key));
            Console.WriteLine("HMAC-SHA1 in URL from key: foo and text: bar" + HexEncode(hmac(System.Text.Encoding.ASCII.GetBytes("foo"), System.Text.Encoding.ASCII.GetBytes("bar"))));

            //SET 4 CHALLENGE 32
            key = breakurlkey(5, 5);
            Console.WriteLine("4.32 Recovered key: " + HexEncode(key));
        }
        static uint modexp(uint g, uint a, uint p)
        {
            uint d = 1;
            for (int i = 31; i >= 0; i--) {
                d = d * d % p;
                if (((1 << i) & a) != 0) {
                    d = d * g % p;
                }
            }
            return d;
        }
        class ManInTheMiddle
        {
            public bool SeeParameter(DHClient Other, DHClient First, BigInteger p, BigInteger g)
            {
                _p = p;
                if (attackver == 1) {
                    return Other.ReceiveParameter(this, First, p, 1); // 1 ^ _ab % p = 1
                } else if (attackver == 2) {
                    return Other.ReceiveParameter(this, First, p, p); // (p ^ _ab) % p = p
                } else if (attackver == 3) {
                    return Other.ReceiveParameter(this, First, p, p - 1); // (p - 1) ^ _ab % p = p - 1 or 1
                } else return false;
            }
            public bool SeeAck(DHClient Other, DHClient First)
            {
                return Other.ReceiveAck(this, First);
            }
            public bool SeeDH(DHClient Other, DHClient First, BigInteger A)
            {
                _s = attackver == 2 ? 0 : 1; //A; A ^ 1=A, A ^ p-1 % p = +/-A so if A==1 then 1 or 1/p-1, A ^ p % p == 0
                SHA1Context sc = new SHA1Context();
                SHA1_Algo.SHA1Reset(sc);
                SHA1_Algo.SHA1Input(sc, BigIntToBytes(_s));
                _key = new byte[20];
                SHA1_Algo.SHA1Result(sc, _key);
                _key = _key.Take(16).ToArray();
                return Other.ReceiveDH(this, First, true ? attackver == 2 ? 0 : attackver == 3 ? 1 : 1 : A);
            }
            public bool SeeDH(DHClient Other, DHClient First, BigInteger p, BigInteger g, BigInteger A)
            {
                _p = p;
                _s = 0;
                SHA1Context sc = new SHA1Context();
                SHA1_Algo.SHA1Reset(sc);
                SHA1_Algo.SHA1Input(sc, BigIntToBytes(_s));
                _key = new byte[20];
                SHA1_Algo.SHA1Result(sc, _key);
                _key = _key.Take(16).ToArray();
                return Other.ReceiveDH(this, First, p, g, p); // p ^ _ab % p = 0
            }
            public bool SeeNextDH(DHClient Other, DHClient First, BigInteger B)
            {
                return Other.NextReceiveDH(this, First, attackver == 0 ? _p : B);
            }
            public bool SeeMsg(DHClient Other, DHClient First, byte[] c, byte[] iv)
            {
                if (attackver == 3)
                {
                    try
                    {
                        if (Encoding.ASCII.GetString(PKCS7Strip(decrypt_cbc(iv, _key, c))) != "msg") return false;
                    } catch {
                        byte[] key = _key;
                        SHA1Context sc = new SHA1Context();
                        SHA1_Algo.SHA1Reset(sc);
                        SHA1_Algo.SHA1Input(sc, BigIntToBytes(_s = (_s == 1 ? _p - 1 : 1))); //swap _s and _key
                        _key = new byte[20];
                        SHA1_Algo.SHA1Result(sc, _key);
                        _key = _key.Take(16).ToArray();
                        if (Encoding.ASCII.GetString(PKCS7Strip(decrypt_cbc(iv, _key, c))) != "msg") return false;
                        return Other.ReceiveMsg(this, First, encrypt_cbc(iv, key, decrypt_cbc(iv, _key, c)), iv);
                    }
                } else if (Encoding.ASCII.GetString(PKCS7Strip(decrypt_cbc(iv, _key, c))) != "msg") return false;
                return Other.ReceiveMsg(this, First, c, iv);
            }
            public bool SeeNextMsg(DHClient Other, DHClient First, byte[] c, byte[] iv)
            {
                if (attackver == 3)
                {
                    try
                    {
                        //secret here is always 1 but we have swapped the key and secret to make sure we re-encode the message
                        if (Encoding.ASCII.GetString(PKCS7Strip(decrypt_cbc(iv, _key, c))) != "a's msg") return false;
                    } catch {
                        byte[] key = _key;
                        SHA1Context sc = new SHA1Context();
                        SHA1_Algo.SHA1Reset(sc);
                        SHA1_Algo.SHA1Input(sc, BigIntToBytes(_s = (_s == 1 ? _p - 1 : 1))); //swap _s and _key
                        _key = new byte[20];
                        SHA1_Algo.SHA1Result(sc, _key);
                        _key = _key.Take(16).ToArray();
                        if (Encoding.ASCII.GetString(PKCS7Strip(decrypt_cbc(iv, _key, c))) != "a's msg") return false;
                        return Other.OtherReceiveMsg(this, First, encrypt_cbc(iv, key, decrypt_cbc(iv, _key, c)), iv);
                    }
                } else if (Encoding.ASCII.GetString(PKCS7Strip(decrypt_cbc(iv, _key, c))) != "a's msg") return false;
                return Other.OtherReceiveMsg(this, First, c, iv);
            }
            public bool SeeEmailDH(DHClient Other, DHClient First, string Email, BigInteger A)
            {
                _o = A;
                return Other.SimpleReceiveEmailDH(this, First, Email, A);
            }
            public bool SeeReceiveSaltDH(DHClient Other, DHClient First, int Salt, BigInteger B, BigInteger u)
            {
                RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                _p = BigInteger.Parse("00" + "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
                _g = 2;
                _Salt = 0;//GetNextRandom(rnd, 256); // fixed salt to any value will speed up calculations
                SHA256 hsh = SHA256.Create();
                //byte[] tmp = new byte[16];
                //rnd.GetBytes(tmp);
                _s = 1; // BytesToBigInt(tmp); //u
                //while ((_ab = (uint)GetNextRandom(rnd, 37)) == 0) { }
                _ab = 1;
                _AB = BigInteger.ModPow(_g, new BigInteger(_ab), _p); //choosing u and b as 1 (hence B=g) will greatly speed up computations without losing information
                return Other.ReceiveSaltDH(this, First, _Salt, _AB, _s);
            }
            public bool SeeSimpleReceiveHMAC(DHClient Other, DHClient First, byte[] hmc)
            {
                string[] passlist = { "test", "password", "YELLOW SUBMARINE", "already found" };
                for (int i = 0; i < passlist.Length; i++)
                {
                    SHA256 hsh = SHA256.Create();
                    HMACSHA256 hmac = new HMACSHA256(hsh.ComputeHash(BigIntToBytes(BigInteger.ModPow(BigInteger.Multiply(_o, BigInteger.ModPow(BigInteger.ModPow(_g, BytesToBigInt(hsh.ComputeHash(BitConverter.GetBytes(_Salt).Concat(System.Text.Encoding.ASCII.GetBytes(passlist[i])).ToArray())), _p), _s, _p)), _ab, _p))));
                    if (new ByteArrayComparer().Equals(hmc, hmac.ComputeHash(BitConverter.GetBytes(_Salt)))) return true;
                }
                return false;
            }
            byte[] _key;
            private BigInteger _s;
            private BigInteger _p;
            private BigInteger _g;
            private BigInteger _o;
            private uint _ab;
            private BigInteger _AB;
            private int _Salt;
            public int attackver = 0;
        }
        class DHClient
        {
            public bool SendParameter(ManInTheMiddle m, DHClient Other)
            {
                _p = BigInteger.Parse("00" + "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
                _g = 2;
                return m == null ? Other.ReceiveParameter(m, this, _p, _g) : m.SeeParameter(Other, this, _p, _g);
            }
            public bool ReceiveParameter(ManInTheMiddle m, DHClient Other, BigInteger p, BigInteger g)
            {
                _p = p;
                _g = g;
                return m == null ? Other.ReceiveAck(m, this) : m.SeeAck(Other, this);
            }
            public bool ReceiveAck(ManInTheMiddle m, DHClient Other)
            {
                RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                while ((_ab = (uint)GetNextRandom(rnd, 37)) == 0) { }
                _AB = BigInteger.ModPow(_g, new BigInteger(_ab), _p);
                return m == null ? Other.ReceiveDH(m, this, _AB) : m.SeeDH(Other, this, _AB);
            }
            public bool ReceiveDH(ManInTheMiddle m, DHClient Other, BigInteger A)
            {
                RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                while ((_ab = (uint)GetNextRandom(rnd, 37)) == 0) { }
                _AB = BigInteger.ModPow(_g, new BigInteger(_ab), _p);
                _s = BigInteger.ModPow(A, _ab, _p);
                SHA1Context sc = new SHA1Context();
                SHA1_Algo.SHA1Reset(sc);
                SHA1_Algo.SHA1Input(sc, BigIntToBytes(_s));
                _key = new byte[20];
                SHA1_Algo.SHA1Result(sc, _key);
                _key = _key.Take(16).ToArray();
                return m == null ? Other.NextReceiveDH(m, this, _AB) : m.SeeNextDH(Other, this, _AB);
            }
            public bool SendDH(ManInTheMiddle m, DHClient Other)
            {
                RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                _p = BigInteger.Parse("00" + "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
                _g = 2;
                while ((_ab = (uint)GetNextRandom(rnd, 37)) == 0) { }
                _AB = BigInteger.ModPow(_g, new BigInteger(_ab), _p);
                return m == null ? Other.ReceiveDH(m, this, _p, _g, _AB) : m.SeeDH(Other, this, _p, _g, _AB);
            }
            public bool ReceiveDH(ManInTheMiddle m, DHClient Other, BigInteger p, BigInteger g, BigInteger A)
            {
                _p = p;
                _g = g;
                return ReceiveDH(m, Other, A);
            }
            public bool NextReceiveDH(ManInTheMiddle m, DHClient Other, BigInteger B)
            {
                _s = BigInteger.ModPow(B, _ab, _p);
                SHA1Context sc = new SHA1Context();
                SHA1_Algo.SHA1Reset(sc);
                SHA1_Algo.SHA1Input(sc, BigIntToBytes(_s));
                _key = new byte[20];
                SHA1_Algo.SHA1Result(sc, _key);
                _key = _key.Take(16).ToArray();
                RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                byte[] iv = new byte[16];
                rnd.GetBytes(iv);
                return m == null ? ReceiveMsg(m, this, encrypt_cbc(iv, _key, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("msg"), 16)), iv) : m.SeeMsg(Other, this, encrypt_cbc(iv, _key, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("msg"), 16)), iv);
            }
            public bool ReceiveMsg(ManInTheMiddle m, DHClient Other, byte[] c, byte[] iv)
            {
                if (Encoding.ASCII.GetString(PKCS7Strip(decrypt_cbc(iv, _key, c))) != "msg") return false;
                RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                iv = new byte[16];
                rnd.GetBytes(iv);
                return m == null ? OtherReceiveMsg(m, this, encrypt_cbc(iv, _key, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("a's msg"), 16)), iv) : m.SeeNextMsg(Other, this, encrypt_cbc(iv, _key, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("a's msg"), 16)), iv);
            }
            public bool OtherReceiveMsg(ManInTheMiddle m, DHClient Other, byte[] c, byte[] iv)
            {
                return (Encoding.ASCII.GetString(PKCS7Strip(decrypt_cbc(iv, _key, c))) == "a's msg");
            }
            public bool SendEmailDH(ManInTheMiddle m, DHClient Other, bool bSimple = false)
            {
                RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                _p = BigInteger.Parse("00" + "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
                _g = 2;
                while ((_ab = (uint)GetNextRandom(rnd, 37)) == 0) { }
                _AB = BigInteger.ModPow(_g, new BigInteger(_ab), _p);
                return m == null ? (bSimple ? Other.SimpleReceiveEmailDH(m, this, "no@no.no", _AB) : Other.ReceiveEmailDH(this, "no@no.no", _AB)) : m.SeeEmailDH(Other, this, "no@no.no", _AB);
            }
            public bool SendEmailDHBreakKey(DHClient Other, BigInteger FakeA)
            {
                RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                _p = BigInteger.Parse("00" + "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
                _g = 2;
                while ((_ab = (uint)GetNextRandom(rnd, 37)) == 0) { }
                _AB = FakeA;
                anypass = true;
                return Other.ReceiveEmailDH(this, "no@no.no", _AB);
            }
            public bool SimpleReceiveEmailDH(ManInTheMiddle m, DHClient Other, string Email, BigInteger A)
            {
                if (Email != "no@no.no") return false;
                RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                _p = BigInteger.Parse("00" + "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
                _g = 2;
                _Salt = GetNextRandom(rnd, 256);
                SHA256 hsh = SHA256.Create();
                _o = A;
                byte[] tmp = new byte[16];
                rnd.GetBytes(tmp);
                _s = BytesToBigInt(tmp); //u
                while ((_ab = (uint)GetNextRandom(rnd, 37)) == 0) { }
                _AB = BigInteger.ModPow(_g, new BigInteger(_ab), _p);
                return m == null ? Other.ReceiveSaltDH(m, this, _Salt, _AB, _s) : m.SeeReceiveSaltDH(Other, this, _Salt, _AB, _s);
            }
            public bool ReceiveEmailDH(DHClient Other, string Email, BigInteger A)
            {
                if (Email != "no@no.no") return false;
                RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                _p = BigInteger.Parse("00" + "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
                _g = 2;
                _Salt = GetNextRandom(rnd, 256);
                SHA256 hsh = SHA256.Create();
                _o = A;
                _s = BigInteger.ModPow(_g, BytesToBigInt(hsh.ComputeHash(BitConverter.GetBytes(_Salt).Concat(System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE")).ToArray())), _p); //v
                while ((_ab = (uint)GetNextRandom(rnd, 37)) == 0) { }
                _AB = BigInteger.Remainder(BigInteger.Add(BigInteger.Multiply(_s, 3), BigInteger.ModPow(_g, new BigInteger(_ab), _p)), _p);
                return Other.ReceiveSaltDH(this, _Salt, _AB);
            }
            public bool ReceiveSaltDH(ManInTheMiddle m, DHClient Other, int Salt, BigInteger B, BigInteger u)
            {
                SHA256 hsh = SHA256.Create();
                BigInteger x = BytesToBigInt(hsh.ComputeHash(BitConverter.GetBytes(Salt).Concat(System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE")).ToArray()));
                HMACSHA256 hmac = new HMACSHA256(hsh.ComputeHash(BigIntToBytes(BigInteger.ModPow(B, BigInteger.Add(_ab, BigInteger.Multiply(u, x)), _p))));
                return m == null ? Other.SimpleReceiveHMAC(m, this, hmac.ComputeHash(BitConverter.GetBytes(Salt))) : m.SeeSimpleReceiveHMAC(Other, this, hmac.ComputeHash(BitConverter.GetBytes(Salt)));
            }
            public bool ReceiveSaltDH(DHClient Other, int Salt, BigInteger B)
            {
                SHA256 hsh = SHA256.Create();
                BigInteger x = BytesToBigInt(hsh.ComputeHash(BitConverter.GetBytes(Salt).Concat(System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE")).ToArray()).ToArray());
                HMACSHA256 hmac = new HMACSHA256(hsh.ComputeHash(anypass ? BigIntToBytes(new BigInteger(0)) : BigIntToBytes(BigInteger.ModPow(posRemainder(BigInteger.Subtract(B, BigInteger.Multiply(3, BigInteger.ModPow(_g, x, _p))), _p), BigInteger.Add(_ab, BigInteger.Multiply(BytesToBigInt(hsh.ComputeHash(BigIntToBytes(_AB).Concat(BigIntToBytes(B)).ToArray())), x)), _p))));
                return Other.ReceiveHMAC(this, hmac.ComputeHash(BitConverter.GetBytes(Salt)));
            }
            public bool SimpleReceiveHMAC(ManInTheMiddle m, DHClient Other, byte[] hmc)
            {
                SHA256 hsh = SHA256.Create();
                HMACSHA256 hmac = new HMACSHA256(hsh.ComputeHash(BigIntToBytes(BigInteger.ModPow(BigInteger.Multiply(_o, BigInteger.ModPow(BigInteger.ModPow(_g, BytesToBigInt(hsh.ComputeHash(BitConverter.GetBytes(_Salt).Concat(System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE")).ToArray())), _p), _s, _p)), _ab, _p))));
                return Other.OtherReceiveHMAC(this, new ByteArrayComparer().Equals(hmc, hmac.ComputeHash(BitConverter.GetBytes(_Salt))));
            }
            public bool ReceiveHMAC(DHClient Other, byte[] hmc)
            {
                SHA256 hsh = SHA256.Create();
                HMACSHA256 hmac = new HMACSHA256(hsh.ComputeHash(BigIntToBytes(BigInteger.ModPow(BigInteger.Multiply(_o, BigInteger.ModPow(_s, BytesToBigInt(hsh.ComputeHash(BigIntToBytes(_o).Concat(BigIntToBytes(_AB)).ToArray())), _p)), _ab, _p))));
                return Other.OtherReceiveHMAC(this, new ByteArrayComparer().Equals(hmc, hmac.ComputeHash(BitConverter.GetBytes(_Salt))));
            }
            public bool OtherReceiveHMAC(DHClient Other, bool isOkay)
            {
                return isOkay;
            }
            byte[] _key;
            private BigInteger _p;
            private BigInteger _g;
            private uint _ab;
            private BigInteger _AB;
            private BigInteger _s;
            private BigInteger _o;
            private int _Salt;
            private bool anypass;
        }
        public static bool IsProbablePrime(BigInteger source, int certainty)
        {
            if (source == 2 || source == 3)
                return true;
            if (source < 2 || source % 2 == 0)
                return false;

            BigInteger d = source - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            // There is no built-in method for generating random BigInteger values.
            // Instead, random BigIntegers are constructed from randomly generated
            // byte arrays of the same length as the source.
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            BigInteger a;
            int bits = GetBitSize(source);

            for (int i = 0; i < certainty; i++)
            {
                do {
                    a = GetRandomBitSize(rng, bits, source - 2);
                } while (a < 2);

                BigInteger x = BigInteger.ModPow(a, d, source);
                if (x == 1 || x == source - 1)
                    continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, source);
                    if (x == 1)
                        return false;
                    if (x == source - 1)
                        break;
                }

                if (x != source - 1)
                    return false;
            }

            return true;
        }
        //Extended Euclid GCD of 1
        static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0) {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }
        //from Hacker's Delight
        public static BigInteger icbrt2(BigInteger x)
        {
            BigInteger b;
            BigInteger y2 = 0;
            BigInteger y = 0;
            for (int s = (GetBitSize(x) / 3) * 3; s >= 0; s = s - 3) {
                y2 = 4 * y2;
                y = 2 * y;
                b = (3 * (y2 + y) + 1) * BigInteger.Pow(2, s);
                if (x >= b) {
                    x = x - b;
                    y2 = y2 + 2 * y + 1;
                    y = y + 1;
                }
            }
            return y;
        }
        BigInteger modPow(BigInteger b, BigInteger e, BigInteger m)
        {
            BigInteger result = 1;
            while (e != 0) {
                if (!e.IsEven) result = (result * b) % m;
                e /= 2;
                b = (b ^ 2) % m;
            }
            return result;
        }

        static void Set5()
        {
            //SET 5 CHALLENGE 33
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            uint p = 37;
            uint g = 5;
            uint a;
            while ((a = (uint)GetNextRandom(rnd, 37)) == 0) { }
            uint A = modexp(g, a, p);
            uint b;
            while ((b = (uint)GetNextRandom(rnd, 37)) == 0) { }
            uint B = modexp(g, b, p);
            uint s = modexp(B, a, p);
            Console.WriteLine("5.33 Shared secrets equal: " + (s == modexp(A, b, p)));
            BigInteger _p = BigInteger.Parse("00" + "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
            BigInteger _g = 2;
            BigInteger _a = a;
            BigInteger _A = BigInteger.ModPow(_g, _a, _p);
            BigInteger _b = b;
            BigInteger _B = BigInteger.ModPow(_g, _b, _p);
            BigInteger _s = BigInteger.ModPow(_B, _a, _p);
            Console.WriteLine("Shared secrets equal with big parameters: " + (_s == BigInteger.ModPow(_A, _b, _p)));

            //SET 5 CHALLENGE 34
            DHClient Alice = new DHClient();
            DHClient Bob = new DHClient();
            Console.WriteLine("5.34 Message exchange successful: " + Alice.SendDH(null, Bob));
            ManInTheMiddle Chuck = new ManInTheMiddle();
            Console.WriteLine("Message exchange injection and snooping successful: " + Alice.SendDH(Chuck, Bob));

            //SET 5 CHALLENGE 35
            //when g=1 or g=p-1, and we set A=1 then the secret will always be 1
            //when g=p, we set A=p and the secret will always be 0 similar to the previous break
            //if not setting A, the protocol will abort because the initiator has s=A or s=1, but the receiver has s=A^b so cannot decrypt the first message
            //at best by setting s=A or s=1, the first message of initiator can be decrypted before the abort occurs
            Chuck.attackver = 1;
            Console.WriteLine("5.35 With g=1 injection and snopping successful: " + Alice.SendParameter(Chuck, Bob));
            Chuck.attackver = 2;
            Console.WriteLine("With g=p injection and snopping successful: " + Alice.SendParameter(Chuck, Bob));
            Chuck.attackver = 3; //8 tries to prove that it works in the other 25% of cases
            Console.WriteLine("With g=p-1 injection and snopping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snopping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snopping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snopping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snopping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snopping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snopping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snopping successful: " + Alice.SendParameter(Chuck, Bob));

            //SET 5 CHALLENGE 36
            Console.WriteLine("5.36 Secure Remote Password DH succeeds: " + Alice.SendEmailDH(null, Bob));

            //SET 5 CHALLENGE 37
            Console.WriteLine("5.37 SRP with 0 public exponent succeeds: " + Alice.SendEmailDHBreakKey(Bob, 0)); //p, p^2, ..., p^n
            Console.WriteLine("n succeeds: " + Alice.SendEmailDHBreakKey(Bob, _p));
            Console.WriteLine("n^2 succeeds: " + Alice.SendEmailDHBreakKey(Bob, BigInteger.ModPow(_p, 2, _p)));

            //SET 5 CHALLENGE 38
            Console.WriteLine("5.38 Simplified SRP succeeds: " + Alice.SendEmailDH(null, Bob, true));
            Console.WriteLine("With MITM dictionary attack salt=0, u=1, b=1, B=g finds password: " + Alice.SendEmailDH(Chuck, Bob, true));

            //SET 5 CHALLENGE 39
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            BigInteger _q;
            BigInteger et;
            do {
                do {
                    _p = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_p, 64));
                do {
                    _q = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_q, 64));
            } while (modInverse(3, et = (_p - 1) * (_q - 1)) == 1); //the totient must be coprime to our fixed e=3
            BigInteger n = _p * _q;
            BigInteger d = modInverse(3, et);
            BigInteger m = 42;
            BigInteger c = BigInteger.ModPow(m, 3, n);
            Console.WriteLine("5.39 RSA decrypts to 42: " + (42 == BigInteger.ModPow(c, d, n)));

            //SET 5 CHALLENGE 40
            do
            {
                do {
                    _p = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_p, 64));
                do {
                    _q = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_q, 64));
            } while (modInverse(3, et = (_p - 1) * (_q - 1)) == 1); //the totient must be coprime to our fixed e=3
            BigInteger n1 = _p * _q;
            BigInteger c1 = BigInteger.ModPow(m, 3, n1);
            do {
                do {
                    _p = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_p, 64));
                do {
                    _q = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_q, 64));
            } while (modInverse(3, et = (_p - 1) * (_q - 1)) == 1); //the totient must be coprime to our fixed e=3
            BigInteger n2 = _p * _q;
            BigInteger c2 = BigInteger.ModPow(m, 3, n2);
            BigInteger result = BigInteger.Remainder(c * n1 * n2 * modInverse(n1 * n2, n) + c1 * n * n2 * modInverse(n * n2, n1) + c2 * n * n1 * modInverse(n * n1, n2), n * n1 * n2);
            Console.WriteLine("5.40 Integer cube root result: " + icbrt2(result));
        }
        static BigInteger GetPivotRandom(RandomNumberGenerator rng, int BitSize)
        {
            byte[] r = new byte[(BitSize >> 3) + 1];
            rng.GetBytes(r);
            r[r.Length - 1] &= (byte)((1 << (BitSize % 8)) - 1); //make sure it wont be interpreted as negative in little-endian order
            r[r.Length - 1 - (BitSize % 8 == 0 ? 1 : 0)] |= (byte)(1 << ((BitSize - 1) % 8)); //always set bitsize-th bit
            return new BigInteger(r);
        }
        static int GetBitSizeSlow(BigInteger num)
        {
            int s = 0;
            while ((BigInteger.One << s) <= num) s = s + 1;
            //if (s != GetBitSizeBinSearch(num)) throw new ArgumentException();
            return s;
        }
        static int GetBitSize(BigInteger num)
        { //instead of 0, 1, 2, 3, 4... use 0, 1, 3, 7, 15, etc
            int s = 0, t = 1, oldt = 1;
            if (t <= 0) return 0;
            while (true) {
                if ((BigInteger.One << (s + t)) <= num) { oldt = t; t <<= 1; }
                else if (t == 1) break;
                else { s += oldt; t = 1; }
            }
            return s + 1;
        }
        static BigInteger GetRandomBitSize(RandomNumberGenerator rng, int BitSize, BigInteger Max)
        {
            byte[] r = new byte[(BitSize >> 3) + 1];
            rng.GetBytes(r);
            r[r.Length - 1] &= (byte)((1 << (BitSize % 8)) - 1); //make sure it wont be interpreted as negative in little-endian order
            return new BigInteger(r) >= Max ? Max - 1 : new BigInteger(r);
        }
        static byte[] PadToSize(byte[] arr, int size)
        {
            return (arr.Length >= size ? arr.Skip(arr.Length - size).ToArray() : Enumerable.Repeat((byte)0, size - arr.Length).Concat(arr).ToArray());
        }
        static BigInteger posRemainder(BigInteger dividend, BigInteger divisor)
        {
            BigInteger r = dividend % divisor; //BigInteger.Remainder(dividend, divisor);
            //if ((r < 0 ? r + divisor : r) != modBarrettReduction(dividend, divisor)) throw new ArgumentException();
            return r < 0 ? r + divisor : r;
        }
        static BigInteger BytesToBigInt(byte[] b)
        {
            return new BigInteger(b[0] == 0 ? b.Reverse().ToArray() : b.Reverse().Concat(new byte[] { 0 }).ToArray());
        }
        static byte[] BigIntToBytes(BigInteger b)
        {
            return b.ToByteArray().Reverse().SkipWhile((bt) => bt == 0).ToArray(); //maximum of one 0 byte so this is okay...
        }
        static bool DSAValidate(BigInteger q, BigInteger p, BigInteger g, BigInteger y, BigInteger r, BigInteger s, BigInteger hm)
        {
            BigInteger w = modInverse(s, q);
            BigInteger u1 = BigInteger.Remainder(hm * w, q);
            BigInteger u2 = BigInteger.Remainder(r * w, q);
            return BigInteger.Remainder(BigInteger.ModPow(g, u1, p) * BigInteger.ModPow(y, u2, p), q) == r;
        }
        static bool IsPKCSConforming(BigInteger c, BigInteger d, BigInteger n)
        {
            byte[] b = BigIntToBytes(BigInteger.ModPow(c, d, n));
            return (b.Length == (GetBitSize(n) - 1) / 8 && b[0] == 2);
        }
        static BigInteger BleichenBacherPaddingOracle(RandomNumberGenerator rng, BigInteger n, BigInteger e, BigInteger d, BigInteger c)
        {
            BigInteger s0;
            bool blinding = false;
            if (!blinding) //blinding or initialization step 1
            {
                s0 = 1;
            }
            else
            {
                s0 = GetNextRandom(rng, int.MaxValue);
                for (; !IsPKCSConforming(BigInteger.Remainder(c * BigInteger.ModPow(s0, e, n), n), d, n); s0 = GetNextRandom(rng, int.MaxValue)) { }
            }
            Console.WriteLine(IsPKCSConforming(BigInteger.Remainder(c * BigInteger.ModPow(s0, e, n), n), d, n));
            BigInteger si1 = s0;
            int i = 1;
            List<BigInteger[]> Intervals = new List<BigInteger[]>();
            List<BigInteger[]> Intervalsi1 = new List<BigInteger[]>();
            BigInteger bsize = BigInteger.Pow(2, ((GetBitSize(n) + 7) / 8 - 2) * 8);
            Intervalsi1.Add(new BigInteger[] { 2 * bsize, 3 * bsize - 1 });
            BigInteger c0 = BigInteger.Remainder(c * BigInteger.ModPow(s0, e, n), n);
            BigInteger si;
            int j;
            do
            {
                //step 2.a and step 2.b and 2.c
                if (i == 1 || Intervalsi1.Count != 1)
                {
                    si = i == 1 ? n / (3 * bsize) : si1 + 1;
                    for (; !IsPKCSConforming(BigInteger.Remainder(c0 * BigInteger.ModPow(si, e, n), n), d, n); si += 1) { }
                }
                else
                {
                    BigInteger ri = 2 * (Intervalsi1[0][1] * si1 - 2 * bsize) / n;
                    do
                    {
                        BigInteger ub = (3 * bsize + ri * n) / Intervalsi1[0][0];
                        for (si = (2 * bsize + ri * n) / Intervalsi1[0][1]; si <= ub; si++)
                        {
                            if (IsPKCSConforming(BigInteger.Remainder(c0 * BigInteger.ModPow(si, e, n), n), d, n)) break;
                        }
                        if (si <= ub) break;
                        ri++;
                    } while (true);
                }
                //step 3
                for (j = 0; j < Intervalsi1.Count; j++)
                {
                    for (BigInteger r = (Intervalsi1[j][0] * si - 3 * bsize + 1) / n; r <= (Intervalsi1[j][1] * si - 2 * bsize) / n; r++)
                    {
                        BigInteger mx = BigInteger.Max(Intervalsi1[j][0], (2 * bsize + r * n + si - 1) / si);
                        BigInteger mn = BigInteger.Min(Intervalsi1[j][1], (3 * bsize - 1 + r * n) / si);
                        if (mx <= mn) Intervals.Add(new BigInteger[] { mx, mn });
                    }
                }
                Intervals = Intervals.Distinct(new BigIntArrayComparer()).ToList(); //finish the union with distinctness criterion
                //step 4
                for (j = 0; j < Intervals.Count; j++)
                {
                    if (Intervals[j][0] == Intervals[j][1]) break; //with blinding effectively this is the same as Intervals[j][0]
                }
                if (j != Intervals.Count) break;
                i++;
                si1 = si;
                Intervalsi1 = Intervals;
                Intervals = new List<BigInteger[]>();
            } while (true);
            return BigInteger.Remainder(Intervals[j][0] * modInverse(s0, n), n);
        }
        class BigIntArrayComparer : IEqualityComparer<BigInteger[]>
        {
            public bool Equals(BigInteger[] x, BigInteger[] y)
            {
                return x[0] == y[0] && x[1] == y[1];
            }
            public int GetHashCode(BigInteger[] obj)
            {
                return obj[0].GetHashCode() ^ obj[1].GetHashCode();
            }
        }
        static void Set6()
        {
            //SET 6 CHALLENGE 41
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            BigInteger _p;
            BigInteger _q;
            BigInteger et;
            do
            {
                //do {
                //    _p = GetPivotRandom(rng, 1536);
                //} while (!IsProbablePrime(_p, 256));
                //do {
                //    _q = GetPivotRandom(rng, 1536);
                //} while (!IsProbablePrime(_q, 256));
                _p = BigInteger.Parse("1538351477610061478490275877391293689255689217092560136893201361066354534867286429869906388817450032805434945081435502701151173877054093820587462501081516115401787238232395766006570867734998219138782543194600598895943441696131379232436323406139242567467532952373171298341997661953712862783689776081779825537852625355036649464217371831489726158268205007742056794397136669173163944001808779586539476193869917647876298150485787155207601800373938150694570451769785649");
                _q = BigInteger.Parse("1734827493435818336176773058030525039389969784884677585793445816767712516001795534356117069792199524584394009072617626753229173135864269965383874172480571223231886094115416162519003126923068072334212152436574466333269254678824843170019255570014611225507046425550398082136107201319933605255673980430818069748924916231863199520474254420649220258987612270431816034603732864149517943444944076137587884492262147097216000644970827565982359738448318803265238993406676797");
            } while (modInverse(3, et = (_p - 1) * (_q - 1)) == 1); //the totient must be coprime to our fixed e=3

            BigInteger n = _p * _q;
            BigInteger d = modInverse(3, et);
            BigInteger m = 555555555;
            BigInteger c = BigInteger.ModPow(m, 3, n);

            BigInteger s = GetRandomBitSize(rng, GetBitSize(n), n);
            BigInteger cprime = BigInteger.Remainder(BigInteger.ModPow(s, 3, n) * c, n);
            BigInteger pprime = BigInteger.ModPow(cprime, d, n);
            Console.WriteLine(BigInteger.Remainder(pprime * modInverse(s, n), n) == BigInteger.ModPow(c, d, n));

            //SET 6 CHALLENGE 42
            //get a real signature with a valid ASN.1 value from the libraries to check this more difficult to obtain value though for some hash functions its in RFC
            byte[] sig;
            byte[] ptext = System.Text.Encoding.ASCII.GetBytes("hi mom");
            SHA1 hf = SHA1.Create();
            //RSAParameters needs 0 padded or minus sign bytes stripped to the correct length then reversed for big endian
            //RSAParameters parms = new RSAParameters() { P = PadToSize(BigIntToBytes(_p), 192), Q = PadToSize(BigIntToBytes(_q), 192), D = PadToSize(BigIntToBytes(d), 384), Exponent = PadToSize(BigIntToBytes(new BigInteger(3)), 4), Modulus = PadToSize(BigIntToBytes(n), 384), DP = PadToSize(BigIntToBytes(BigInteger.Remainder(d, _p - 1)), 192), DQ = PadToSize(BigIntToBytes(BigInteger.Remainder(d, _q - 1)), 192), InverseQ = PadToSize(BigIntToBytes(modInverse(_q, n)), 192) };
            //RSA check = RSA.Create();
            //check.ImportParameters(parms);
            //RSAPKCS1SignatureFormatter sigmaker = new RSAPKCS1SignatureFormatter(check);
            //sigmaker.SetHashAlgorithm("SHA1");
            //sigmaker.SetKey(check);
            //sig = sigmaker.CreateSignature(hf.ComputeHash(ptext));
            //used for deducing some DER encoded ASN.1 values for a realistic simulation

            //Hal Finney's write up of Bleichenbacher's attack: http://marc.info/?l=cryptography&m=115694833312008
            //PKCS #1 v1.5: https://tools.ietf.org/html/rfc2313 and the DER encoded values in http://www.ietf.org/rfc/rfc3447.txt
            //SHA1 "1.3.14.3.2.26", SHA256 "2.16.840.1.101.3.4.2.1", 15 vs 19 bytes
            //DER encoded: 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14, 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
            byte[] ASN1_PKCS1_SHA1 = new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0xe, 3, 2, 0x1a, 5, 0, 4, 0x14 }; //DER encoded PKCS#1 (-> 1.5) "1.2.840.113549.1.1" iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 with SHA-1=5, SHA-256=11
            m = BytesToBigInt(new byte[] { 0 }.Concat(ASN1_PKCS1_SHA1.Concat(hf.ComputeHash(ptext))).ToArray());
            // PKCS#1 00 01 FF ... FF 00
            m = BigInteger.ModPow(BytesToBigInt(new byte[] { 0, 1 }.Concat(Enumerable.Repeat((byte)0xFF, 384 - 2 - 36)).ToArray()) * BigInteger.Pow(2, 288) + m, d, n); //legitimate signature
            BigInteger signature = BigInteger.ModPow(m, 3, n); // = BigInteger.Pow(m, 3);
            sig = PadToSize(BigIntToBytes(signature), 384);
            if (sig[0] == 0 && sig[1] == 1) {
                int i;
                for (i = 2; i < sig.Length; i++) {
                    if (sig[i] != 0xFF) break;
                }
                if (sig[i] == 0 && new ByteArrayComparer().Equals(ASN1_PKCS1_SHA1, sig.Skip(i + 1).Take(15).ToArray())) {
                    Console.WriteLine(new ByteArrayComparer().Equals(sig.Skip(i + 16).Take(20).ToArray(), hf.ComputeHash(ptext)));
                }
            }

            m = BytesToBigInt(new byte[] { 0 }.Concat(ASN1_PKCS1_SHA1.Concat(hf.ComputeHash(ptext))).ToArray());
            BigInteger garbage = BigInteger.Pow(2, 2360) - m * BigInteger.Pow(2, 2072) - (BigInteger.Pow(2, 288) - m) * BigInteger.Pow(2, 2072) + (BigInteger.Pow((BigInteger.Pow(2, 288) - m), 2) * BigInteger.Pow(2, 1087) / 3) - (BigInteger.Pow((BigInteger.Pow(2, 288) - m), 3) * BigInteger.Pow(2, 102) / 27);
            //N=2^288-D where D is 00 01 FF ... FF ASN.1 SHA1-HASH shifted by 2072 bits
            //2 ^ 3057 - 2 ^ 2360 + D * 2 ^ 2072 + garbage=2^3057 - N*2^2072 + garbage
            //a possible cube root is 2^1019 - (N * 2^34 / 3)
            //cube is 2^3057 - N*2^2072 + (N^2 * 2^1087 / 3) - (N^3 * 2^102 / 27)=2^3057 - N*2^2072 + garbage since (A-B)^3=A^3 - 3(A^2)B + 3A(B^2) - B^3
            //implementation error if garbage at end and less FF values
            Console.WriteLine(((BigInteger.Pow(2, 288) - m) % 3) == 0); //N must be divisible by 3 to allow calculation to succeed
            m = icbrt2(BytesToBigInt(new byte[] { 0, 1 }.Concat(Enumerable.Repeat((byte)0xFF, 384 - 259 - 2 - 36)).ToArray()) * BigInteger.Pow(2, 2360) + m * BigInteger.Pow(2, 2072) + garbage); //forgery
            signature = BigInteger.ModPow(m, 3, n); // = BigInteger.Pow(m, 3);
            sig = PadToSize(BigIntToBytes(signature), 384);
            if (sig[0] == 0 && sig[1] == 1) {
                int i;
                for (i = 2; i < sig.Length; i++) {
                    if (sig[i] != 0xFF) break;
                }
                //i == 384 - 36 check would avoid the break...
                if (sig[i] == 0 && new ByteArrayComparer().Equals(ASN1_PKCS1_SHA1, sig.Skip(i + 1).Take(15).ToArray())) {
                    Console.WriteLine(new ByteArrayComparer().Equals(sig.Skip(i + 16).Take(20).ToArray(), hf.ComputeHash(ptext)));
                }
            }

            //SET 6 CHALLENGE 43

            _p = BigInteger.Parse("00" + "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", System.Globalization.NumberStyles.HexNumber);
            _q = BigInteger.Parse("00" + "f4f47f05794b256174bba6e9b396a7707e563c5b", System.Globalization.NumberStyles.HexNumber);
            BigInteger g = BigInteger.Parse("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", System.Globalization.NumberStyles.HexNumber);
            BigInteger y = BigInteger.Parse("00" + "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", System.Globalization.NumberStyles.HexNumber);
            byte[] b = System.Text.Encoding.ASCII.GetBytes("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n");
            Console.WriteLine(new ByteArrayComparer().Equals(hf.ComputeHash(b), HexDecode("d2d0714f014a9784047eaeccf956520045c45265")));
            BigInteger r = BigInteger.Parse("548099063082341131477253921760299949438196259240");
            s = BigInteger.Parse("857042759984254168557880549501802188789837994940");
            BigInteger realx = BigInteger.Parse("0954edd5e0afe5542a4adf012611a91912a3ec16", System.Globalization.NumberStyles.HexNumber);
            BigInteger x;
            BigInteger mhsh = BytesToBigInt(hf.ComputeHash(b));
            BigInteger rinv = modInverse(r, _q);
            for (int _k = 16574; _k <= 1 << 16; _k++) {
                x = posRemainder((s * _k - mhsh) * rinv, _q);
                //x = 499e6554da7afd18096df79f123e6bd17328fb15 k=16575
                if (BigInteger.ModPow(g, x, _p) == y) {
                    Console.WriteLine("Found x: " + HexEncode(BigIntToBytes(x)) + " k: " + _k.ToString());
                    if (BytesToBigInt(hf.ComputeHash(System.Text.Encoding.ASCII.GetBytes(HexEncode(BigIntToBytes(x))))) == realx) {
                        Console.WriteLine("Matches hash");
                    }
                    if (r == BigInteger.Remainder(BigInteger.ModPow(g, _k, _p), _q) && s == BigInteger.Remainder(modInverse(_k, _q) * (BytesToBigInt(hf.ComputeHash(b)) + x * r), _q)) {
                        Console.WriteLine("Matches r and s");
                    }
                    break;
                }
            }

            //SET 6 CHALLENGE 44
            y = BigInteger.Parse("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", System.Globalization.NumberStyles.HexNumber);
            realx = BigInteger.Parse("00" + "ca8f6f7c66fa362d40760d135b763eb8527d3d52", System.Globalization.NumberStyles.HexNumber);
            string[] strs = System.IO.File.ReadAllLines("../../44.txt");
            BigInteger k;
            for (int i = 0; i < strs.Length; i += 4) { //(n^2+n)/2 possibilities to try
                for (int j = i + 4; j < strs.Length; j += 4) {
                    k = posRemainder(posRemainder(BigInteger.Parse("00" + strs[i + 3].Remove(0, 3), System.Globalization.NumberStyles.HexNumber) - BigInteger.Parse("00" + strs[j + 3].Remove(0, 3), System.Globalization.NumberStyles.HexNumber), _q) *
                        modInverse(posRemainder(BigInteger.Parse(strs[i + 1].Remove(0, 3)) - BigInteger.Parse(strs[j + 1].Remove(0, 3)), _q), _q), _q);
                    x = posRemainder((BigInteger.Parse(strs[j + 1].Remove(0, 3)) * k - BytesToBigInt(hf.ComputeHash(System.Text.Encoding.ASCII.GetBytes(strs[j].Remove(0, 5))))) * modInverse(BigInteger.Parse(strs[j + 2].Remove(0, 3)), _q), _q);
                    if (BigInteger.ModPow(g, x, _p) == y) {
                        Console.WriteLine("Found x: " + HexEncode(BigIntToBytes(x)) + " k: " + HexEncode(BigIntToBytes(k)) + " entries: " + (i / 4).ToString() + ", " + (j / 4).ToString());
                        if (BytesToBigInt(hf.ComputeHash(System.Text.Encoding.ASCII.GetBytes(HexEncode(BigIntToBytes(x))))) == realx)
                        {
                            Console.WriteLine("Matches hash");
                        }
                    }
                }
            }

            //SET 6 CHALLENGE 45
            g = 0;
            k = GetRandomBitSize(rng, GetBitSize(_q), _q);
            y = BigInteger.Parse("00" + "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", System.Globalization.NumberStyles.HexNumber);
            x = BigInteger.Parse("00" + "499e6554da7afd18096df79f123e6bd17328fb15", System.Globalization.NumberStyles.HexNumber);
            r = BigInteger.Remainder(BigInteger.ModPow(g, k, _p), _q);
            s = BigInteger.Remainder(modInverse(k, _q) * (BytesToBigInt(hf.ComputeHash(b)) + x * r), _q);
            Console.WriteLine("r == 0: " + (r == 0).ToString() + " s: " + HexEncode(BigIntToBytes(s)) + " recovered k == k: " + (k == BigInteger.Remainder(modInverse(s, _q) * BytesToBigInt(hf.ComputeHash(b)), _q)).ToString());
            Console.WriteLine(DSAValidate(_q, _p, g, y, r, s, BytesToBigInt(hf.ComputeHash(b))));
            g = _p + 1; //same as using 1
            BigInteger z = GetRandomBitSize(rng, GetBitSize(_q), _q);
            r = BigInteger.Remainder(BigInteger.ModPow(y, z, _p), _q);
            s = BigInteger.Remainder(r * modInverse(z, _q), _q);
            Console.WriteLine(DSAValidate(_q, _p, g, y, r, s, BytesToBigInt(hf.ComputeHash(b))));
            Console.WriteLine(DSAValidate(_q, _p, g, y, r, s, BytesToBigInt(hf.ComputeHash(System.Text.Encoding.ASCII.GetBytes("Hello, world")))));
            Console.WriteLine(DSAValidate(_q, _p, g, y, r, s, BytesToBigInt(hf.ComputeHash(System.Text.Encoding.ASCII.GetBytes("Goodbye, world")))));

            //SET 6 CHALLENGE 46

            do
            {
                //do
                //{
                //    _p = GetPivotRandom(rng, 1024);
                //} while (!IsProbablePrime(_p, 256));
                //do
                //{
                //    _q = GetPivotRandom(rng, 1024);
                //} while (!IsProbablePrime(_q, 256));
                _p = BigInteger.Parse("97077030932104802284940686692945479273403779175760221117723819516153453837955884028799063151915362006300646767671088966981467828841381943539728428707491854730423327954207598914323653776600819434790945078060804332799255976938481298977048092983541957347275053610454026995658973516030986018960012208967898765429");
                _q = BigInteger.Parse("168681937745034746959314925177428099780787382075951203471297511943978176202758101393815778412936910367663323945690112148196984674722220426446257338983921160524529781462275737999762893078384771514408719375217581450146951432838686843968460606403061839780018969120049813190167943010439627583410290421209333632987");
            } while (modInverse(3, et = (_p - 1) * (_q - 1)) == 1); //the totient must be coprime to our fixed e=3

            n = _p * _q; //product of 2 primes is always odd number if neither one is 2
            d = modInverse(3, et);
            m = BytesToBigInt(Convert.FromBase64String("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="));
            c = BigInteger.ModPow(m, 3, n);
            //BigInteger.Remainder(BigInteger.ModPow(c, d, n), 2);
            BigInteger lbound = 0;
            BigInteger ubound = n;
            cprime = c;
            BigInteger enctwo = BigInteger.ModPow(2, 3, n);
            BigInteger multiplier = 1;
            //division by 2 will lead to inaccuracies in final bits so must do it with known division at final stage
            int bsize = GetBitSize(n);
            //int rc = 0;
            //while (rc < bsize) {
            //    cprime = BigInteger.Remainder(cprime * enctwo, n);
            //    multiplier *= 2;
            //    if (BigInteger.Remainder(BigInteger.ModPow(cprime, d, n), 2) == 0) {
            //        ubound = (ubound + lbound);
            //        lbound *= 2;
            //        multiplier--;
            //    }
            //    else {
            //        ubound *= 2;
            //        lbound = (ubound + lbound);
            //    }
            //    Console.WriteLine((rc++).ToString() + ": " + System.Text.Encoding.ASCII.GetString(BigIntToBytes(ubound / BigInteger.Pow(2, rc))));
            //    Console.WriteLine(System.Text.Encoding.ASCII.GetString(BigIntToBytes(multiplier * n / BigInteger.Pow(2, rc))));
            //    if (rc > 2040) { Console.WriteLine(HexEncode(BigIntToBytes(ubound / BigInteger.Pow(2, rc)))); Console.WriteLine(HexEncode(BigIntToBytes(lbound / BigInteger.Pow(2, rc)))); }
            //}
            Console.WriteLine(ubound == m);
            Console.WriteLine(HexEncode(BigIntToBytes(m)));

            //SET 6 CHALLENGE 47
            do
            {
                do
                {
                    _p = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_p, 64));
                do
                {
                    _q = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_q, 64));
            } while (modInverse(3, et = (_p - 1) * (_q - 1)) == 1); //the totient must be coprime to our fixed e=3
            n = _p * _q;
            d = modInverse(3, et);

            b = System.Text.Encoding.ASCII.GetBytes("kick it, CC");
            byte[] pad = new byte[GetBitSize(n) / 8 - b.Length - 1 - 2];
            rng.GetBytes(pad);
            c = BigInteger.ModPow(BytesToBigInt(new byte[] { 0, 2 }.Concat(pad).Concat(new byte[] { 0 }).Concat(b).ToArray()), 3, n);
            BigInteger result = BleichenBacherPaddingOracle(rng, n, 3, d, c);
            Console.WriteLine("Result: " + HexEncode(BigIntToBytes(result)) + " matches: " + (result == BigInteger.ModPow(c, d, n)));

            //SET 6 CHALLENGE 48
            do
            {
                do
                {
                    _p = GetPivotRandom(rng, 384);
                } while (!IsProbablePrime(_p, 192));
                do
                {
                    _q = GetPivotRandom(rng, 384);
                } while (!IsProbablePrime(_q, 192));
            } while (modInverse(3, et = (_p - 1) * (_q - 1)) == 1); //the totient must be coprime to our fixed e=3
            n = _p * _q;
            d = modInverse(3, et);

            pad = new byte[GetBitSize(n) / 8 - b.Length - 1 - 2];
            rng.GetBytes(pad);
            c = BigInteger.ModPow(BytesToBigInt(new byte[] { 0, 2 }.Concat(pad).Concat(new byte[] { 0 }).Concat(b).ToArray()), 3, n);
            result = BleichenBacherPaddingOracle(rng, n, 3, d, c);
            Console.WriteLine("Result: " + HexEncode(BigIntToBytes(result)) + " matches: " + (result == BigInteger.ModPow(c, d, n)));
        }
        public class Rc4
        {
            private const int N = 256;
            private byte[] _sbox;
            private readonly byte[] _seedKey;
            private byte[] _text;
            private int _i, _j;
            public Rc4(byte[] seedKey, byte[] text)
            {
                _seedKey = seedKey;
                _text = text;
            }
            public Rc4(byte[] seedKey)
            {
                _seedKey = seedKey;
            }
            public byte[] Text {
                get {
                    return _text;
                }
                set {
                    _text = value;
                }
            }
            public byte[] EnDeCrypt()
            {
                Rc4Initialize();
                byte[] cipher = new byte[_text.Length];
                for (int i = 0; i < _text.Length; i++) {
                    cipher[i] = (byte)(_text[i] ^ GetNextKeyByte());
                }
                return cipher;
            }
            public byte GetNextKeyByte()
            {
                _i = (_i + 1) & (N - 1);
                _j = (_j + _sbox[_i]) & (N - 1);
                byte tempSwap = _sbox[_i];
                _sbox[_i] = _sbox[_j];
                _sbox[_j] = tempSwap;
                return _sbox[(_sbox[_i] + _sbox[_j]) & (N - 1)];
            }
            public void Rc4Initialize()
            {
                Initialize();
            }
            public void Rc4Initialize(int drop)
            {
                Initialize();
                for (int i = 0; i < drop; i++) {
                    GetNextKeyByte();
                }
            }
            private void Initialize()
            {
                _i = 0;
                _j = 0;
                _sbox = new byte[N];
                for (int a = 0; a < N; a++) {
                    _sbox[a] = (byte)a;
                }
                int b = 0;
                for (int a = 0; a < N; a++) {
                    b = (b + _sbox[a] + _seedKey[a % _seedKey.Length]) & (N - 1);
                    byte tempSwap = _sbox[a];
                    _sbox[a] = _sbox[b];
                    _sbox[b] = tempSwap;
                }
            }
        }
        static int CompressionLengthOracle(string str, bool bCBC)
        {
            byte[] iv = new byte[16];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] key = new byte[16];
            System.IO.MemoryStream output = new System.IO.MemoryStream();
            System.IO.Compression.DeflateStream defstream = new System.IO.Compression.DeflateStream(output, System.IO.Compression.CompressionMode.Compress, true);
            byte[] b = System.Text.Encoding.ASCII.GetBytes("POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\nContent-Length: " + str.Length + "\n" + str);
            defstream.Write(b, 0, b.Length);
            defstream.Flush();
            defstream.Close();
            byte[] o = new byte[4096];
            int nread;
            output.Seek(0, System.IO.SeekOrigin.Begin);
            do {
                nread = output.Read(o, o.Length - 4096, 4096);
                Array.Resize(ref o, o.Length - 4096 + nread);
            } while (nread == 4096);
            output.Close();
            rng.GetBytes(key);
            rng.GetBytes(iv);
            if (bCBC) {
                return encrypt_cbc(iv, key, PKCS7Pad(o, 16)).Length;
            } else {
                //with RC4 the IV equivalent is to prepend it as the first 16 bytes of the stream
                Rc4 rc4 = new Rc4(key, iv.Concat(o).ToArray());
                return rc4.EnDeCrypt().Length;
            }
        }
        static byte[] PrehMD(byte[] m, int bitsize, byte[] h)
        {
            if (m.Length % 16 != 0) m = m.Concat(Enumerable.Repeat((byte)0, 16 - m.Length % 16)).ToArray();
            for (int i = 0; i < (m.Length + 15) / 16; i++)
            {
                h = encrypt_ecb(h.Concat(Enumerable.Repeat((byte)0, 16 - h.Length)).ToArray(), m.Skip(i * 16).Take(16).ToArray()).Take((bitsize + 7) / 8).ToArray();
                if ((bitsize % 8) != 0) h[h.Length - 1] = (byte)(h[h.Length - 1] & ((1 << (bitsize % 8)) - 1));
            }
            return h;
        }
        static byte[] MD(byte[] m, int bitsize)
        {
            return PrehMD(m, bitsize, Enumerable.Repeat((byte)0, (bitsize + 7) / 8).ToArray());
        }
        static byte[][] fcollision(int n)
        {
            List<byte[]> cols = new List<byte[]> { new byte[] { } };
            if (n == 0) return cols.ToArray();
            BigInteger i;
            do {
                Dictionary<byte[], BigInteger> map = new Dictionary<byte[], BigInteger>(new ByteArrayComparer());
                byte[] newh;
                byte[] inith = MD(cols[0], 16);
                for (i = 0; true; i++) {
                    newh = PrehMD(i == 0 ? new byte[] { 0 } : BigIntToBytes(i).ToArray(), 16, inith);
                    if (map.ContainsKey(newh)) break;
                    map.Add(newh, i);
                }
                cols = cols.Select((b) => b.Concat(map[newh] == 0 ? new byte[] { 0 } : BigIntToBytes(map[newh])).ToArray()).Concat(cols.Select((b) => b.Concat(i == 0 ? new byte[] { 0 } : BigIntToBytes(i)).ToArray())).ToList();
                if (cols.Count == (1 << n)) return cols.ToArray();
                cols = cols.Select((b) => b.Concat(Enumerable.Repeat((byte)0, (b.Length % 16) == 0 ? 0 : 16 - (b.Length % 16))).ToArray()).ToList();
            } while (true);
        }
        static byte[][][] kcollisions(int k)
        {
            byte[][][] result = new byte[k][][];
            byte[] inith = new byte[] { 0 };
            while (k > 0) {
                byte[] prefix = Enumerable.Repeat((byte)0, 16 * (1 << (k - 1))).ToArray();
                BigInteger i;
                Dictionary<byte[], BigInteger> map = new Dictionary<byte[], BigInteger>(new ByteArrayComparer());
                byte[] newh;
                for (i = 0; map.Count < 1 << 8; i++) {
                    newh = PrehMD(i == 0 ? new byte[] { 0 } : BigIntToBytes(i).ToArray(), 16, inith);
                    if (map.ContainsKey(newh)) continue;
                    map.Add(newh, i); //2^8 is going to be a good birthday attack collider
                }
                inith = PrehMD(prefix, 16, inith);
                for (i = 0; true; i++) {
                    newh = PrehMD(i == 0 ? new byte[] { 0 } : BigIntToBytes(i).ToArray(), 16, inith);
                    if (map.ContainsKey(newh)) break;
                }
                result[k - 1] = new byte[][] { map[newh] == 0 ? new byte[] { 0 } : BigIntToBytes(map[newh]), prefix.Concat(i == 0 ? new byte[] { 0 } : BigIntToBytes(i)).ToArray() };
                inith = newh;
                k--;
            }
            return result;
        }
        public class MyTree<K, V> : Dictionary<K, MyTree<K, V>>
        {
            public V Value { get; set; }
        }
        static byte[][] ktreecollisions(int k)
        {
            //could use a BinaryTree and node class per https://msdn.microsoft.com/en-us/library/aa289150(v=vs.71).aspx
            //but why not use a list with ... + 8 + 4 + 2 + 1 format for items and proper indexing
            //first is initial hash states, followed by collision messages followed by the last hash
            byte[][] result = new byte[(1 << (k + 1)) + (1 << k)][];
            byte[][] hashlist = new byte[1 << k][];
            for (int i = 0; i < (1 << k); i++) {
                result[i] = BigIntToBytes(i).Concat(new byte[] { 0, 0 }).Take(2).ToArray();
                hashlist[i] = result[i];
            }
            int b = 1 << k;
            k--;
            while (k >= 0) {
                byte[][] nextlist = new byte[1 << k][];
                for (int i = 0; i < (1 << k); i++) {
                    Dictionary<byte[], BigInteger> map = new Dictionary<byte[], BigInteger>(new ByteArrayComparer()); //set up a birthday collider
                    byte[] newh;
                    for (BigInteger c = 0; map.Count < 1 << 8; c++) {
                        newh = PrehMD(c == 0 ? new byte[] { 0 } : BigIntToBytes(c), 16, hashlist[(i << 1)]);
                        if (map.ContainsKey(newh)) continue;
                        map.Add(newh, c);
                    }
                    for (BigInteger c = 0; true; c++) {
                        if (map.ContainsKey(newh = PrehMD(c == 0 ? new byte[] { 0 } : BigIntToBytes(c), 16, hashlist[(i << 1) + 1]))) {
                            result[b + (i << 1)] = (map[newh] == 0 ? new byte[] { 0 } : BigIntToBytes(map[newh]));
                            result[b + (i << 1) + 1] = (c == 0 ? new byte[] { 0 } : BigIntToBytes(c));
                            nextlist[i] = newh;
                            if (k == 0) result[result.Length - 1] = newh;
                            break;
                        }
                    }
                }
                b += (1 << (k + 1));
                k--;
                hashlist = nextlist;
            }
            return result;
        }
        static void Set7()
        {
            //SET 7 CHALLENGE 49
            //proof regarding CBC-MAC's randomness and its length extension vulnerability
            //http://isis.poly.edu/courses/cs6903-s09/Lectures/lecture9.pdf
            byte[] iv = new byte[16];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] key = new byte[16];
            rng.GetBytes(iv);
            rng.GetBytes(key);
            byte[] message = PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("from=" + 1.ToString() + "&to=" + 2.ToString() + "&amount=1"), 16);
            byte[] cbcmac = encrypt_cbc(iv, key, message).Skip(16 * ((message.Length - 1) / 16)).ToArray();
            byte[] request = message.Concat(iv).Concat(cbcmac).ToArray();
            //only the from account number matters from this message since the rest we can forge by getting valid message and changing its IV and first block
            rng.GetBytes(iv);
            string str = System.Text.Encoding.ASCII.GetString(request.Take(request.Length - 32).ToArray());
            byte[] attackmessage = PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("from=" + 3.ToString() + "&to=" + 3.ToString() + "&amount=1000000"), 16);
            cbcmac = encrypt_cbc(iv, key, attackmessage).Skip(16 * ((attackmessage.Length - 1) / 16)).ToArray();
            byte[] newattackmessage;
            newattackmessage = PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("from=" + str.Substring(str.IndexOf("from=") + 5, str.IndexOf("&", str.IndexOf("from=")) - str.IndexOf("from=") - 5) + "&to=" + 3.ToString() + "&amount=1000000"), 16);
            byte[] attackiv = FixedXOR(iv, FixedXOR(attackmessage.Take(16).ToArray(), newattackmessage.Take(16).ToArray()));
            newattackmessage = newattackmessage.Concat(attackiv).Concat(cbcmac).ToArray();
            Console.WriteLine("7.49 Forged message with new IV is equal to original MAC: " + (new ByteArrayComparer().Equals(encrypt_cbc(attackiv, key, newattackmessage.Take(newattackmessage.Length - 32).ToArray()).Skip(16 * ((newattackmessage.Take(newattackmessage.Length - 32).ToArray().Length - 1) / 16)).ToArray(), cbcmac)));

            iv = Enumerable.Repeat((byte)0, 16).ToArray();
            message = PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("from=" + 1.ToString() + "&tx_list=" + 2.ToString() + ":1"), 16);
            cbcmac = encrypt_cbc(iv, key, message).Skip(16 * ((message.Length - 1) / 16)).ToArray();
            request = message.Concat(cbcmac).ToArray();

            str = System.Text.Encoding.ASCII.GetString(request.Take(request.Length - 32).ToArray());
            attackmessage = PKCS7Pad(System.Text.Encoding.ASCII.GetBytes(";" + 3.ToString() + ":1000000"), 16);
            cbcmac = encrypt_cbc(cbcmac, key, attackmessage).Skip(16 * ((attackmessage.Length - 1) / 16)).ToArray();
            newattackmessage = message.Concat(attackmessage).Concat(cbcmac).ToArray();
            Console.WriteLine("Length extension appended MAC correct: " + (new ByteArrayComparer().Equals(encrypt_cbc(iv, key, newattackmessage.Take(newattackmessage.Length - 16).ToArray()).Skip(16 * ((newattackmessage.Take(newattackmessage.Length - 16).ToArray().Length - 1) / 16)).ToArray(), cbcmac)));

            //SET 7 CHALLENGE 50
            key = System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            //16 encrypted bytes before the cbcmac xored with the plaintext are the ones needed to correctly forge this
            cbcmac = encrypt_cbc(iv, key, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("alert('MZA who was that?');\n"), 16)).Skip(16 * (("alert('MZA who was that?');\n".Length - 1) / 16)).Take(16).ToArray();
            Console.WriteLine("7.50 Verify CBC-MAC expected value: " + (new ByteArrayComparer().Equals(cbcmac, HexDecode("296b8d7cb78a243dda4d0a61d33bbdd1"))));
            cbcmac = encrypt_cbc(iv, key, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("alert('MZA who was that?');\n"), 16)).Skip(16 * (("alert('MZA who was that?');\n".Length - 1) / 16) - 16).Take(16).ToArray();
            str = "alert('Ayo, the Wu is back!');//                ";
            //     0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF;
            //binary 0 and new line should be only characters we need to watch out for if we use a comment structure
            //one approach is to do length extension and append original message but commented out - not general for multiline so could also return or play other javascript abort game
            //yet better since we have key and hence decryption oracle access, other approach is to decrypt the padding xored with desired output
            //the spirit of this exercise is to show that hash functions are one way and symmetric encryption is not
            attackmessage = System.Text.Encoding.ASCII.GetBytes(str).Concat(FixedXOR(encrypt_cbc(iv, key, System.Text.Encoding.ASCII.GetBytes(str)).Skip(16 * ((str.Length - 1) / 16)).ToArray(), decrypt_cbc(iv, key, FixedXOR(Enumerable.Repeat((byte)16, 16).ToArray(), FixedXOR(cbcmac, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("alert('MZA who was that?');\n"), 16).Skip(16 * (("alert('MZA who was that?');\n".Length - 1) / 16)).Take(16).ToArray()))))).ToArray();
            Console.WriteLine("Forged javascript: \"" + System.Text.Encoding.ASCII.GetString(attackmessage) + "\" same CBC-MAC: " + new ByteArrayComparer().Equals(encrypt_cbc(iv, key, PKCS7Pad(attackmessage, 16)).Skip(16 * ((PKCS7Pad(attackmessage, 16).Length - 1) / 16)).ToArray(), HexDecode("296b8d7cb78a243dda4d0a61d33bbdd1")));
            //Extra Credit: Write JavaScript code that downloads your file, checks its CBC-MAC, and inserts it into the DOM iff it matches the expected hash.

            //SET 7 CHALLENGE 51
            List<string> Candidates = new List<String>(); //queue
            //base 64 character set
            Candidates.Add("sessionid=");
            int baselen = CompressionLengthOracle(Candidates[0], false);
            string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            do {
                for (int i = 0; i < charset.Length; i++) {
                    //it will eventually grow up to one byte reasonably with a short session key and though could get more sophisticated with when that happens, no need in this case
                    if (CompressionLengthOracle(Candidates[0] + charset[i], false) <= baselen + 1) {
                        Candidates.Add(Candidates[0] + charset[i]);
                    }
                    //could consider equal sign positions for extra efficiency as they are only at the end
                    //if % 3 = 1 consider '='
                    //if % 3 = 2 && [-1] == '=' consider '='
                }
                if (Candidates.Count == 1) break;
                Candidates.RemoveAt(0);
            } while (true);
            Console.WriteLine("7.51 Recovered plaintext from compression oracle: " + Candidates[0] + " " + System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(Candidates[0].Remove(0, "sessionid=".Length))));
            Candidates[0] = "sessionid=";
            //only 2 changes needed to deal with the padding of CBC: first prefix the prefix to the block border length
            //second must delete one prefix character when match occurs and then try all 2 byte combinations to determine if its a continuation or termination case
            //perhaps can use some heuristical knowledge of base-64 or the length of the shared key to avoid the 2^16 search as eveywhere else its 2^8
            baselen = CompressionLengthOracle(Candidates[0], true);
            int rnd;
            while (baselen == CompressionLengthOracle(charset[rnd = GetNextRandom(rng, charset.Length - 1)] + Candidates[0], true)) { Candidates[0] = charset[rnd] + Candidates[0]; }
            do {
                for (int i = 0; i < charset.Length; i++) {
                    //it will eventually grow up to one byte reasonably with a short session key and though could get more sophisticated with when that happens, no need in this case
                    if (CompressionLengthOracle(Candidates[0] + charset[i], true) <= baselen + 1) {
                        Candidates.Add(Candidates[0] + charset[i]);
                    }
                    //could consider equal sign positions for extra efficiency as they are only at the end
                    //if % 3 = 1 consider '='
                    //if % 3 = 2 && [-1] == '=' consider '='
                }
                if (Candidates.Count == 1) {
                    Candidates[0] = Candidates[0].Remove(0, 1);
                    for (int i = 0; i < charset.Length; i++) {
                        for (int j = 0; j < charset.Length; j++) {
                            if (j == i && j == charset.Length - 1) break; if (j == i) j++;
                            if (CompressionLengthOracle(Candidates[0] + charset[i] + charset[j], true) <= baselen + 1) {
                                Candidates.Add(Candidates[0] + charset[i] + charset[j]);
                            }
                        }
                    }
                    if (Candidates.Count == 1) break;
                }
                Candidates.RemoveAt(0);
            } while (true);
            Console.WriteLine("Recovered plaintext from compression oracle with padding: " + Candidates[0] + " " + System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(Candidates[0].Substring(Candidates[0].IndexOf("sessionid=") + "sessionid=".Length))));

            //SET 7 CHALLENGE 52
            byte[][] cols = fcollision(6); //2^6=64 collisions
            int c;
            byte[] h = MD(cols[0], 16);
            for (c = 1; c < cols.Length; c++) {
                if (!(new ByteArrayComparer().Equals(h, MD(cols[c], 16)))) break;
            }
            Console.WriteLine("7.52 Number of collisions generated: " + cols.Length.ToString() + " all verified: " + (c == cols.Length));
            int n;
            Dictionary<byte[], int> map;
            h = MD(new byte[] { 0, 0 }, 20);
            //50% chance after 2^10 but it could theoretically go to any length even past 2^20 depending on how evenly distributed the hash function is...since AES is good, unlikely concern
            for (n = 10; true; n++) {
                cols = fcollision(n);
                h = cols[0];
                map = new Dictionary<byte[], int>(new ByteArrayComparer());
                for (c = 0; c < cols.Length; c++) {
                    byte[] newh = MD(cols[c], 20);
                    if (map.ContainsKey(newh)) {
                        Console.WriteLine("Colliding values and their f||g hash output: " + HexEncode(cols[c]) + ": " + HexEncode(MD(cols[c], 16)) + HexEncode(newh) + " " + HexEncode(cols[map[newh]]) + ": " + HexEncode(MD(cols[map[newh]], 16)) + HexEncode(newh));
                        break;
                    } else {
                        map.Add(newh, c);
                    }
                }
                if (c != cols.Length) break;
            }
            Console.WriteLine("Number of collisions in f to find collision in g as a power of 2: " + n);

            //SET 7 CHALLENGE 53
            byte[] kblock = new byte[16 * 8]; //any message length between k and k+2^k-1 is possible...e.g. 2-5, 3-10, 4-19, 5-36
            rng.GetBytes(kblock);
            byte[][][] expmsg = kcollisions(3); //find k s.t.: k << 3 > ((kblock.Length + 15) / 16)
            map = new Dictionary<byte[], int>(new ByteArrayComparer());
            for (int i = 0; i < kblock.Length / 16; i++) {
                byte[] newh = MD(kblock.Take(i * 16).ToArray(), 16);
                if (map.ContainsKey(newh)) map[newh] = i; //use last index on this rare coincidence to make this deterministic
                else map.Add(newh, i);
            }
            BigInteger bridge;
            byte[] inith = MD(expmsg.Reverse().SelectMany((b) => b[0].Concat(Enumerable.Repeat((byte)0, 16)).Take(16).ToArray()).ToArray(), 16);
            int blocknum;
            for (bridge = 0; true; bridge++) {
                if (map.ContainsKey(PrehMD(bridge == 0 ? new byte[] { 0 } : BigIntToBytes(bridge).ToArray(), 16, inith))) {
                    blocknum = map[PrehMD(bridge == 0 ? new byte[] { 0 } : BigIntToBytes(bridge).ToArray(), 16, inith)];
                    if (blocknum > expmsg.Length) break;
                }
            }
            //already have 1, so 2+4+8+...
            byte[] forgery = new byte[kblock.Length];
            for (int i = expmsg.Length - 1; i >= 0; i--) {
                Array.Copy(expmsg[i][((blocknum - 1 - expmsg.Length) & (1 << i)) != 0 ? 1 : 0].Concat(Enumerable.Repeat((byte)0, 16)).Take((((blocknum - 1 - expmsg.Length) & (1 << i)) != 0 ? (1 << i) : 0) * 16 + 16).ToArray(), 0, forgery, (((blocknum - 1 - expmsg.Length) & ((1 << expmsg.Length) - (1 << (i + 1)))) + (expmsg.Length - 1 - i)) * 16, (((blocknum - 1 - expmsg.Length) & (1 << i)) != 0 ? (1 << i) : 0) * 16 + 16);
            }
            Array.Copy(BigIntToBytes(bridge).Concat(Enumerable.Repeat((byte)0, 16)).Take(16).ToArray(), 0, forgery, (blocknum - 1) * 16, 16);
            Array.Copy(kblock, blocknum * 16, forgery, blocknum * 16, kblock.Length - blocknum * 16);
            Console.WriteLine("Forgery hash is identical: " + (new ByteArrayComparer().Equals(MD(kblock, 16), MD(forgery, 16))));

            //SET 7 CHALLENGE 54
            cols = ktreecollisions(8);
            str = String.Empty;
            for (int i = 0; i < 2430; i++) { //simple formula as a substitute for the actual results
                str += i.ToString() + ": " + (i % 9) + "-" + ((i + 1) % 9) + "\n";
            }
            forgery = System.Text.Encoding.ASCII.GetBytes(str);
            if ((forgery.Length % 16) != 0) forgery = forgery.Concat(Enumerable.Repeat((byte)0, 16 - (forgery.Length % 16))).ToArray();
            inith = MD(forgery, 16);
            map.Clear();
            for (int i = 0; i < (1 << 8); i++) {
                map[cols[i]] = i;
            }
            for (bridge = 0; true; bridge++) {
                if (map.ContainsKey(PrehMD(bridge == 0 ? new byte[] { 0 } : BigIntToBytes(bridge).ToArray(), 16, inith))) break;
            }
            forgery = forgery.Concat(bridge == 0 ? new byte[] { 0 } : BigIntToBytes(bridge)).ToArray();
            if ((forgery.Length % 16) != 0) forgery = forgery.Concat(Enumerable.Repeat((byte)0, 16 - (forgery.Length % 16))).ToArray();
            blocknum = (1 << 8);
            c = map[PrehMD(bridge == 0 ? new byte[] { 0 } : BigIntToBytes(bridge).ToArray(), 16, inith)];
            for (int i = 7; i >= 0; i--) {
                forgery = forgery.Concat(cols[blocknum + c]).ToArray();
                if ((forgery.Length % 16) != 0) forgery = forgery.Concat(Enumerable.Repeat((byte)0, 16 - (forgery.Length % 16))).ToArray();
                blocknum += (1 << (i + 1));
                c >>= 1;
            }
            Console.WriteLine("Forged prediction hash is identical to prior prediction hash: " + (new ByteArrayComparer().Equals(cols[cols.Length - 1], MD(forgery, 16))));

            //SET 7 CHALLENGE 55
            uint[] m1 = { 0x4d7a9c83, 0x56cb927a, 0xb9d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f, 0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8, 0x45dd8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9 };
            uint[] m1prime = { 0x4d7a9c83, 0xd6cb927a, 0x29d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f, 0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8, 0x45dc8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9 };
            uint[] m2 = { 0x4d7a9c83, 0x56cb927a, 0xb9d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f, 0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8, 0x45dd8e31, 0x97e31fe5, 0xf713c240, 0xa7b8cf69 };
            uint[] m2prime = { 0x4d7a9c83, 0xd6cb927a, 0x29d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f, 0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8, 0x45dc8e31, 0x97e31fe5, 0xf713c240, 0xa7b8cf69 };
            MD4 md4 = new MD4();
            forgery = MD4.WangsAttack(m1.SelectMany((d) => BitConverter.GetBytes(d)).ToArray(), false, false);
            Console.WriteLine("7.55 Verify paper hash meets first round conditions: " + (new ByteArrayComparer().Equals(forgery, m1.SelectMany((d) => BitConverter.GetBytes(d)).ToArray())));
            Console.WriteLine("Verify paper differential: " + (new ByteArrayComparer().Equals(MD4.ApplyWangDifferential(m1.SelectMany((d) => BitConverter.GetBytes(d)).ToArray()), m1prime.SelectMany((d) => BitConverter.GetBytes(d)).ToArray())));
            forgery = MD4.WangsAttack(m2.SelectMany((d) => BitConverter.GetBytes(d)).ToArray(), false, false);
            Console.WriteLine("Verify second paper hash meets first round conditions: " + (new ByteArrayComparer().Equals(forgery, m2.SelectMany((d) => BitConverter.GetBytes(d)).ToArray())));
            Console.WriteLine("Verify second paper differential: " + (new ByteArrayComparer().Equals(MD4.ApplyWangDifferential(m2.SelectMany((d) => BitConverter.GetBytes(d)).ToArray()), m2prime.SelectMany((d) => BitConverter.GetBytes(d)).ToArray())));
            //HexDecode("4d7e6a1defa93d2dde05b45d864c429b");
            Console.WriteLine("Hash of paper message: " + HexEncode(md4.ComputeHash(m1.SelectMany((d) => BitConverter.GetBytes(d)).ToArray())));
            Console.WriteLine("Hash of paper differential message: " + HexEncode(md4.ComputeHash(m1prime.SelectMany((d) => BitConverter.GetBytes(d)).ToArray())));
            //HexDecode("c6f3b3fe1f4833e0697340fb214fb9ea");
            Console.WriteLine("Hash of second paper message: " + HexEncode(md4.ComputeHash(m2.SelectMany((d) => BitConverter.GetBytes(d)).ToArray())));
            Console.WriteLine("Hash of second paper differential message: " + HexEncode(md4.ComputeHash(m2prime.SelectMany((d) => BitConverter.GetBytes(d)).ToArray())));
            key = new byte[64];
            n = 0;
            //byte[] twowords = new byte[8];
            for (int i = 0; i < 20; i++)
            {
                do
                {
                    n++;
                    //rng.GetBytes(twowords);
                    //key = MD4.WangsAttack(key.Take(56).Concat(twowords).ToArray(), false);
                    rng.GetBytes(key);
                    key = MD4.WangsAttack(key, true, true);
                    //if (!(new ByteArrayComparer().Equals(key, MD4.WangsAttack(key, true, true)))) { }
                    forgery = MD4.ApplyWangDifferential(key);
                } while (new ByteArrayComparer().Equals(forgery, key) || !(new ByteArrayComparer().Equals(md4.ComputeHash(key), md4.ComputeHash(forgery))));
                Console.WriteLine("Naito et al. improvement: " + n + " tries: " + HexEncode(key) + " " + HexEncode(forgery) + " -> " + HexEncode(md4.ComputeHash(key)));
            }
            n = 0;
            //byte[] twowords = new byte[8];
            for (int i = 0; i < 20; i++)
            {
                do
                {
                    n++;
                    //rng.GetBytes(twowords);
                    //key = MD4.WangsAttack(key.Take(56).Concat(twowords).ToArray(), false);
                    rng.GetBytes(key);
                    key = MD4.WangsAttack(key, true, false);
                    //if (!(new ByteArrayComparer().Equals(key, MD4.WangsAttack(key, true, false)))) {}
                    forgery = MD4.ApplyWangDifferential(key);
                } while (new ByteArrayComparer().Equals(forgery, key) || !(new ByteArrayComparer().Equals(md4.ComputeHash(key), md4.ComputeHash(forgery))));
                Console.WriteLine("Wang et al. paper attack: " + n + " tries: " + HexEncode(key) + " " + HexEncode(forgery) + " -> " + HexEncode(md4.ComputeHash(key)));
            }

            //SET 7 CHALLENGE 56
            forgery = Convert.FromBase64String("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F");
            //position 16, 240 at .00395 chance, .00390625 average, biases at 0 and 16 at half weight
            //position 32, 224 at .00395 chance, .00390625 average, biases at 0 and 32 at half weight
            //1.12% more frequent
            byte[] recover = new byte[forgery.Length];
            for (int len = 0; len < 16; len++)
            {
                int[] hist = new int[256];
                int[] hist2 = new int[256];
                int max = 0; //takes a very large number of rounds to correctly get the histogram distributions amplified 2^24 minimum and 2^25 is better
                int max2 = 0;
                //new byte[] { (byte)'/' }.Concat()
                byte[] b = Enumerable.Repeat((byte)'A', Math.Max(0, 15 - len)).Concat(forgery).ToArray();
                for (int i = 0; i < 1 << 25; i++) {
                    rng.GetBytes(key);
                    Rc4 rc4 = new Rc4(key, b);
                    byte[] peep = rc4.EnDeCrypt();
                    byte ch = peep[15];
                    hist[ch ^ 240] += 4;
                    hist[ch ^ 0]++;
                    hist[ch ^ 16]++;
                    max = hist[max] > hist[ch ^ 240] ? max : (ch ^ 240);
                    max = hist[max] > hist[ch ^ 0] ? max : (ch ^ 0);
                    max = hist[max] > hist[ch ^ 16] ? max : (ch ^ 16);
                    if (15 - len + forgery.Length >= 32) {
                        ch = peep[31];
                        hist2[ch ^ 224] += 4;
                        hist2[ch ^ 0]++;
                        hist2[ch ^ 32]++;
                        max2 = hist2[max2] > hist2[ch ^ 224] ? max2 : (ch ^ 224);
                        max2 = hist2[max2] > hist2[ch ^ 0] ? max2 : (ch ^ 0);
                        max2 = hist2[max2] > hist2[ch ^ 32] ? max2 : (ch ^ 32);
                    }
                }
                recover[len] = (byte)max;
                if (15 - len + forgery.Length >= 32) recover[len + 16] = (byte)max2;
            }
            Console.WriteLine("7.56 Recovered RC4 statistical decryption: " + System.Text.Encoding.ASCII.GetString(recover));
            Console.WriteLine("Equal to original: " + (new ByteArrayComparer().Equals(recover, forgery)));
        }
        static BigInteger PollardKangaroo(BigInteger a, BigInteger b, int k, BigInteger g, BigInteger p, BigInteger y)
        {
            BigInteger xT = BigInteger.Zero;
            BigInteger yT = BigInteger.ModPow(g, b, p);
            //N is then derived from f -take the mean of all possible outputs of f and multiply it by a small constant, e.g. 4.
            int N = ((1 << (k + 1)) - 1) * 4 / k;
            //make the constant bigger to better your chances of finding a collision at the(obvious) cost of extra computation.
            for (int i = 1; i <= N; i++)
            {
                BigInteger KF = BigInteger.Remainder(KangF(yT, k), p);
                xT = xT + KF;
                yT = BigInteger.Remainder(yT * BigInteger.ModPow(g, KF, p), p);
            }
            //now yT = g^(b + xT)
            //Console.WriteLine("yT = " + HexEncode(yT.ToByteArray()) + " g^(b + xT) = " + HexEncode(BigInteger.ModPow(g, b + xT, p).ToByteArray()));
            BigInteger xW = BigInteger.Zero;
            BigInteger yW = y;
            while (xW < (b - a + xT))
            {
                BigInteger KF = BigInteger.Remainder(KangF(yW, k), p);
                xW = xW + KF;
                yW = BigInteger.Remainder(yW * BigInteger.ModPow(g, KF, p), p);
                if (yW == yT)
                {
                    return b + xT - xW;
                }
            }
            return BigInteger.Zero;
        }
        static BigInteger PollardKangarooEC(BigInteger a, BigInteger b, int k, Tuple<BigInteger, BigInteger> G, int Ea, BigInteger p, Tuple<BigInteger, BigInteger> y)
        {//modular exponentiation/multiplication is scalar multiplication/group addition on the elliptical curve
            BigInteger xT = BigInteger.Zero;
            Tuple<BigInteger, BigInteger> yT = scaleEC(G, b, Ea, p);
            //N is then derived from f -take the mean of all possible outputs of f and multiply it by a small constant, e.g. 4.
            ulong N = (((ulong)1 << (k + 1)) - 1) * 4 / (ulong)k;
            //make the constant bigger to better your chances of finding a collision at the(obvious) cost of extra computation.
            for (ulong i = 1; i <= N; i++) {
                BigInteger KF = BigInteger.Remainder(KangF(yT.Item1, k), p);
                xT = xT + KF;
                yT = addEC(yT, scaleEC(G, KF, Ea, p), Ea, p);
            }
            //now yT = g^(b + xT)
            //Console.WriteLine("yT = " + HexEncode(yT.ToByteArray()) + " g^(b + xT) = " + HexEncode(BigInteger.ModPow(g, b + xT, p).ToByteArray()));
            BigInteger xW = BigInteger.Zero;
            Tuple<BigInteger, BigInteger> yW = y;
            BigInteger upperBound = (b - a + xT);
            while (xW < upperBound) {
                BigInteger KF = BigInteger.Remainder(KangF(yW.Item1, k), p);
                xW = xW + KF;
                yW = addEC(yW, scaleEC(G, KF, Ea, p), Ea, p);
                if (yW.Item1 == yT.Item1 && yW.Item2 == yT.Item2) {
                    return b + xT - xW;
                }
            }
            return BigInteger.Zero;
        }
        //Montgomery gives in his paper "Speeding the Pollard and Elliptic Curve Methods of Factorization" from 1987 the formula on page 19:
        //x3=((y1-y2)/(x1-x2))^2-A-x1-x2, x coordinate point addition
        //Affine addition/doubling formulae: http://hyperelliptic.org/EFD/g1p/auto-montgom.html
        static BigInteger PollardKangarooECmontg(BigInteger a, BigInteger b, int k, Tuple<BigInteger, BigInteger> G, int EaOrig, int Ea, int Eb, BigInteger p, Tuple<BigInteger, BigInteger> y, int conv)
        {//modular exponentiation/multiplication is scalar multiplication/group addition on the elliptical curve
            BigInteger xT = BigInteger.Zero;
            Tuple<BigInteger, BigInteger> yT = montgToWS(ladder2(G, b, Ea, EaOrig, Eb, p, conv), conv);
            //N is then derived from f -take the mean of all possible outputs of f and multiply it by a small constant, e.g. 4.
            ulong N = (((ulong)1 << (k + 1)) - 1) * 4 / (ulong)k;
            //if (N > ((ulong)1 << 24)) N /= 8;
            //make the constant bigger to better your chances of finding a collision at the(obvious) cost of extra computation.
            for (ulong i = 1; i <= N; i++)
            {
                BigInteger KF = BigInteger.Remainder(KangF(yT.Item1, k), p);
                xT = xT + KF;
                yT = addEC(yT, montgToWS(ladder2(G, KF, Ea, EaOrig, Eb, p, conv), conv), EaOrig, p);
            }
            //now yT = g^(b + xT)
            //Console.WriteLine("yT = " + HexEncode(yT.ToByteArray()) + " g^(b + xT) = " + HexEncode(BigInteger.ModPow(g, b + xT, p).ToByteArray()));
            BigInteger xW = BigInteger.Zero;
            Tuple<BigInteger, BigInteger> yW = y;
            BigInteger upperBound = (b - a + xT);
            while (xW < upperBound) {
                BigInteger KF = BigInteger.Remainder(KangF(yW.Item1, k), p);
                xW = xW + KF;
                yW = addEC(yW, montgToWS(ladder2(G, KF, Ea, EaOrig, Eb, p, conv), conv), EaOrig, p);
                if (yW.Item1 == yT.Item1 && yW.Item2 == yT.Item2) {
                    return b + xT - xW;
                }
            }
            return BigInteger.Zero;
        }
        static BigInteger KangF(BigInteger y, int k)
        {
            return BigInteger.One << (int)(BigInteger.Remainder(y, k));
            //return BigInteger.Pow(2, (int)BigInteger.Remainder(y, k));
        }
        static Tuple<BigInteger, BigInteger> invertEC(Tuple<BigInteger, BigInteger> P, BigInteger GF)
        {
            return new Tuple<BigInteger, BigInteger>(P.Item1, GF - P.Item2);
        }
        static Tuple<BigInteger, BigInteger> addEC(Tuple<BigInteger, BigInteger> P1, Tuple<BigInteger, BigInteger> P2, int a, BigInteger GF)
        {
            Tuple<BigInteger, BigInteger> O = new Tuple<BigInteger, BigInteger>(0, 1);
            if (P1.Equals(O)) return P2;
            if (P2.Equals(O)) return P1;
            if (P1.Equals(invertEC(P2, GF))) return new Tuple<BigInteger, BigInteger>(0, 1);
            BigInteger x1 = P1.Item1, y1 = P1.Item2, x2 = P2.Item1, y2 = P2.Item2, m;
            m = (P1.Equals(P2)) ? posRemainder((3 * x1 * x1 + a) * modInverse(2 * y1, GF), GF) : posRemainder((y2 - y1) * modInverse(posRemainder(x2 - x1, GF), GF), GF);
            BigInteger x3 = posRemainder(m * m - x1 - x2, GF);
            return new Tuple<BigInteger, BigInteger>(x3, posRemainder(m * (x1 - x3) - y1, GF));
        }
        static Tuple<BigInteger, BigInteger> scaleEC(Tuple<BigInteger, BigInteger> x, BigInteger k, int a, BigInteger GF)
        {
            Tuple<BigInteger, BigInteger> result = new Tuple<BigInteger, BigInteger>(0, 1);
            while (k > 0) {
                if (!k.IsEven) result = addEC(result, x, a, GF);
                x = addEC(x, x, a, GF);
                k = k >> 1;
            }
            return result;
        }
        static BigInteger TonelliShanks(RNGCryptoServiceProvider rng, BigInteger n, BigInteger p) //inverse modular square root
        {
            //Console.WriteLine(BigInteger.ModPow(n, (p - 1) / 2, p) == 1); //Euler's criterion must equal one or no square root exists
            BigInteger S = 0, Q = p - 1;
            while (Q.IsEven) {
                S += 1; Q /= 2;
            }
            if (S == 1) {
                BigInteger r = BigInteger.ModPow(n, (p + 1) / 4, p);
                return BigInteger.Remainder(r * r, p) == n ? r : 0;
            }
            BigInteger z;
            do { z = Crypto.GetNextRandomBig(rng, p); } while (z <= 1 || BigInteger.ModPow(z, (p - 1) / 2, p) != p - 1); //Euler's criterion for quadratic non-residue (== -1)
            BigInteger M = S, c = BigInteger.ModPow(z, Q, p), t = BigInteger.ModPow(n, Q, p), R = BigInteger.ModPow(n, (Q + 1) / 2, p);
            while (true) {
                if (t == 0) return 0;
                if (t == 1) return R;
                BigInteger i = 0, tt = t;
                if (M == 0) return 0;
                do {
                    i++;
                    tt = BigInteger.Remainder(tt * tt, p);
                } while (i < M && tt != 1);
                if (i == M) return 0; //no solution to the congruence exists
                BigInteger b = BigInteger.ModPow(c, BigInteger.ModPow(2, (int)M - (int)i - 1, p - 1), p);
                M = i; c = BigInteger.Remainder(b * b, p); t = BigInteger.Remainder(t * c, p); R = BigInteger.Remainder(R * b, p);
            }
        }
        static bool isSqrt(BigInteger n, BigInteger root)
        {
            BigInteger lowerBound = root * root;
            return (n >= lowerBound && n <= lowerBound + root + root);
        }
        static BigInteger Sqrt(BigInteger n)
        {
            if (n == 0) return BigInteger.Zero;
            if (n > 0) {
                int bitLength = GetBitSize(n);
                BigInteger root = BigInteger.One << (bitLength / 2);
                while (!isSqrt(n, root)) {
                    root += (n / root);
                    root >>= 1;
                }
                return root;
            }
            throw new ArithmeticException("NaN");
        }
        static bool isPrime(BigInteger n)
        {
            BigInteger mx = Sqrt(n);
            for (BigInteger i = 2; i <= mx; i++) {
                if (BigInteger.Remainder(n, i) == BigInteger.Zero) return false;
            }
            return true;
        }
        static BigInteger nextPrime(BigInteger n)
        {
            if (n == 2) return 3;
            do {
                n += 2;
            } while (!isPrime(n));
            return n;
        }
        static int[] getPrimes(int n) //sieve of Eratosthenes
        {
            bool[] A = new bool[(int)n - 2+1];
            int mx = (int)Sqrt(new BigInteger(n));
            for (int i = 2; i <= mx; i++) {
                if (!A[i - 2]) {
                    for (int j = i * i; j <= n; j += i) {
                        A[j - 2] = true;
                    }
                }
            }
            return A.Select((b, i) => !b ? i + 2 : -1).Where((i) => i != -1).ToArray();
        }
        static BigInteger[] addPolyRing(BigInteger[] a, BigInteger[] b, BigInteger GF)
        {
            int alen = a.Length, blen = b.Length;
            BigInteger[] c = new BigInteger[Math.Max(alen, blen)];
            int clen = c.Length;
            for (int i = 0; i < clen; i++)
            {
                int aoffs = alen - 1 - i, boffs = blen - 1 - i, coffs = clen - 1 - i;
                if (i >= alen) c[coffs] = b[boffs];
                else if (i >= blen) c[coffs] = a[aoffs];
                else c[coffs] = posRemainder(a[aoffs] + b[boffs], GF);
            }
            return clen == 0 || c[0] != BigInteger.Zero ? c : c.Skip(c.TakeWhile((BigInteger cr) => cr == BigInteger.Zero).Count()).ToArray(); ;
        }
        static SortedList<BigInteger, BigInteger> addPolyRingSparse(SortedList<BigInteger, BigInteger> a, SortedList<BigInteger, BigInteger> b, BigInteger GF)
        {
            SortedList<BigInteger, BigInteger> c = new SortedList<BigInteger, BigInteger>();
            SortedSet<BigInteger> idxs = new SortedSet<BigInteger>(a.Keys.ToList().Concat(b.Keys.ToList()));
            foreach (BigInteger i in idxs)
            {
                if (!a.ContainsKey(i)) c[i] = b[i];
                else if (!b.ContainsKey(i)) c[i] = a[i];
                else c[i] = posRemainder(a[i] + b[i], GF);
            }
            return new SortedList<BigInteger, BigInteger>(c.Where((KeyValuePair<BigInteger, BigInteger> kv) => kv.Value != 0).ToDictionary(x => x.Key, x => x.Value));
        }
        static BigInteger modBarrettReduction(BigInteger a, BigInteger n)
        {
            if (a < 0) {
                a = a % n;
                return a < 0 ? a + n : a;
            }
            int k = GetBitSize(a);
            BigInteger m = (BigInteger.One << k) / n;
            BigInteger max_a = ((BigInteger.One << k) * n) / ((BigInteger.One << k) - m * n);
            //m=lowerBound(2^k/n)
            //error = 1/n-m/2^k and in result is a * error must be < 1 or a < 1/error
            //1/n-m/2^k=(2^k-mn)/(2^k*n), 1/error=(2^k*n)/(2^k-mn)
            BigInteger q = (a * m) >> k;
            a -= q * n;
            if (n <= a) a -= n;
            return a;
        }
        static BigInteger modmul(BigInteger a, BigInteger b, BigInteger m)
        {
            //BigInteger res = posRemainder(a * b, m);
            BigInteger d = BigInteger.Zero, mp2 = m >> 1;
            if (a >= m || a < 0) a = posRemainder(a, m);
            if (b >= m || b < 0) b = posRemainder(b, m);
            int bits = GetBitSize(a);
            BigInteger check = BigInteger.One << (bits - 1);
            for (int i = 0; i < bits; i++) {
                d = (d > mp2) ? (d << 1) - m : d << 1;
                if ((a & check) != 0) d += b;
                if (d >= m) d -= m;
                a <<= 1;
            }
            //if (res != d) throw new ArgumentException();
            return d;
        }
        static BigInteger mulKaratsuba(BigInteger num1, BigInteger num2)
        {
            if (num1 <= uint.MaxValue && num2 <= uint.MaxValue) {
                return new BigInteger((System.UInt64)num1 * (System.UInt64)num2);
            }
            if (num1 <= uint.MaxValue || num2 <= uint.MaxValue) return num1 * num2;
            //if (num1 < 2 || num2 < 2) return num1 * num2;
            int m = Math.Min(GetBitSize(num1), GetBitSize(num2));
            int m2 = m >> 1;
            BigInteger m2shift = BigInteger.One << m2;
            BigInteger low1, low2, high1, high2;
            low1 = num1 & (m2shift - 1);
            low2 = num2 & (m2shift - 1);
            high1 = num1 >> m2;
            high2 = num2 >> m2;
            BigInteger z0 = mulKaratsuba(low1, low2);
            BigInteger z1 = mulKaratsuba(low1 + high1, low2 + high2);
            BigInteger z2 = mulKaratsuba(high1, high2);
            return z2 * (BigInteger.One << (m2 << 1)) + (z1 - z2 - z0) * m2shift + z0;
        }
        //Kronecker substitution
        //https://en.wikipedia.org/wiki/Kronecker_substitution
        //https://web.maths.unsw.edu.au/~davidharvey/talks/kronecker-talk.pdf
        static BigInteger[] mulPolyRingKronecker(BigInteger[] A, BigInteger[] B, BigInteger GF)
        {
            int alen = A.Length, blen = B.Length;
            int packSize = (GetBitSize(GF) << 1) + GetBitSize(Math.Max(alen, blen)); //coefficients are bounded by 2^(2*GetBitSize(GF))*n where n is degree+1 of A, B
            //evaluate at 2^(2*GetBitSize(GF)+UpperBound(log2(n)))
            BigInteger Apack = BigInteger.Zero, Bpack = BigInteger.Zero;
            for (int i = 0; i < alen; i++) {
                if (A[i] < 0) Apack += posRemainder(A[i], GF) << ((alen - i - 1) * packSize);
                else Apack |= A[i] << ((alen - i - 1) * packSize);
            }
            for (int i = 0; i < blen; i++) {
                if (B[i] < 0) Bpack += posRemainder(B[i], GF) << ((blen - i - 1) * packSize);
                else Bpack |= B[i] << ((blen - i - 1) * packSize);
            }
            //BigInteger Cpack = Apack * Bpack; //should use Schonhage-Strassen here
            BigInteger Cpack = mulKaratsuba(Apack, Bpack);
            BigInteger[] p = new BigInteger[alen + blen - 1];
            BigInteger packMask = (BigInteger.One << packSize) - 1;
            for (int i = 0; i < alen + blen - 1; i++) {
                p[i] = posRemainder((Cpack >> ((alen + blen - 1 - i - 1) * packSize)) & packMask, GF);
            }
            return p.Skip(p.TakeWhile((BigInteger c) => c == BigInteger.Zero).Count()).ToArray();
        }
        static BigInteger[] mulPolyRing(BigInteger[] A, BigInteger[] B, BigInteger GF)
        {
            int alen = A.Length, blen = B.Length;
            if (alen == 0) return A; if (blen == 0) return B;
            BigInteger[] p = new BigInteger[alen + blen - 1];
            for (int i = 0; i < blen; i++) {
                if (B[i] == BigInteger.Zero) continue;
                for (int j = 0; j < alen; j++) {
                    if (A[j] == BigInteger.Zero) continue;
                    int ijoffs = i + j;
                    //if (posRemainder(A[j] * B[i], GF) != posRemainder(mulKaratsuba(A[j] < 0 ? posRemainder(A[j], GF) : A[j], B[i] < 0 ? posRemainder(B[i], GF) : B[i]), GF)) throw new ArgumentException();
                    //p[ijoffs] += posRemainder(mulKaratsuba(A[j] < 0 ? posRemainder(A[j], GF) : A[j], B[i] < 0 ? posRemainder(B[i], GF) : B[i]), GF);
                    p[ijoffs] += posRemainder(A[j] * B[i], GF);
                    if (p[ijoffs] > GF) p[ijoffs] -= GF;
                }
            }
            //while (!A.All((BigInteger c) => c == BigInteger.Zero)) {
            //    if (A[0] != BigInteger.Zero) p = posRemainder(p + B, GF);
            //    A = A.Skip(1).ToArray(); B = B.Concat(new BigInteger[] { BigInteger.Zero }).ToArray();
            //}
            //if (!mulPolyRingKronecker(A, B, GF).SequenceEqual(p.Skip(p.TakeWhile((BigInteger c) => c == BigInteger.Zero).Count()).Select((x) => posRemainder(x, GF)).ToArray())) {
            //throw new ArgumentException();
            //}
            return p.Length == 0 || p[0] != BigInteger.Zero ? p : p.Skip(p.TakeWhile((BigInteger c) => c == BigInteger.Zero).Count()).ToArray(); //.Select((x) => posRemainder(x, GF)).ToArray();
        }
        static SortedList<BigInteger, BigInteger> mulPolyRingSparse(BigInteger[] A, SortedList<BigInteger, BigInteger> B, BigInteger GF)
        {
            int alen = A.Length;
            if (alen == 0) return new SortedList<BigInteger, BigInteger>(); if (B.Count() == 0) return B;
            SortedList<BigInteger, BigInteger> p = new SortedList<BigInteger, BigInteger>();
            foreach (BigInteger i in B.Keys.Reverse())
            {
                if (B[i] == BigInteger.Zero) continue;
                for (int j = 0; j < alen; j++)
                {
                    if (A[j] == BigInteger.Zero) continue;
                    BigInteger poffs = i + alen - j - 1;
                    if (p.ContainsKey(poffs))
                        p[poffs] = posRemainder(A[j] * B[i] + p[poffs], GF);
                    else
                        p[poffs] = posRemainder(A[j] * B[i], GF);
                }
            }
            return new SortedList<BigInteger, BigInteger>(p.Where((KeyValuePair<BigInteger, BigInteger> kv) => kv.Value != 0).ToDictionary(x => x.Key, x => x.Value));
        }

        //https://en.wikipedia.org/wiki/Polynomial_long_division#Pseudo-code
        static Tuple<BigInteger[], BigInteger[]> divmodPolyRing(BigInteger[] A, BigInteger[] B, BigInteger GF)
        {
            //if (B.Length == 0) throw;
            int alen = A.Length, blen = B.Count();
            BigInteger[] q = new BigInteger[alen], r = A; int d;
            BigInteger binv = modInverse(B[0], GF);
            BigInteger[] bneg = mulPolyRing(B, new BigInteger[] { -1 }, GF);
            int rlen = r.Length;
            while (rlen != 0 && (d = (rlen - 1) - (blen - 1)) >= 0)
            {
                int aoffs = alen - d - 1;
                q[aoffs] = posRemainder(r[0] * binv, GF);
                if (q[aoffs] == BigInteger.Zero) break;
                r = addPolyRing(r, mulPolyRing(bneg, q.Skip(aoffs).ToArray(), GF), GF);
                rlen = r.Length;
            }
            return new Tuple<BigInteger[], BigInteger[]>(q.Skip(q.TakeWhile((BigInteger c) => c == BigInteger.Zero).Count()).ToArray(), r);
        }
        static Tuple<SortedList<BigInteger, BigInteger>, BigInteger[]> divmodPolyRingSparse(SortedList<BigInteger, BigInteger> A, BigInteger[] B, BigInteger GF)
        {
            //if (B.Length == 0) throw;
            int blen = B.Count();
            SortedList<BigInteger, BigInteger> q = new SortedList<BigInteger, BigInteger>(), r = A; BigInteger d;
            BigInteger binv = modInverse(B[0], GF);
            BigInteger[] bneg = mulPolyRing(B, new BigInteger[] { -1 }, GF);
            while (r.Count() != 0 && (d = (r.Last().Key) - (blen - 1)) >= 0)
            {
                q[d] = posRemainder(r.Last().Value * binv, GF);
                if (q[d] == BigInteger.Zero) {
                    q.Remove(d);
                    break;
                }
                r = addPolyRingSparse(r, mulPolyRingSparse(bneg, new SortedList<BigInteger, BigInteger>(q.TakeWhile((kv) => kv.Key <= d).ToDictionary(x => x.Key, x => x.Value)), GF), GF);
            }
            BigInteger[] rret = new BigInteger[(int)r.Last().Key+1];
            foreach (BigInteger i in r.Keys) rret[(int)(r.Last().Key - i)] = r[i];
            return new Tuple<SortedList<BigInteger, BigInteger>, BigInteger[]>(q, rret);
        }
        //Generalized Remainder Theorem - still need to compute t recurrent series which for large degree divisor is not practical
        //https://arxiv.org/abs/1506.06637
        static BigInteger[] remainderPolyRingSparse(SortedList<BigInteger, BigInteger> A, BigInteger[] B, BigInteger GF)
        {
            //if (B.Length == 0) throw;
            BigInteger n = A.Last().Key;
            int m = B.Count() - 1;
            BigInteger[] remainder = new BigInteger[m]; //m-1 terms
            BigInteger[] t = new BigInteger[(int)n - m + 1];
            t[0] = modInverse(B[0], GF); //t1
            //B coefficients must be negated except for B[0]
            //t1=1/b[m]
            //tr=1/b[m]*sum_i=1^r-1(b[m-i]*t[r-i])
            //t2=t1*b[m-1]*t1=t1^2*b[m-1]
            //t3=t1*(b[m-1]*t2+b[m-2]*t1)=t1^3*b[m-1]^2+t1^2*b[m-2]
            //t4=t1*(b[m-1]*t3+b[m-2]*t2+b[m-3]*t1)=t1^4*b[m-1]^3+2*t1^3*b[m-1]*b[m-2]+t1^2*b[m-3]
            //t5=t1*(b[m-1]*t4+b[m-2]*t3+b[m-3]*t2+b[m-4]*t1)=t1^5*b[m-1]^4+3*t1^4*b[m-1]^2*b[m-2]+2*t1^3*b[m-1]*b[m-3]+tl^3*bm2^2+t1^2*bm4
            for (int r = 2; r <= n - m + 1; r++) {
                BigInteger sum = BigInteger.Zero;
                for (int i = 1; i <= Math.Min(r - 1, m); i++) {
                    sum = posRemainder(sum + (-B[i] * t[r - i - 1]), GF);
                }
                t[r-1] = posRemainder(t[0] * sum, GF);
            }
            for (int k = 0; k < m; k++) {
                if (A.ContainsKey(k)) remainder[m - 1 - k] = A[k];
                BigInteger outersum = BigInteger.Zero;
                for (int i = 0; i <= k; i++) {
                    int j = k - i;
                    BigInteger sum = BigInteger.Zero;
                    //all in A between m+j and n
                    foreach (KeyValuePair<BigInteger, BigInteger> kval in A.Where((kv) => kv.Key >= m + j)) {
                        //for (int v = 0; v <= n - m - j; v++) {
                        int v = (int)(n - kval.Key);
                        //if (A.ContainsKey(n - v))
                        sum = posRemainder(sum + (t[(int)n - m - j + 1 - v - 1] * A[n - v]), GF);
                    }
                    outersum = posRemainder(outersum + ((i == m ? B[m - i] : (-B[m - i])) * sum), GF);
                }
                remainder[m - 1 - k] = posRemainder(remainder[m - 1 - k] + outersum, GF); //make monic with posRemainder(t[0] * outersum, GF)
            }
            return remainder.Skip(remainder.TakeWhile((BigInteger c) => c == BigInteger.Zero).Count()).ToArray();
        }
        //https://github.com/sagemath/sage/blob/master/src/sage/libs/ntl/ntlwrap_impl.h
        //https://github.com/sagemath/sage/blob/develop/src/sage/rings/polynomial/polynomial_quotient_ring_element.py
        //https://github.com/sagemath/sage/blob/develop/src/sage/rings/polynomial/polynomial_quotient_ring.py
        static BigInteger[] remainderPolyRingSparsePow2(SortedList<BigInteger, BigInteger> A, BigInteger[] B, BigInteger GF)
        {
            //note that (B%2^p)*(B%2^(p-1))=B%2^(2p-1)
            //NTL in lzz_pX for integer field univariate polynomial implements rem with rem21 using the FFT method
            //however in this case we can just do the classic modular exponentiation which works in log n and always keeps a reduced polynomial
            int m = B.Count() - 1;
            BigInteger[] remainder = new BigInteger[m]; //m-1 terms
            foreach (KeyValuePair<BigInteger, BigInteger> elem in A) {
                BigInteger exp = elem.Key;
                BigInteger[] result = new BigInteger[] { BigInteger.One };
                BigInteger[] b = new BigInteger[] { BigInteger.One, BigInteger.Zero };
                while (exp > 0) {
                    if ((exp & 1) == 1) {
                        result = divmodPolyRing(mulPolyRing(result, b, GF), B, GF).Item2;
                    }
                    exp >>= 1;
                    b = divmodPolyRing(mulPolyRing(b, b, GF), B, GF).Item2;
                }
                result = mulPolyRing(result, new BigInteger[] { elem.Value }, GF);
                remainder = addPolyRing(result, remainder, GF);
            }
            return remainder.Skip(remainder.TakeWhile((BigInteger c) => c == BigInteger.Zero).Count()).ToArray();
        }
        static BigInteger[] substitutePolyRing(BigInteger[] A, BigInteger[] B, BigInteger[] divpoly, BigInteger GF)
        {
            BigInteger[] result = new BigInteger[] { BigInteger.Zero };
            int alen = A.Length;
            for (int i = 0; i < alen; i++) {
                if (i == alen - 1) {
                    result = addPolyRing(result, new BigInteger[] { A[i] }, GF);
                } else {
                    result = addPolyRing(result, mulPolyRing(modexpPolyRing(B, alen - i - 1, divpoly, GF), new BigInteger[] { A[i] }, GF), GF);
                }
            }
            return result;
        }
        //https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
        //https://en.wikipedia.org/wiki/Polynomial_greatest_common_divisor#Bézout's_identity_and_extended_GCD_algorithm
        static BigInteger[] gcdPolyRing(BigInteger[] a, BigInteger[] b, BigInteger GF)
        {
            BigInteger[] r = a, ro = b;
            BigInteger[] s = new BigInteger[] { BigInteger.Zero }, so = new BigInteger[] { BigInteger.One };
            BigInteger[] t = new BigInteger[] { BigInteger.One }, to = new BigInteger[] { BigInteger.Zero };
            while (r.Length != 0)
            {
                if (r[0] != BigInteger.One)
                { //must be monic or division will not be correct!
                    BigInteger multiplier = modInverse(r[0], GF);
                    r = mulPolyRing(r, new BigInteger[] { multiplier }, GF);
                }
                BigInteger[] quot = mulPolyRing(divmodPolyRing(ro, r, GF).Item1, new BigInteger[] { -1 }, GF);
                BigInteger[] swap = ro;
                ro = r; r = addPolyRing(swap, mulPolyRing(quot, r, GF), GF);
                swap = so;
                so = s; s = addPolyRing(swap, mulPolyRing(quot, s, GF), GF);
                swap = to;
                to = t; t = addPolyRing(swap, mulPolyRing(quot, t, GF), GF);
            }
            return ro;
        }
        //Extended Euclid GCD of 1
        static BigInteger[] modInversePolyRing(BigInteger[] a, BigInteger[] n, BigInteger GF)
        {
            BigInteger[] i = n, v = new BigInteger[] { BigInteger.Zero }, d = new BigInteger[] { BigInteger.One };
            while (a.Length > 0)
            {
                BigInteger[] t = divmodPolyRing(i, a, GF).Item1, x = a;
                a = divmodPolyRing(i, x, GF).Item2;
                i = x;
                x = d;
                d = addPolyRing(v, mulPolyRing(mulPolyRing(t, x, GF), new BigInteger[] { -1 }, GF), GF);
                v = x;
            }
            v = mulPolyRing(new BigInteger[] { modInverse(i[0], GF) }, v, GF);
            v = divmodPolyRing(v, n, GF).Item2;
            //if (v < 0) v = (v + n) % n;
            return v;
        }
        static BigInteger[] modexpPolyRingFast(BigInteger[] X, BigInteger m, BigInteger[] f, BigInteger GF)
        {
            BigInteger[] d = { BigInteger.One };
            int bs = GetBitSize(m);
            for (int i = bs; i > 0; i--)
            {
                if (((BigInteger.One << (bs - i)) & m) != 0)
                {
                    d = divmodPolyRing(mulPolyRing(d, X, GF), f, GF).Item2;
                }
                X = divmodPolyRing(mulPolyRing(X, X, GF), f, GF).Item2;
            }
            return d;
        }

        static BigInteger[] modexpPolyRing(BigInteger[] X, BigInteger m, BigInteger[] f, BigInteger GF)
        {
            BigInteger[] d = { BigInteger.One };
            int bs = GetBitSize(m);
            for (int i = bs; i > 0; i--)
            {
                if (((BigInteger.One << (bs - i)) & m) != 0)
                {
                    d = divmodPolyRing(mulPolyRing(d, X, GF), f, GF).Item2;
                }
                X = divmodPolyRing(mulPolyRing(X, X, GF), f, GF).Item2;
            }
            return d;
        }
        static Tuple<BigInteger[], BigInteger[]> invertECPolyRing(Tuple<BigInteger[], BigInteger[]> P, BigInteger GF)
        {
            return new Tuple<BigInteger[], BigInteger[]>(P.Item1, mulPolyRing(P.Item2, new BigInteger[] { -1 }, GF));
        }
        static Tuple<BigInteger[], BigInteger[]> addECPolyRing(Tuple<BigInteger[], BigInteger[]> P1, Tuple<BigInteger[], BigInteger[]> P2, int a, BigInteger GF, BigInteger[] divpoly, BigInteger[] f)
        {
            Tuple<BigInteger[], BigInteger[]> O = new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.Zero }, new BigInteger[] { BigInteger.One });
            if (P1.Item1.SequenceEqual(O.Item1) && P1.Item2.SequenceEqual(O.Item2)) return P2;
            if (P2.Item1.SequenceEqual(O.Item1) && P2.Item2.SequenceEqual(O.Item2)) return P1;
            Tuple<BigInteger[], BigInteger[]> inv = invertECPolyRing(P2, GF);
            if (P1.Item1.SequenceEqual(inv.Item1) && P1.Item2.SequenceEqual(inv.Item2)) return new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.Zero }, new BigInteger[] { BigInteger.One });
            BigInteger[] x1 = P1.Item1, y1 = P1.Item2, x2 = P2.Item1, y2 = P2.Item2, m;
            m = (P1.Item1.SequenceEqual(P2.Item1) && P1.Item2.SequenceEqual(P2.Item2)) ? divmodPolyRing(mulPolyRing(addPolyRing(mulPolyRing(new BigInteger[] { 3 }, mulPolyRing(x1, x1, GF), GF), new BigInteger[] { a }, GF), modInversePolyRing(mulPolyRing(mulPolyRing(new BigInteger[] { 2 }, y1, GF), f, GF), divpoly, GF), GF), divpoly, GF).Item2 : divmodPolyRing(mulPolyRing(addPolyRing(y2, mulPolyRing(y1, new BigInteger[] { -1 }, GF), GF), modInversePolyRing(divmodPolyRing(addPolyRing(x2, mulPolyRing(x1, new BigInteger[] { -1 }, GF), GF), divpoly, GF).Item2, divpoly, GF), GF), divpoly, GF).Item2;
            BigInteger[] x3 = divmodPolyRing(addPolyRing(addPolyRing(mulPolyRing(f, mulPolyRing(m, m, GF), GF), mulPolyRing(x1, new BigInteger[] { -1 }, GF), GF), mulPolyRing(x2, new BigInteger[] { -1 }, GF), GF), divpoly, GF).Item2;
            return new Tuple<BigInteger[], BigInteger[]>(x3, divmodPolyRing(addPolyRing(mulPolyRing(m, addPolyRing(x1, mulPolyRing(x3, new BigInteger[] { -1 }, GF), GF), GF), mulPolyRing(y1, new BigInteger[] { -1 }, GF), GF), divpoly, GF).Item2);
        }
        static Tuple<BigInteger[], BigInteger[]> scaleECPolyRing(Tuple<BigInteger[], BigInteger[]> x, BigInteger k, int a, BigInteger GF, BigInteger[] divpoly, BigInteger[] f)
        {
            Tuple<BigInteger[], BigInteger[]> result = new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.Zero }, new BigInteger[] { BigInteger.One });
            while (k > 0)
            {
                if (!k.IsEven) result = addECPolyRing(result, x, a, GF, divpoly, f);
                x = addECPolyRing(x, x, a, GF, divpoly, f);
                k = k >> 1;
            }
            return result;
        }
        //https://en.wikipedia.org/wiki/Schoof%27s_algorithm
        static BigInteger Schoof(int Ea, int Eb, BigInteger GF, RNGCryptoServiceProvider rng, BigInteger ExpectedBase)
        {
            BigInteger realT = GF + 1 - ExpectedBase;
            //BigInteger sqrtp = TonelliShanks(rng, GF, GF);
            BigInteger sqrtGF = Sqrt(16 * GF);
            BigInteger sqrtp4 = sqrtGF + (sqrtGF * sqrtGF < 16 * GF ? 1 : 0); //64-bit square root, can bump this up by one if less than lower bound if that is needed
            //getPrimes(1024);
            BigInteger l = 2;
            BigInteger prodS = BigInteger.One;
            //need a random point on the EC
            /*BigInteger x, ysquared, y;
            do {
                //x = GetNextRandomBig(rng, GF);
                x = 3;
                ysquared = posRemainder(x * x * x + Ea * x + Eb, GF);
                y = TonelliShanks(rng, ysquared, GF);
                y = BigInteger.Parse("138210074149391040327039341895683130372");
            } while (y == BigInteger.Zero);
            BigInteger xp = posRemainder(BigInteger.ModPow(x, GF, GF), GF), yp = posRemainder(BigInteger.ModPow(y, GF, GF), GF);*/
            //https://en.wikipedia.org/wiki/Division_polynomials
            //y=2*y^2 where y^2=x^3+ax+b
            //BigInteger ysub = 2 * (x * x * x + Ea * x + Eb);
            BigInteger[] f = new BigInteger[] { 1, 0, Ea, Eb }; //Eb, Ea, 0, 1
            BigInteger[] ysub = mulPolyRing(new BigInteger[] { 2 }, f, GF);
            List<BigInteger[]> divPolys = new List<BigInteger[]>(new BigInteger[][] {
                new BigInteger[] { BigInteger.Zero },
                new BigInteger[] { BigInteger.One },
                mulPolyRing(new BigInteger[] { 2 }, ysub, GF),
                new BigInteger[] { 3, 0, 6 * Ea, 12 * Eb, -new BigInteger(Ea) * Ea}, //-new BigInteger(Ea) * Ea, 12 * Eb, 6 * Ea, 0, 3
                mulPolyRing(mulPolyRing(new BigInteger[] { 4 }, ysub, GF), new BigInteger[] { 1, 0, 5 * Ea, 20 * Eb, -5 * new BigInteger(Ea) * Ea, -4 * new BigInteger(Ea) * Eb, -8 * new BigInteger(Eb) * Eb - new BigInteger(Ea) * Ea * Ea }, GF) //-8 * new BigInteger(Eb) * Eb - new BigInteger(Ea) * Ea * Ea, -4 * new BigInteger(Ea) * Eb, -5 * new BigInteger(Ea) * Ea, 20 * Eb, 5 * Ea, 0, 1
                });
            //Tuple<BigInteger, BigInteger> xypsquared = new Tuple<BigInteger, BigInteger>(BigInteger.ModPow(x, GF * GF, GF), BigInteger.ModPow(y, GF * GF, GF));
            BigInteger[] ysquared = mulPolyRing(ysub, ysub, GF);
            BigInteger[] b6sqr = mulPolyRing(new BigInteger[] { new BigInteger(2 * 2) }, mulPolyRing(ysub, ysub, GF), GF);
            //BigInteger b6sqrinv = modInverse(2 * 2 * y * y * 2 * 2 * y * y, GF); //(4y^2)^2
            List<Tuple<BigInteger, BigInteger>> ts = new List<Tuple<BigInteger, BigInteger>>();
            BigInteger t = BigInteger.Zero;
            while (prodS <= sqrtp4) { //log2(GF) primes required on average
                while (divPolys.Count <= l) {
                    int m = divPolys.Count / 2; //m >= 2
                    //even ones in odd psis need adjustment by b6^2=(2*y)^2=4y^2
                    if ((m & 1) == 0) {
                        divPolys.Add(addPolyRing(divmodPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m], GF), divPolys[m], GF), divPolys[m], GF), b6sqr, GF).Item1, mulPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 1], divPolys[m + 1], GF), divPolys[m + 1], GF), divPolys[m + 1], GF), new BigInteger[] { -1 }, GF), GF));
                    } else {
                        divPolys.Add(addPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m], GF), divPolys[m], GF), divPolys[m], GF), mulPolyRing(divmodPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 1], divPolys[m + 1], GF), divPolys[m + 1], GF), divPolys[m + 1], GF), b6sqr, GF).Item1, new BigInteger[] { -1 }, GF), GF));
                    }
                    //divPolys.Add(addPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m], GF), divPolys[m], GF), divPolys[m], GF), mulPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 1], divPolys[m + 1], GF), divPolys[m + 1], GF), divPolys[m + 1], GF), new BigInteger[] { -1 }, GF), GF));
                    m++; //m >= 3
                    divPolys.Add(divmodPolyRing(mulPolyRing(divPolys[m], addPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m - 1], GF), divPolys[m - 1], GF), mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 2], divPolys[m + 1], GF), divPolys[m + 1], GF), new BigInteger[] { -1 }, GF), GF), GF), mulPolyRing(new BigInteger[] { 2 }, ysub, GF), GF).Item1);
                }
                BigInteger tl = BigInteger.Zero;
                BigInteger[] divpoly = divPolys[(int)l]; //even ones need to be divided by 2*y
                if (l == 2) {
                    SortedList<BigInteger, BigInteger> xp = new SortedList<BigInteger, BigInteger>();
                    xp.Add(GF, 1); //gcd should return 1
                    BigInteger[] gcdres = addPolyRing(gcdPolyRing(remainderPolyRingSparsePow2(xp, f, GF), f, GF), mulPolyRing(new BigInteger[] { 1, 0 }, new BigInteger[] { -1 }, GF), GF);
                    if (gcdres.Length == 1 & gcdres[0] == BigInteger.One) tl = 1;
                } else {
                    BigInteger pl = posRemainder(GF, l);
                    if (pl >= l / 2) pl -= l;
                    SortedList<BigInteger, BigInteger> xp = new SortedList<BigInteger, BigInteger>();
                    xp.Add(GF, 1);
                    //remainderPolyRingSparse(xp, divpoly, GF);
                    //divmodPolyRingSparse(xp, divpoly, GF);
                    //BigInteger[] modinv = modInversePolyRing(new BigInteger[] { BigInteger.One, BigInteger.Zero }, divpoly, GF);
                    //divmodPolyRing(mulPolyRing(modinv, new BigInteger[] { BigInteger.One, BigInteger.Zero }, GF), divpoly, GF).Item2;
                    BigInteger[] xprem = remainderPolyRingSparsePow2(xp, divpoly, GF);
                    BigInteger[] yprem = modexpPolyRing(f, (GF - 1) / 2, divpoly, GF);
                    //correct method of squaring is to substitute x value of prior fields into x, y of itself with the y multiplied by the original y
                    //BigInteger[] xpsquared = divmodPolyRing(substitutePolyRing(xprem, xprem, divpoly, GF), divpoly, GF).Item2;
                    BigInteger[] xpsquared = modexpPolyRing(xprem, GF, divpoly, GF);
                    //BigInteger[] ypsquared = divmodPolyRing(mulPolyRing(substitutePolyRing(yprem, xprem, divpoly, GF), yprem, GF), divpoly, GF).Item2;
                    BigInteger[] ypsquared = modexpPolyRing(mulPolyRing(substitutePolyRing(f, xprem, divpoly, GF), f, GF), (GF - 1) / 2, divpoly, GF);
                    //BigInteger[] ypsquared = modexpPolyRing(yprem, GF + 1, divpoly, GF);
                    Tuple<BigInteger[], BigInteger[]> Q = scaleECPolyRing(new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.One, BigInteger.Zero }, new BigInteger[] { BigInteger.One }), posRemainder(pl, l), Ea, GF, divpoly, f);
                    if (!Q.Item1.SequenceEqual(xpsquared) || !Q.Item2.SequenceEqual(ypsquared)) {
                        Tuple<BigInteger[], BigInteger[]> S = addECPolyRing(new Tuple<BigInteger[], BigInteger[]>(xpsquared, ypsquared), Q, Ea, GF, divpoly, f);
                        if (!S.Item1.SequenceEqual(new BigInteger[] { BigInteger.Zero }) || !S.Item2.SequenceEqual(new BigInteger[] { BigInteger.One }))
                        {
                            //limited by 1 in y, and (l^2 - 3) / 2 in x
                            BigInteger m;
                            Tuple<BigInteger[], BigInteger[]> P = new Tuple<BigInteger[], BigInteger[]>(xprem, yprem);
                            for (m = BigInteger.One; m <= (l - 1) / 2; m++) {
                                //Tuple<BigInteger, BigInteger> xym = scaleEC(new Tuple<BigInteger[], BigInteger[]>(xprem, yprem), m, Ea, GF);
                                if (addPolyRing(S.Item1, mulPolyRing(P.Item1, new BigInteger[] { -1 }, GF), GF).Length == 0) {
                                    tl = addPolyRing(S.Item2, mulPolyRing(P.Item2, new BigInteger[] { -1 }, GF), GF).Length == 0 ? m : l - m;
                                    break;
                                }
                                P = addECPolyRing(P, new Tuple<BigInteger[], BigInteger[]>(xprem, yprem), Ea, GF, divpoly, f);
                            }
                        }
                    } else { //if (m > (l - 1) / 2) {
                        //quadratic non-residue of x^2 === GF (mod l) === pl
                        //since l is prime, do not need to deal with composite or prime power cases
                        //instead of Tonelli-Shanks, can show non-residue by excluding 1 root (GF === 0 (mod l)), and 2 roots (gcd(GF, l) == 1) and is residue
                        //but easier to just use Legendre symbol is -1 and prove non-residue = GF ^ ((l - 1) / 2) (mod l)
                        //if (BigInteger.ModPow(GF, (l - 1) / 2, l) == -1) tl = 0;
                        //if (pl != BigInteger.Zero && BigInteger.GreatestCommonDivisor(GF, l) != BigInteger.One) tl = 0;
                        BigInteger w = TonelliShanks(rng, posRemainder(GF, l), l); //since we need result anyway might as well compute unless non-residue very common and much faster other methods
                        if (w == BigInteger.Zero) tl = 0;
                        else {
                            Tuple<BigInteger[], BigInteger[]> xyw = scaleECPolyRing(new Tuple<BigInteger[], BigInteger[]>(xprem, yprem), w, Ea, GF, divpoly, f);
                            if (xprem != xyw.Item1) { tl = BigInteger.Zero; }
                            else { tl = yprem == xyw.Item2 ? BigInteger.Remainder(2 * w, l) : BigInteger.Remainder(-2 * w, l); }
                        }
                    }
                }
                Console.WriteLine(l + " " + tl + " " + BigInteger.Remainder(realT, l));
                //BigInteger.Remainder(realT, l) == tl;
                ts.Add(new Tuple<BigInteger, BigInteger>(tl, l));
                BigInteger a = prodS * modInverse(prodS, l);
                BigInteger b = l * modInverse(l, prodS);
                prodS *= l;
                t = (a * tl + b * t) % prodS;
                l = nextPrime(l);
            }
            //GetBitSize(GF) == int(Math.Ceiling(BigInteger.Log(GF, 2))); //128-bit field
            //BigInteger t = BigInteger.Zero;
            //chinese remainder theorem (CRT) on ts while |t| < 2*Sqrt(GF)
            return GF + 1 - t;
        }
        //Dedekind Eta function (1-x)(1-x^2)(1-x^3)... infinite expansion
        //https://github.com/miracl/MIRACL/blob/master/source/curve/ps_zzn.cpp
        static BigInteger[] getEta(int psN)
        {
            int ce = 2, co = 1, c = 2, one = 1;
            bool even = true;
            int degree = psN * (psN - 1) / 2 + 1;
            List<BigInteger> res = new List<BigInteger>();
            res.Add(BigInteger.One);
            res.Add(-BigInteger.One);
            res.Add(-BigInteger.One);
            while (c < psN) {
                if (even) {
                    c += ce + 1;
                    ce += 2;
                    while (res.Count() < c) res.Add(BigInteger.Zero);
                    res.Add(one);
                } else {
                    c += co + 1;
                    co += 1;
                    while (res.Count() < c) res.Add(BigInteger.Zero);
                    res.Add(one);
                    one = -one;
                }
                even = !even;
            }
            res.Reverse();
            return res.ToArray();
        }
        static BigInteger[] addPoly(BigInteger[] a, BigInteger[] b)
        {
            int alen = a.Length, blen = b.Length;
            BigInteger[] c = new BigInteger[Math.Max(alen, blen)];
            int clen = c.Length;
            for (int i = 0; i < clen; i++)
            {
                int aoffs = alen - 1 - i, boffs = blen - 1 - i, coffs = clen - 1 - i;
                if (i >= alen) c[coffs] = b[boffs];
                else if (i >= blen) c[coffs] = a[aoffs];
                else c[coffs] = a[aoffs] + b[boffs];
            }
            return clen == 0 || c[0] != BigInteger.Zero ? c : c.Skip(c.TakeWhile((BigInteger cr) => cr == BigInteger.Zero).Count()).ToArray(); ;
        }
        static BigInteger[] mulPoly(BigInteger[] A, BigInteger[] B)
        {
            int alen = A.Length, blen = B.Length;
            if (alen == 0) return A; if (blen == 0) return B;
            BigInteger[] p = new BigInteger[alen + blen - 1];
            for (int i = 0; i < blen; i++) {
                if (B[i] == BigInteger.Zero) continue;
                for (int j = 0; j < alen; j++) {
                    if (A[j] == BigInteger.Zero) continue;
                    int ijoffs = i + j;
                    p[ijoffs] += A[j] * B[i];
                }
            }
            return p.Length == 0 || p[0] != BigInteger.Zero ? p : p.Skip(p.TakeWhile((BigInteger c) => c == BigInteger.Zero).Count()).ToArray();
        }
        static BigInteger[] modexpPoly(BigInteger[] X, BigInteger m)
        {
            BigInteger[] d = { BigInteger.One };
            int bs = GetBitSize(m);
            for (int i = bs; i > 0; i--) {
                if (((BigInteger.One << (bs - i)) & m) != 0) {
                    d = mulPoly(d, X);
                }
                X = mulPoly(X, X);
            }
            return d;
        }
        static Tuple<BigInteger[], BigInteger[]> divmodPoly(BigInteger[] A, BigInteger[] B)
        {
            //if (B.Length == 0) throw;
            int alen = A.Length, blen = B.Count();
            BigInteger[] q = new BigInteger[alen], r = A; int d;
            BigInteger[] bneg = mulPoly(B, new BigInteger[] { -1 });
            int rlen = r.Length;
            while (rlen != 0 && (d = (rlen - 1) - (blen - 1)) >= 0)
            {
                int aoffs = alen - d - 1;
                q[aoffs] = r[0] / B[0];
                if (q[aoffs] == BigInteger.Zero) break;
                r = addPoly(r, mulPoly(bneg, q.Skip(aoffs).ToArray()));
                rlen = r.Length;
            }
            return new Tuple<BigInteger[], BigInteger[]>(q.Skip(q.TakeWhile((BigInteger c) => c == BigInteger.Zero).Count()).ToArray(), r);
        }
        static BigInteger[] phase(BigInteger [] z, int l, int psN)
        {
            BigInteger[] w = new BigInteger[psN];
            int zf = (int)z[0], k;
            if (zf % l == 0) k = zf;
            else {
                k = (zf / l) * l;
                if (zf >= 0) k += l;
            }
            for (; k < psN; k += l) {
                w[k] = l * z[k];
            }
            return w;
        }
        static List<Tuple<BigInteger, BigInteger, BigInteger>> getModularPoly(int l)
        {
            //need mulPoly, divmodPoly, addPoly, modexpPoly since no ring here
            int s;
            for (s = 1; ; s++)
                if (s * (l - 1) % 12 == 0) break;
            int v = s * (l - 1) / 12;
            int psN = v + 2;
            BigInteger[] x = new BigInteger[] { BigInteger.Zero };
            //calculate Klein=j(tau) from its definition
            for (int n = 1; n < psN; n++)
            {
                //SortedList<BigInteger, BigInteger> a = new SortedList<BigInteger, BigInteger>();
                //a.Add(n, new BigInteger(n * n * n)); //a=n^3*x^n
                //SortedList<BigInteger, BigInteger> b = new SortedList<BigInteger, BigInteger>();
                //b.Add(0, 1);
                //b.Add(n, -1);
                BigInteger[] a = new BigInteger[n + 1];
                a[0] = new BigInteger(n * n * n);
                BigInteger[] b = new BigInteger[n + 1];
                b[0] = -1;
                b[n] = 1;
                BigInteger[] t = divmodPoly(a, b).Item1;
                x = addPoly(x, t);
            }
            x = mulPoly(x, new BigInteger[] { 240 });
            x[0] = BigInteger.One;
            x = modexpPoly(x, 3);
            BigInteger[] y = getEta(psN);
            y = modexpPoly(y, 24);
            BigInteger[] klein = divmodPoly(x, y).Item1;
            klein = divmodPoly(klein, new BigInteger[] {BigInteger.One, BigInteger.Zero}).Item1; // divide by x
            psN *= l;
            klein = modexpPoly(klein, l);
            BigInteger[] z = getEta(psN);
            y = modexpPoly(z, l);
            z = divmodPoly(z, y).Item1; //y = 1 / y; z *= y;
            BigInteger[] flt = modexpPoly(z, 2 * s);
            BigInteger[] xv = new BigInteger[v + 1];
            xv[0] = 1;
            flt = divmodPoly(flt, xv).Item1; // multiply by x^-v
            BigInteger w = BigInteger.Pow(l, s);
            y = modexpPoly(flt, l);
            BigInteger[] zlt = divmodPoly(new BigInteger[] { w }, y).Item1;
            // Calculate Power Sums
            z = new BigInteger[] { 1 };
            BigInteger[] f = new BigInteger[] { 1 };
            BigInteger[][] ps = new BigInteger[l + 1 + 1][];
            ps[0] = new BigInteger[] { l + 1 };
            for (int i = 1; i <= l + 1; i++) {
                f = mulPoly(f, flt);
                z = mulPoly(z, flt);
                ps[i] = addPoly(phase(f, l, psN), z);
            }
            BigInteger[][] c = new BigInteger[l + 1 + 1][];
            c[0] = new BigInteger[] { BigInteger.One };
            for (int i = 1; i <= l + 1; i++) {
                c[i] = new BigInteger[] { BigInteger.Zero };
                for (int j = 1; j <= i; j++) c[i] = addPoly(c[i], mulPoly(ps[j], c[i - j]));
                c[i] = divmodPoly(mulPoly(c[i], new BigInteger[] { -1 }), new BigInteger[] { i }).Item1;
            }

            return new List<Tuple<BigInteger, BigInteger, BigInteger>>();
        }
        static BigInteger SchoofElkiesAtkins(int Ea, int Eb, BigInteger GF, BigInteger ExpectedBase)
        {
            BigInteger realT = GF + 1 - ExpectedBase;
            BigInteger delta = -16 * (4 * new BigInteger(Ea) * Ea * Ea + 27 * new BigInteger(Eb) * Eb);
            //4A^3+27B^2 == 0 is not allowed or j-invariant with 0 or 1728
            BigInteger j_invariant = (-1728 * new BigInteger(Ea) * Ea * Ea) / delta;
            BigInteger sqrtGF = Sqrt(16 * GF);
            BigInteger sqrtp4 = sqrtGF + (sqrtGF * sqrtGF < 16 * GF ? 1 : 0); //64-bit square root, can bump this up by one if less than lower bound if that is needed
            //getPrimes(1024);
            BigInteger M = BigInteger.One, l = 2;
            BigInteger prodS = BigInteger.One;
            BigInteger[] f = new BigInteger[] { 1, 0, Ea, Eb }; //Eb, Ea, 0, 1
            //modular polynomials are needed first
            //https://github.com/miracl/MIRACL/blob/master/source/curve/mueller.cpp
            List<Tuple<List<BigInteger>, BigInteger>> Ap = new List<Tuple<List<BigInteger>, BigInteger>>();
            List<Tuple<BigInteger, BigInteger>> Ep = new List<Tuple<BigInteger, BigInteger>>();
            BigInteger t = BigInteger.Zero;
            //https://github.com/miracl/MIRACL/blob/master/source/curve/sea.cpp
            while (prodS <= sqrtp4) { //log2(GF) primes required on average
                BigInteger tl = BigInteger.Zero;
                if (l == 2) {
                    SortedList<BigInteger, BigInteger> xp = new SortedList<BigInteger, BigInteger>();
                    xp.Add(GF, 1); //gcd should return 1
                    BigInteger[] gcdres = addPolyRing(gcdPolyRing(remainderPolyRingSparsePow2(xp, f, GF), f, GF), mulPolyRing(new BigInteger[] { 1, 0 }, new BigInteger[] { -1 }, GF), GF);
                    if (gcdres.Length == 1 & gcdres[0] == BigInteger.One) tl = 1;
                } else {
                    if (0 == 0) { //Atkin prime
                        List<BigInteger> T = new List<BigInteger>();
                    } else { //Elkies prime
                        //GetFactorOfDivisionPolynomialFactor(l, Ea, Eb, GF);
                        BigInteger lambda = BigInteger.Zero;
                        t = lambda + lambda / GF;
                        Ep.Add(new Tuple<BigInteger, BigInteger>(t, l));
                    }
                }
                Console.WriteLine(l + " " + tl + " " + BigInteger.Remainder(realT, l));
                BigInteger a = prodS * modInverse(prodS, l);
                BigInteger b = l * modInverse(l, prodS);
                prodS *= l;
                t = (a * tl + b * t) % prodS;
                l = nextPrime(l);
            }
            //t = BigInteger.Zero;
            return GF + 1 - t;
        }
        static Tuple<BigInteger, BigInteger> cswap(BigInteger a, BigInteger b, bool swap)
        {
            return swap ? new Tuple<BigInteger, BigInteger>(b, a) : new Tuple<BigInteger, BigInteger>(a, b);
        }
        static BigInteger ladder(BigInteger u, BigInteger k, int Ea, BigInteger p)
        {
            BigInteger u2 = 1, w2 = 0;
            BigInteger u3 = u, w3 = 1;
            for (int i = GetBitSize(p); i >= 0; i--) {
                bool b = (1 & (k >> i)) != BigInteger.Zero;
                Tuple<BigInteger, BigInteger> tup;
                tup = cswap(u2, u3, b); u2 = tup.Item1; u3 = tup.Item2;
                tup = cswap(w2, w3, b); w2 = tup.Item1; w3 = tup.Item2;
                BigInteger temp = posRemainder(u2 * u3 - w2 * w3, p),
                    temp2 = posRemainder(u2 * w3 - w2 * u3, p);
                u3 = temp * temp;
                w3 = u * temp2 * temp2;
                temp = u2 * u2; temp2 = w2 * w2;
                w2 = posRemainder(4 * u2 * w2 * (temp + Ea * u2 * w2 + temp2), p);
                temp = posRemainder(temp - temp2, p);
                u2 = temp * temp;
                tup = cswap(u2, u3, b); u2 = tup.Item1; u3 = tup.Item2;
                tup = cswap(w2, w3, b); w2 = tup.Item1; w3 = tup.Item2;
            }
            return BigInteger.Remainder(u2 * BigInteger.ModPow(w2, p - 2, p), p);
        }
        //Recover: Okeya–Sakurai y-coordinate recovery
        static Tuple<BigInteger, BigInteger> ladder2(Tuple<BigInteger, BigInteger> u, BigInteger k, int Ea, int EaOrig, int Eb, BigInteger p, int conv)
        {
            BigInteger u2 = 1, w2 = 0;
            BigInteger u3 = u.Item1, w3 = 1;
            for (int i = GetBitSize(p); i >= 0; i--)
            {
                bool b = (1 & (k >> i)) != BigInteger.Zero;
                Tuple<BigInteger, BigInteger> tup;
                tup = cswap(u2, u3, b); u2 = tup.Item1; u3 = tup.Item2;
                tup = cswap(w2, w3, b); w2 = tup.Item1; w3 = tup.Item2;
                BigInteger temp = posRemainder(u2 * u3 - w2 * w3, p),
                    temp2 = posRemainder(u2 * w3 - w2 * u3, p);
                u3 = temp * temp;
                w3 = u.Item1 * temp2 * temp2;
                temp = u2 * u2; temp2 = w2 * w2;
                w2 = posRemainder(4 * u2 * w2 * (temp + Ea * u2 * w2 + temp2), p);
                temp = posRemainder(temp - temp2, p);
                u2 = temp * temp;
                tup = cswap(u2, u3, b); u2 = tup.Item1; u3 = tup.Item2;
                tup = cswap(w2, w3, b); w2 = tup.Item1; w3 = tup.Item2;
            }
            BigInteger x1 = BigInteger.Remainder(u2 * BigInteger.ModPow(w2, p - 2, p), p); //or for other algo x0
            //x2=ladder(u.Item1, k+1, Ea, p) //or (r+1)G instead of rG
            BigInteger x2 = BigInteger.Remainder(u3 * BigInteger.ModPow(w3, p - 2, p), p); //or for other algo x1
            //y1=(2b+(a+x0x1)(x0+x1)-x2(x0-x1)^2)/2y0
            BigInteger diff = posRemainder(u.Item1 - x1, p);
            return new Tuple<BigInteger, BigInteger>(x1, posRemainder(posRemainder(2 * Eb + posRemainder(EaOrig + (u.Item1 + conv) * (x1 + conv), p) * (u.Item1 + conv + x1 + conv) - (x2 + conv) * diff * diff, p) * modInverse(2 * u.Item2, p), p));
            //BigInteger x1 = BigInteger.Remainder(u3 * BigInteger.ModPow(w3, p - 2, p), p);
            //BigInteger v1 = x0 == 1 ? 0 : u.Item1, v2 = x0 + v1, v3 = x0 - v1;
            //v3 = v3 * v3; v3 = v3 * x1;
            //v1 = x0 == 1 ? 0 : 2 * Ea;
            //v2 = v2 + v1;
            //BigInteger v4 = u.Item1 * x0; v4 += (x0 == 1 ? 0 : 1);
            //v2 = v2 * v4;
            //v1 = x0 == 1 ? 0 : v1;
            //v2 = v2 - v1;
            //v2 = x1 == 1 ? 0 : v2;
            //BigInteger y1 = v2 - v3;
            //v1 = 2 * Eb * u.Item2;
            //v1 = x0 == 1 ? 0 : v1; v1 = x1 == 1 ? 0 : v1;
            //return (x0 == 1 ? 0 : v1) == 0 ? new Tuple<BigInteger, BigInteger>(1, 0) : new Tuple<BigInteger, BigInteger>(posRemainder(v1 * x0, p), posRemainder(y1, p));
        }
        static Tuple<BigInteger, BigInteger> montgToWS(Tuple<BigInteger, BigInteger> Q, int conv)
        {
            return new Tuple<BigInteger, BigInteger>(Q.Item1 + conv, Q.Item2);
        }
        static Tuple<BigInteger, BigInteger> montgPtToWS(BigInteger x, int conv, BigInteger Ea, BigInteger GF, System.Security.Cryptography.RNGCryptoServiceProvider rng)
        {
            return new Tuple<BigInteger, BigInteger>(x + conv, TonelliShanks(rng, posRemainder(x * x * x + Ea * x * x + x, GF), GF));
            //TonelliShanks(rng, posRemainder((x + 178) * (x + 178) * (x + 178) + EaOrig * (x + 178) + Eb, GF), GF)
        }
        static Tuple<BigInteger, BigInteger> WSToMontg(Tuple<BigInteger, BigInteger> Q, int conv)
        {
            return new Tuple<BigInteger, BigInteger>(Q.Item1 - conv, Q.Item2);
        }
        static Tuple<BigInteger, BigInteger> signECDSA(RNGCryptoServiceProvider rng, BigInteger m, BigInteger d, BigInteger n, Tuple<BigInteger, BigInteger> G, int Ea, BigInteger GF)
        {
            BigInteger k, r, s;
            do {
                do {
                    do { k = Crypto.GetNextRandomBig(rng, n); } while (k <= 1);
                    r = scaleEC(G, k, Ea, GF).Item1;
                } while (r.Equals(BigInteger.Zero));
                s = BigInteger.Remainder((m + d * r) * modInverse(k, n), n);
            } while (s.Equals(BigInteger.Zero));
            return new Tuple<BigInteger, BigInteger>(r, s);
        }
        static bool verifyECDSA(BigInteger m, Tuple<BigInteger, BigInteger> rs, Tuple<BigInteger, BigInteger> Q, BigInteger n, Tuple<BigInteger, BigInteger> G, int Ea, BigInteger GF)
        {
            BigInteger inv = modInverse(rs.Item2, n), u1 = BigInteger.Remainder(m * inv, n), u2 = BigInteger.Remainder(rs.Item1 * inv, n);
            return rs.Item1.Equals(addEC(scaleEC(G, u1, Ea, GF), scaleEC(Q, u2, Ea, GF), Ea, GF).Item1);
        }
        static Tuple<BigInteger, BigInteger> signECDSAbiased(RNGCryptoServiceProvider rng, BigInteger m, BigInteger d, BigInteger n, Tuple<BigInteger, BigInteger> G, int Ea, BigInteger GF)
        {
            BigInteger k, r, s;
            do
            {
                do
                {
                    do { k = Crypto.GetNextRandomBig(rng, n); } while (k <= 1);
                    k -= (k & 255);
                    r = scaleEC(G, k, Ea, GF).Item1;
                } while (r.Equals(BigInteger.Zero));
                s = BigInteger.Remainder((m + d * r) * modInverse(k, n), n);
            } while (s.Equals(BigInteger.Zero));
            return new Tuple<BigInteger, BigInteger>(r, s);
        }
        static BigInteger rhog(BigInteger x, BigInteger n)
        {
            return BigInteger.Remainder(x * x + 1, n);
        }
        static BigInteger PollardRho(BigInteger n)
        {
            //128 bit integer has maximum factor of 64 bits
            int limit = 1 << 16; //sqrt(factor) time would imply 2^32 maximum but we dont want factors over 2^24 which averages to 2^12 iterations maximum, and increase 2^4 more so its less than 1/16 of missing it
            BigInteger x = 2, y = 2, d = 1;
            while (d.Equals(BigInteger.One)) {
                x = rhog(x, n);
                y = rhog(rhog(y, n), n);
                d = BigInteger.GreatestCommonDivisor(BigInteger.Abs(x - y), n);
                limit--; if (limit == 0) return 0;
            }
            if (d.Equals(n)) {
                return 0;
            } else {
                return d;
            }
        }
        static List<BigInteger> PollardRhoAll(BigInteger n)
        {
            List<BigInteger> facs = new List<BigInteger>();
            do {
                BigInteger fac = PollardRho(n);
                if (fac.Equals(BigInteger.Zero)) break;
                if (fac.IsPowerOfTwo) fac = 2; else if (!IsProbablePrime(fac, 64)) break;
                facs.Add(fac);
                n = n / fac;
                BigInteger remainder, quot = BigInteger.DivRem(n, fac, out remainder);
                while (remainder.Equals(BigInteger.Zero)) {
                    if (fac != 2) return new List<BigInteger>(); //if repeated factor is not 2, should abort
                    n = quot;
                    quot = BigInteger.DivRem(n, fac, out remainder);
                }
                if (IsProbablePrime(n, 64)) {
                    facs.Add(n); return facs;
                }
            } while (true);
            facs.Clear(); return facs;
        }
        static List<Tuple<BigInteger, BigInteger>> proj(List<Tuple<BigInteger, BigInteger>> u, List<Tuple<BigInteger, BigInteger>> v)
        {
            if (u.All((Tuple<BigInteger, BigInteger> el) => el.Item1 == 0)) return u;
            Tuple<BigInteger, BigInteger> m = mu(v, u);
            return u.Select((Tuple<BigInteger, BigInteger> el) => new Tuple<BigInteger, BigInteger>(m.Item1 * el.Item1, m.Item2 * el.Item2)).ToList();
        }
        static List<List<Tuple<BigInteger, BigInteger>>> gramschmidt(List<List<Tuple<BigInteger, BigInteger>>> B, List<List<Tuple<BigInteger, BigInteger>>> Q)
        {
            if (Q == null) Q = new List<List<Tuple<BigInteger, BigInteger>>>();
            if (Q.Count == 0 && B.Count != 0) Q.Add(B[0]);
            for (int i = Q.Count; i < B.Count; i++) {
                List<Tuple<BigInteger, BigInteger>> v = B[i];
                List<Tuple<BigInteger, BigInteger>> p = Q.Select((u) => proj(u, v)).Aggregate((b, t) => t.Zip(b, (s, a) => new Tuple<BigInteger, BigInteger>(s.Item1 * a.Item2 + s.Item2 * a.Item1, s.Item2 * a.Item2)).ToList()).ToList();
                Q.Add(v.Zip(p, (t, s) => reducFrac(new Tuple<BigInteger, BigInteger>(t.Item1 * s.Item2 - t.Item2 * s.Item1, t.Item2 * s.Item2))).ToList());
            }
            return Q;
        }
        static Tuple<BigInteger, BigInteger> reducFrac(Tuple<BigInteger, BigInteger> j)
        { //negative numerator and denominator could also be removed
            if (j.Item1 == 0) return new Tuple<BigInteger, BigInteger>(0, 1);
            BigInteger gcd = BigInteger.GreatestCommonDivisor(j.Item1, j.Item2);
            return new Tuple<BigInteger, BigInteger>(j.Item1 / gcd, j.Item2 / gcd);
        }
        static Tuple<BigInteger, BigInteger> vecSqr(List<Tuple<BigInteger, BigInteger>> j)
        {
            //a1^2/b1^2 + ... + an^2/bn^2
            //an^2*accb+acca*bn^2/bn^2*accb
            return reducFrac(j.Select((u) => new Tuple<BigInteger, BigInteger>(u.Item1 * u.Item1, u.Item2 * u.Item2)).Aggregate((Tuple<BigInteger, BigInteger> acc, Tuple<BigInteger, BigInteger> val) => new Tuple<BigInteger, BigInteger>(acc.Item1 * val.Item2 + val.Item1 * acc.Item2, val.Item2 * acc.Item2)));
        }
        static Tuple<BigInteger, BigInteger> mu(List<Tuple<BigInteger, BigInteger>> i, List<Tuple<BigInteger, BigInteger>> j)
        {
            Tuple<BigInteger, BigInteger> uv = i.Zip(j, (u, v) => new Tuple<BigInteger, BigInteger>(u.Item1 * v.Item1, u.Item2 * v.Item2)).Aggregate((Tuple<BigInteger, BigInteger> acc, Tuple<BigInteger, BigInteger> val) => new Tuple<BigInteger, BigInteger>(acc.Item1 * val.Item2 + val.Item1 * acc.Item2, val.Item2 * acc.Item2));
            Tuple<BigInteger, BigInteger> u2 = vecSqr(j);
            return reducFrac(new Tuple<BigInteger, BigInteger>(uv.Item1 * u2.Item2, uv.Item2 * u2.Item1));
        }
        static List<List<Tuple<BigInteger, BigInteger>>> LLL(List<List<Tuple<BigInteger, BigInteger>>> B, Tuple<BigInteger, BigInteger> delta)
        {
            List<List<Tuple<BigInteger, BigInteger>>> Q = gramschmidt(B, null);
            int n = B.Count;
            int k = 1;
            while (k < n) {
                for (int j = k - 1; j >= 0; j--) {
                    //for (int j = 0; j <= k-1; j++) {
                    Tuple<BigInteger, BigInteger> mjk = mu(B[k], Q[j]); //mu(k,j) >= 0 ? > 1/2 : < -1/2, !(-1/2 >= mu(k,j) <= 1/2)
                    BigInteger mjk2 = mjk.Item1 * 2;
                    if ((mjk2 - mjk.Item2) > 0 || (mjk2 + mjk.Item2) < 0)
                    { //rounding by adding half of divisor before lbound dividing round(a/b)=lbound(a/b+1/2)=lbound((2a+b)/2b)
                        //BigInteger mjkRnd = ((2 * mjk.Item1 + mjk.Item2) / (2 * mjk.Item2)); //round down on tie semantics but this wrongly forgets negatives
                        BigInteger mjkRem, mjkRnd = BigInteger.DivRem(mjk.Item1, mjk.Item2, out mjkRem); //proper round down on tie semantics
                        BigInteger mjkRem2 = mjkRem * 2;
                        mjkRnd += (mjkRem2 > mjk.Item2 ? 1 : (mjkRem2 < -mjk.Item2 ? -1 : 0));
                        List<Tuple<BigInteger, BigInteger>> test = B[k].Zip(B[j], (u, v) => reducFrac(new Tuple<BigInteger, BigInteger>(u.Item1 * v.Item2 - u.Item2 * v.Item1 * mjkRnd, u.Item2 * v.Item2))).ToList();
                        B[k] = test;
                        Q = gramschmidt(B, Q.Take(k - 1).ToList());
                    }
                }
                Tuple<BigInteger, BigInteger> m = mu(B[k], Q[k - 1]);
                Tuple<BigInteger, BigInteger> Qkm1 = vecSqr(Q[k - 1]);
                Tuple<BigInteger, BigInteger> Qsqr = vecSqr(Q[k]);
                BigInteger mi2 = m.Item2 * m.Item2;
                Tuple<BigInteger, BigInteger> Cmp = new Tuple<BigInteger, BigInteger>((delta.Item1 * mi2 - delta.Item2 * m.Item1 * m.Item1) * Qkm1.Item1, delta.Item2 * mi2 * Qkm1.Item2);
                //a/b>=c/d === ad>=bc
                if (Qsqr.Item1 * Cmp.Item2 - Qsqr.Item2 * Cmp.Item1 >= 0) {
                    k++;
                } else {
                    if (!B[k].SequenceEqual(B[k - 1])) {
                        List<Tuple<BigInteger, BigInteger>> swap = B[k];
                        B[k] = B[k - 1];
                        B[k - 1] = swap;
                        k = Math.Max(k - 1, 1);
                        Q = gramschmidt(B, Q.Take(k - 1).ToList());
                    } else k = Math.Max(k - 1, 1);
                }
            }
            return B;
        }
        static BigInteger addGF2(BigInteger A, BigInteger B)
        {
            return A ^ B;
        }
        static BigInteger mulGF2(BigInteger A, BigInteger B)
        {
            BigInteger p = 0;
            while (A > 0) {
                if ((A & 1) != BigInteger.Zero) p = p ^ B;
                A = A >> 1; B = B << 1;
            }
            return p;
        }
        static Tuple<BigInteger, BigInteger> divmodGF2(BigInteger A, BigInteger B)
        {
            BigInteger q = BigInteger.Zero, r = A; int d;
            int Bsz = GetBitSize(B);
            while ((d = GetBitSize(r) - Bsz) >= 0) {
                q = q ^ (BigInteger.One << d); r = r ^ (B << d);
            }
            return new Tuple<BigInteger, BigInteger>(q, r);
        }
        //M=x^4 + x + 1, 1100(1)=C
        //M=x^128 + x^7 + x^2 + x + 1
        //leftmost bit is the coefficient of x^0 so reverse bits E100 0000 0000 0000 0000 0000 0000 0000
        static BigInteger modmulGF2k(BigInteger A, BigInteger B, BigInteger M)
        {
            //BigInteger p = mulGF2(A, B);
            //return divmodGF2(p, M).Item2;
            BigInteger p = 0;
            int Msz = GetBitSize(M), Bsz = GetBitSize(B);
            while (A > 0) {
                if ((A & 1) != BigInteger.Zero) p = p ^ B;
                A = A >> 1; B = B << 1;
                if (++Bsz == Msz) { B = B ^ M; Bsz = GetBitSize(B); }
            }
            return p;
        }
        static BigInteger modinvGF2k(BigInteger a, BigInteger n)
        {
            BigInteger M = BigInteger.Parse("0100000000000000000000000000000087", System.Globalization.NumberStyles.HexNumber); //00E1000000000000000000000000000000 00E100000000000000000000000000000080 0100000000000000000000000000000087
            BigInteger i = n, v = 0, d = 1;
            while (a > 0)
            {
                BigInteger t = divmodGF2(i, a).Item1, x = a;
                a = divmodGF2(i, x).Item2;
                i = x;
                x = d;
                d = addGF2(v, modmulGF2k(t, x, M)); //this could just as equivalently be replaced with a simpler mulGF2k(t, x)
                v = x;
            }
            v = divmodGF2(v, n).Item2;
            if (v < 0) v = addGF2(v, n) % n;
            return v;
        }
        static BigInteger modexpGF2k(BigInteger A, BigInteger B, BigInteger M)
        {
            //naive way for comparison
            //BigInteger dc = 1;
            //for (int i = 0; i < B; i++) {
            //dc = modmulGF2k(dc, A, M);
            //}
            BigInteger d = BigInteger.One;
            int bs = GetBitSize(B);
            for (int i = bs; i > 0; i--) {
                if (((BigInteger.One << (bs - i)) & B) != 0) {
                    d = modmulGF2k(d, A, M);
                }
                A = modmulGF2k(A, A, M);
            }
            return d;
        }
        public static byte ReverseBitsWith4Operations(byte b)
        {
            return (byte)(((b * 0x80200802ul) & 0x0884422110ul) * 0x0101010101ul >> 32);
        }
        static BigInteger calc_gcm_s(byte[] nonce, BigInteger h, byte[] cyphText, byte[] authData, BigInteger tag)
        {
            BigInteger g = BigInteger.Zero, M = BigInteger.Parse("0100000000000000000000000000000087", System.Globalization.NumberStyles.HexNumber); //00E1000000000000000000000000000000 00E100000000000000000000000000000080 0100000000000000000000000000000087
            byte[] padAuthData = authData.Concat(Enumerable.Repeat((byte)0, (16 - (authData.Length % 16)) % 16)).ToArray();
            byte[] padCyphText = cyphText.Concat(Enumerable.Repeat((byte)0, (16 - (cyphText.Length % 16)) % 16)).ToArray();
            for (ulong ctr = 0; (int)ctr < padAuthData.Length; ctr += 16)
            { //zero pad to block align
                g = modmulGF2k(addGF2(g, new BigInteger(padAuthData.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray())), h, M);
            }
            for (ulong ctr = 0; (int)ctr < padCyphText.Length; ctr += 16)
            { //zero pad to block align
                g = modmulGF2k(addGF2(g, new BigInteger(padCyphText.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray())), h, M);
            }
            g = modmulGF2k(addGF2(g, new BigInteger(BitConverter.GetBytes((ulong)authData.Length * 8).Reverse().Concat(BitConverter.GetBytes((ulong)cyphText.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray())), h, M);
            return addGF2(g, tag); //tag = g + s, s = tag - g
        }
        static BigInteger calc_gcm_tag(byte[] nonce, byte[] key, byte[] cyphText, byte[] authData)
        {
            BigInteger h = new BigInteger(encrypt_ecb(key, Enumerable.Repeat((byte)0, 16).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()); //authentication key
            BigInteger g = BigInteger.Zero, M = BigInteger.Parse("0100000000000000000000000000000087", System.Globalization.NumberStyles.HexNumber); //00E1000000000000000000000000000000 00E100000000000000000000000000000080 0100000000000000000000000000000087
            byte[] padAuthData = authData.Concat(Enumerable.Repeat((byte)0, (16 - (authData.Length % 16)) % 16)).ToArray();
            byte[] padCyphText = cyphText.Concat(Enumerable.Repeat((byte)0, (16 - (cyphText.Length % 16)) % 16)).ToArray();
            for (ulong ctr = 0; (int)ctr < padAuthData.Length; ctr += 16) { //zero pad to block align
                g = modmulGF2k(addGF2(g, new BigInteger(padAuthData.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray())), h, M);
            }
            for (ulong ctr = 0; (int)ctr < padCyphText.Length; ctr += 16) { //zero pad to block align
                g = modmulGF2k(addGF2(g, new BigInteger(padCyphText.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray())), h, M);
            }
            g = modmulGF2k(addGF2(g, new BigInteger(BitConverter.GetBytes((ulong)authData.Length * 8).Reverse().Concat(BitConverter.GetBytes((ulong)cyphText.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray())), h, M);
            BigInteger s = new BigInteger(encrypt_ecb(key, nonce.Concat(BitConverter.GetBytes((int)1).Reverse()).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
            BigInteger t = addGF2(g, s);
            return t;
        }
        static BigInteger calc_gcm_tag_fastlib(BigInteger M, byte[] nonce, byte[] key, byte [] cyphData)
        {
            //this is a trick to get a tag when cypher data is known by passing it as auth data and a 0 byte final block transform, then reversing the last steps and reperforming them with the length adjusted correctly for cypher data not auth data
            //library is much faster than a C# GCM implementation due to excessive modmulGF2k calls
            Security.Cryptography.AuthenticatedAesCng aes = new Security.Cryptography.AuthenticatedAesCng();
            aes = new Security.Cryptography.AuthenticatedAesCng();
            aes.CngMode = Security.Cryptography.CngChainingMode.Gcm;
            aes.Key = key;
            aes.IV = nonce;
            aes.AuthenticatedData = null;
            Security.Cryptography.IAuthenticatedCryptoTransform aesgcm;
            aesgcm = aes.CreateAuthenticatedEncryptor(aes.Key, aes.IV, cyphData);
            aesgcm.TransformFinalBlock(new byte[] { }, 0, 0);
            byte [] Tag = aesgcm.GetTag().ToArray(); //32-bit MAC
            BigInteger t = new BigInteger(Tag.Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());

            BigInteger h = new BigInteger(encrypt_ecb(key, Enumerable.Repeat((byte)0, 16).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()); //authentication key
            BigInteger s = new BigInteger(encrypt_ecb(key, nonce.Concat(BitConverter.GetBytes((int)1).Reverse()).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());

            BigInteger g = addGF2(t, s);
            g = modmulGF2k(g, modinvGF2k(h, M), M);
            g = addGF2(g, new BigInteger(BitConverter.GetBytes((ulong)cyphData.Length * 8).Reverse().Concat(BitConverter.GetBytes((ulong)0).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()));

            g = modmulGF2k(addGF2(g, new BigInteger(BitConverter.GetBytes((ulong)0).Reverse().Concat(BitConverter.GetBytes((ulong)cyphData.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray())), h, M);
            return addGF2(g, s);
        }
        static BigInteger calc_gcm_tag_squares(byte[] nonce, byte[] key, byte[] cyphText, byte[] authData)
        {
            BigInteger h = new BigInteger(encrypt_ecb(key, Enumerable.Repeat((byte)0, 16).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()); //authentication key
            BigInteger g = BigInteger.Zero, M = BigInteger.Parse("0100000000000000000000000000000087", System.Globalization.NumberStyles.HexNumber); //00E1000000000000000000000000000000 00E100000000000000000000000000000080 0100000000000000000000000000000087
            byte[] padAuthData = authData.Concat(Enumerable.Repeat((byte)0, (16 - (authData.Length % 16)) % 16)).ToArray();
            byte[] padCyphText = cyphText.Concat(Enumerable.Repeat((byte)0, (16 - (cyphText.Length % 16)) % 16)).ToArray();
            for (ulong ctr = 0; (int)ctr < padAuthData.Length; ctr += 16)
            { //zero pad to block align
                g = modmulGF2k(addGF2(g, new BigInteger(padAuthData.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray())), h, M);
            }
            for (ulong ctr = 0; (int)ctr < padCyphText.Length; ctr += 16)
            { //zero pad to block align
                int v = (padCyphText.Length - (int)ctr) / 16 + 1;
                v = v - ((v >> 1) & 0x55555555);                    // reuse input as temporary
                v = (v & 0x33333333) + ((v >> 2) & 0x33333333);     // temp
                int c = ((v + (v >> 4) & 0xF0F0F0F) * 0x1010101) >> 24; // count
                if (c != 1) {
                    g = modmulGF2k(g, h, M);
                } else {
                    g = modmulGF2k(addGF2(g, new BigInteger(padCyphText.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray())), h, M);
                    //BigInteger tmp = new BigInteger(padCyphText.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
                    //for (int ct = padCyphText.Length; ct >= (int)ctr; ct -= 16)
                    //    tmp = modmulGF2k(tmp, h, M);
                    //Console.WriteLine(ctr + " " + ((padCyphText.Length - (int)ctr) / 16 + 1) + " " + g + " " + tmp);
                }
            }
            g = modmulGF2k(addGF2(g, new BigInteger(BitConverter.GetBytes((ulong)authData.Length * 8).Reverse().Concat(BitConverter.GetBytes((ulong)cyphText.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray())), h, M);
            //Console.WriteLine(g + " " + modmulGF2k(new BigInteger(BitConverter.GetBytes((ulong)authData.Length * 8).Reverse().Concat(BitConverter.GetBytes((ulong)cyphText.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()), h, M));
            //BigInteger s = new BigInteger(encrypt_ecb(key, nonce.Concat(BitConverter.GetBytes((int)1).Reverse()).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
            //BigInteger t = addGF2(g, s);
            return g;
        }
        static byte[] crypt_gcm(byte [] nonce, byte[] key, byte[] input)
        {
            byte[] o = new byte[input.Length];
            for (uint ctr = 0; ctr < input.Length; ctr += 16) { //zero pad to block align
                //BitConverter uses little endian order
                FixedXOR(input.Skip((int)ctr).Take(Math.Min(input.Length - (int)ctr, 16)).ToArray(), encrypt_ecb(key, nonce.Concat(BitConverter.GetBytes(ctr / 16 + 2).Reverse()).ToArray()).ToArray().Take(Math.Min(input.Length - (int)ctr, 16)).ToArray()).CopyTo(o, (int)ctr);
            }
            return o;
        }
        static Tuple<byte[], BigInteger> crypt_gcm_fastlib(byte [] nonce, byte[] key, byte[] input, byte[] authData)
        {
            Security.Cryptography.AuthenticatedAesCng aes = new Security.Cryptography.AuthenticatedAesCng();
            aes = new Security.Cryptography.AuthenticatedAesCng();
            aes.CngMode = Security.Cryptography.CngChainingMode.Gcm;
            aes.Key = key;
            aes.IV = nonce;
            aes.AuthenticatedData = authData;
            Security.Cryptography.IAuthenticatedCryptoTransform aesgcm = aes.CreateAuthenticatedEncryptor();
            byte [] cyphData = new byte[(input.Length - 1) / 16 * 16];
            for (int i = 0; i < input.Length; i += 16)
            {
                if (i + 16 >= input.Length) cyphData = cyphData.Concat(aesgcm.TransformFinalBlock(input, i, input.Length - i)).ToArray();
                else aesgcm.TransformBlock(input, i, 16, cyphData, i);
            }
            byte [] VerifyTag = aesgcm.GetTag().ToArray();
            BigInteger tag = new BigInteger(VerifyTag.Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
            return new Tuple<byte[], BigInteger>(cyphData, tag);
        }
        static BigInteger[] addGFE2k(BigInteger[] a, BigInteger[] b)
        {
            BigInteger[] c = new BigInteger[Math.Max(a.Length, b.Length)];
            for (int i = 0; i < c.Length; i++) {
                if (i >= a.Length) c[c.Length - 1 - i] = b[b.Length - 1 - i];
                else if (i >= b.Length) c[c.Length - 1 - i] = a[a.Length - 1 - i];
                else c[c.Length - 1 - i] = addGF2(a[a.Length - 1 - i], b[b.Length - 1 - i]);
            }
            return c.Skip(c.TakeWhile((BigInteger cr) => cr == BigInteger.Zero).Count()).ToArray(); ;
        }
        static BigInteger[] mulGFE2k(BigInteger[] A, BigInteger[] B)
        {
            BigInteger M = BigInteger.Parse("0100000000000000000000000000000087", System.Globalization.NumberStyles.HexNumber); //00E1000000000000000000000000000000 00E100000000000000000000000000000080 0100000000000000000000000000000087
            if (A.Length == 0) return A; if (B.Length == 0) return B;
            BigInteger[] p = new BigInteger[A.Length + B.Length - 1];
            for (int i = 0; i < B.Length; i++) {
                for (int j = 0; j < A.Length; j++) {
                    p[i + j] = addGF2(modmulGF2k(A[j], B[i], M), p[i + j]);
                }
            }
            //while (!A.All((BigInteger c) => c == BigInteger.Zero)) {
            //    if (A[0] != BigInteger.Zero) p = addGFE2k(p, B);
            //    A = A.Skip(1).ToArray(); B = B.Concat(new BigInteger[] { BigInteger.Zero }).ToArray();
            //}
            return p.Skip(p.TakeWhile((BigInteger c) => c == BigInteger.Zero).Count()).ToArray();
        }
        //https://en.wikipedia.org/wiki/Polynomial_long_division#Pseudo-code
        static Tuple<BigInteger[], BigInteger[]> divmodGFE2k(BigInteger[] A, BigInteger[] B)
        {
            //if (B.Length == 0) throw;
            BigInteger[] q = new BigInteger[A.Length], r = A; int d;
            while (r.Length != 0 && (d = (r.Count() - 1) - (B.Count() - 1)) >= 0) {
                q[A.Length - d - 1] = divmodGF2(r[0], B[0]).Item1;
                if (q[A.Length - d - 1] == BigInteger.Zero) break;
                r = addGFE2k(r, mulGFE2k(q.Skip(A.Length - d - 1).ToArray(), B));
            }
            return new Tuple<BigInteger[], BigInteger[]>(q.Skip(q.TakeWhile((BigInteger c) => c == BigInteger.Zero).Count()).ToArray(), r);
        }
        static BigInteger [] modinvGFE2k(BigInteger[] a, BigInteger[] n) //should now be working but untested - final adjustment difference in polynomials was not present
        {
            BigInteger M = BigInteger.Parse("0100000000000000000000000000000087", System.Globalization.NumberStyles.HexNumber); //00E1000000000000000000000000000000 00E100000000000000000000000000000080 0100000000000000000000000000000087
            BigInteger[] i = n, v = new BigInteger[] { BigInteger.Zero }, d = new BigInteger[] { BigInteger.One };
            while (!a.All((BigInteger c) => c == BigInteger.Zero)) {
                BigInteger [] t = divmodGFE2k(i, a).Item1, x = a;
                a = divmodGFE2k(i, x).Item2;
                i = x;
                x = d;
                d = addGFE2k(v, mulGFE2k(t, x));
                v = x;
            }
            v = mulGFE2k(new BigInteger[] { modinvGF2k(i[0], M) }, v);
            v = divmodGFE2k(v, n).Item2;
            //if (v < 0) v = addGFE2k(v, n) % n;
            return v;

        }
        //https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
        //https://en.wikipedia.org/wiki/Polynomial_greatest_common_divisor#Bézout's_identity_and_extended_GCD_algorithm
        static BigInteger[] gcdGFE2k(BigInteger[] a, BigInteger[] b)
        {
            BigInteger M = BigInteger.Parse("0100000000000000000000000000000087", System.Globalization.NumberStyles.HexNumber); //00E1000000000000000000000000000000 00E100000000000000000000000000000080 0100000000000000000000000000000087
            BigInteger[] r = a, ro = b;
            BigInteger[] s = new BigInteger[] { BigInteger.Zero }, so = new BigInteger[] { BigInteger.One };
            BigInteger[] t = new BigInteger[] { BigInteger.One }, to = new BigInteger[] { BigInteger.Zero };
            while (r.Length != 0) {
                if (r[0] != BigInteger.One) { //must be monic or division will not be correct!
                    BigInteger multiplier = modinvGF2k(r[0], M);
                    r = mulGFE2k(r, new BigInteger[] { multiplier });
                }
                BigInteger[] quot = divmodGFE2k(ro, r).Item1;
                BigInteger[] swap = ro;
                ro = r; r = addGFE2k(swap, mulGFE2k(quot, r));
                swap = so;
                so = s; s = addGFE2k(swap, mulGFE2k(quot, s));
                swap = to;
                to = t; t = addGFE2k(swap, mulGFE2k(quot, t));
            }
            return ro;
        }
        //characteristic of GF(2) is 2 hence non-zero and the following algorithm:
        //https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Square-free_factorization
        static List<BigInteger[]> sqrFree(BigInteger[] f) //Yun's algorithm, g is monic polynomial
        {
            BigInteger[] fprime = new BigInteger[f.Length];
            List<BigInteger[]> R = new List<BigInteger[]>();
            //R.Add(new BigInteger[] { BigInteger.One });
            int i;
            for (i = 0; i < f.Length - 1; i++) {
                fprime[i + 1] = ((i + 1) & 1) != 0 ? addGF2(f[i], f[i]) : f[i]; //formal derivative f', not using multiplication in the ring but addition
            }
            BigInteger[] c = gcdGFE2k(f, fprime.Skip(fprime.TakeWhile((BigInteger cr) => cr == BigInteger.Zero).Count()).ToArray()), w = divmodGFE2k(f, c).Item1;
            i = 0; //Step 1: Identify all factors in w
            while (w.Length != 1 || w[0] != BigInteger.One) {
                BigInteger[] y = gcdGFE2k(w, c);
                BigInteger[] fac = divmodGFE2k(w, y).Item1;
                R.Add(fac); //to the ith power
                w = y; c = divmodGFE2k(c, y).Item1; i++;
            }
            //c is now the product (with multiplicity) of the remaining factors of f
            //Step 2: Identify all remaining factors using recursion
            //Note that these are the factors of f that have multiplicity divisible by p
            if (c.Length != 1 || c[0] != BigInteger.One) {
                c = c.Where((cr, idx) => (idx & 1) == 0).ToArray(); // c=c^(1/p) where q=p^m=2^128
                //square root of polynomial
                //completed by applying the inverse of the Frobenius automorphism to the coefficients
                //e.g. divide all polynomial exponents by p=2, hence all the even coefficients        
                R.AddRange(sqrFree(c)); //to the pth=2 power
            }
            return R;
        }
        //M=2^m
        static BigInteger [] repSqr(BigInteger [] X, BigInteger m, BigInteger [] f)
        {
            BigInteger[] gl = X;
            for (int i = 1; i <= m; i++) {
                gl = divmodGFE2k(mulGFE2k(gl, gl), f).Item2;
            }
            return gl;
        }
        static BigInteger [] modexpGFE2k(BigInteger[] X, BigInteger m, BigInteger[] f)
        {
            BigInteger [] d = { BigInteger.One };
            int bs = GetBitSize(m);
            for (int i = bs; i > 0; i--) {
                if (((BigInteger.One << (bs - i)) & m) != 0) {
                    d = divmodGFE2k(mulGFE2k(d, X), f).Item2;
                }
                X = divmodGFE2k(mulGFE2k(X, X), f).Item2;
            }
            return d;
        }
        static Tuple<BigInteger[], int>[] ddf(BigInteger[] f)
        {
            int i = 1;
            List<Tuple<BigInteger[], int>> S = new List<Tuple<BigInteger[], int>>();
            BigInteger[] fs = f;
            BigInteger[] lSqr = new BigInteger[] { BigInteger.One, BigInteger.Zero };
            while (fs.Length >= 2 * i) {
                //x^(q^i)-x where F_q[X]=F_(2^128)[X]
                //must use repeated squaring to calculate X^M mod f
                //addGFE2k(repSqr(new BigInteger[] { BigInteger.One, BigInteger.Zero }, new BigInteger(7), fs), new BigInteger[] { BigInteger.One, BigInteger.Zero }); //128=2^7
                //BigInteger[] g = gcdGFE2k(fs, addGFE2k(repSqr(new BigInteger[] { BigInteger.One, BigInteger.Zero }, new BigInteger(128) * i, fs), new BigInteger[] { BigInteger.One, BigInteger.Zero }));
                lSqr = modexpGFE2k(lSqr, BigInteger.One << 128, fs);
                //lSqr = repSqr(lSqr, new BigInteger(128), fs); //instead of starting over, just do additional 128 each time
                BigInteger[] g = gcdGFE2k(fs, addGFE2k(lSqr, new BigInteger[] { BigInteger.One, BigInteger.Zero }));
                if (g.Length != 1 || g[0] != BigInteger.One) {
                    S.Add(new Tuple<BigInteger[], int>(g, i));
                    fs = divmodGFE2k(fs, g).Item1;
                }
                i++;
            }
            if (fs.Length != 1 || fs[0] != BigInteger.One) {
                S.Add(new Tuple<BigInteger[], int>(fs, fs.Length - 1));
            }
            if (S.Count == 0) S.Add(new Tuple<BigInteger[], int>(f, 1));
            return S.ToArray();
        }
        static BigInteger[][] edf(RandomNumberGenerator rng, BigInteger[] f, int d)
        {
            int n = f.Length - 1;
            int r = n / d;
            List<BigInteger[]> S = new List<BigInteger[]>();
            S.Add(f);
            while (S.Count < r) {
                BigInteger[] h = new BigInteger[f.Length - 1]; // deg(h) < n
                //random_polynomial(1, f);
                h[0] = 1; //h is monic
                for (int i = 1; i < f.Length - 1; i++) {
                    do {
                        h[i] = GetNextRandomBig(rng, (BigInteger.One << 128) - 1);
                    } while (h[i] < BigInteger.Zero);
                }
                BigInteger[] g = gcdGFE2k(h, f);
                if (g.Length == 1 && g[0] == BigInteger.One) {
                    g = addGFE2k(modexpGFE2k(h, ((BigInteger.One << (128 * d)) - 1) / 3, f), new BigInteger[] { BigInteger.One });
                }
                for (int i = 0; i < S.Count; i++) {
                    BigInteger[] u = S[i];
                    //implicitly apply the Chinese Remainder Theorem
                    if (u.Length - 1 == d) continue;
                    BigInteger[] gcd = gcdGFE2k(g, u);
                    if ((gcd.Length != 1 || gcd[0] != BigInteger.One) && !gcd.SequenceEqual(u)) {
                        S.Remove(u);
                        S.Add(gcd);
                        S.Add(divmodGFE2k(u, gcd).Item1);
                    }
                }
            }
            return S.ToArray();
        }
        static bool [,] matmul(bool [,] x, bool [,] y)
        {
            int m = x.GetLength(1);
            if (m != y.GetLength(0)) return null;
            int l = x.GetLength(0);
            int n = y.GetLength(1);
            bool[,] ret = new bool[l, n];
            for (int outcol = 0; outcol < n; outcol++) {
                for (int row = 0; row < l; row++) {
                    bool val = false;
                    for (int col = 0; col < m; col++) {
                        val ^= x[row, col] & y[col, outcol];
                    }
                    ret[row, outcol] = val;
                }
            }
            return ret;
        }
        static bool [,] matsum(bool [,] x, bool [,] y)
        {
            int m = x.GetLength(0);
            int n = x.GetLength(1);
            if (m != y.GetLength(0) || n != y.GetLength(1)) return null;
            bool[,] ret = new bool[m, n];
            for (int row = 0; row < m; row++) {
                for (int col = 0; col < n; col++) {
                    ret[row, col] = x[row, col] ^ y[row, col];
                }
            }
            return ret;
        }
        static bool [,] transpose(bool [,] x)
        {
            int m = x.GetLength(0);
            int n = x.GetLength(1);
            bool[,] ret = new bool[n, m];
            for (int row = 0; row < m; row++) {
                for (int col = 0; col < n; col++) {
                    ret[col, row] = x[row, col];
                }
            }
            return ret;
        }
        //problem description seems to forget to mention a new matrix augmented with identity matrix
        static bool[,] augmentIdentityMat(bool[,] x)
        {
            int m = x.GetLength(0);
            int n = x.GetLength(1);
            bool[,] res = new bool[m, n + m];
            for (int i = 0; i < m; i++) {
                for (int col = 0; col < n; col++) {
                    res[i, col] = x[i, col];
                }
            }
            for (int i = 0; i < m; i++) {
                res[i, i + n] = true;
            }
            return res;
        }
        static bool[,] extractBasisMat(bool [,] x)
        {
            int m = x.GetLength(0);
            int n = x.GetLength(1) - m;
            int ci;
            for(ci = 0; ci < m; ci++) {
                int col;
                for (col = 0; col < n; col++) {
                    if (x[ci, col]) break;
                }
                if (col == n) break;
            }
            bool[,] res = new bool[m - ci, m];
            for (int i = 0; ci < m; i++, ci++) {
                for (int col = 0; col < m; col++) {
                    res[i, col] = x[ci, col + n];
                }
            }
            return res;
        }
        static bool [,] gaussianElim(bool [,] x)
        {
            //bool[,] ret = new bool[x.GetLength(0), x.GetLength(1)];
            //algorithm here is in place
            int h = 0; //Initialization of pivot row
            int k = 0; //Initialization of pivot column
            int m = x.GetLength(0);
            int n = x.GetLength(1);
            bool[,] vect = new bool[1, n];
            while (h < m && k < n) {
                //Find the k-th pivot
                int i_max = Enumerable.Range(h, m - h + 1 - 1).Where((int i) => x[i, k]).FirstOrDefault(); //index of maximum which is first one with a bit set, also should consider absolute value but here its not applicable since no negative values though zero still possible
                if (x[i_max, k] == false || i_max < h) //No pivot in this column, pass to next column
                    k++;
                else {
                    //swap rows h and i_max
                    if (h != i_max) {
                        Array.Copy(x, i_max * n, vect, 0, n);
                        Array.Copy(x, h * n, x, i_max * n, n);
                        Array.Copy(vect, 0, x, h * n, n);
                        /*for (int col = 0; col < n; col++) {
                            x[i_max, col] ^= x[h, col];
                            x[h, col] ^= x[i_max, col];
                            x[i_max, col] ^= x[h, col];
                        }*/
                    }
                    //Do for all rows below pivot
                    //for (int i = h + 1; i < m; i++) {
                    //reduced row echelon form (RREF) is obtained without a back substitution step by starting from 0 and skipping h
                    for (int i = 0; i < m; i++) {
                        if (h == i) continue;
                        //if (!x[i, k] || !x[h, k]) continue;
                        //000, 010, 100, 111 where a*b=c is a&b=c, then a=c/b, a=c|!b but this seems ambiguous as !b&!c has two values of both true and false for a, but x[i, k] is certainly c - the divisor
                        //and x[h, k] cannot contain 0 as the swap operation and i_max selection above guarantee it must in this case be one and therefore irrelevant
                        bool f = x[i, k]; //division by x[h, k] could be nand if multiplication is and - not really
                        //& invmodGF2(x[h, k]) is 1 when x[h, k] is 1 and not defined when x[h, k] is 0...
                        //but this operation is meaningless in the context of scaling except when both x[i,k] and x[h,k] are both true...
                        //Fill with zeros the lower part of the pivot column
                        x[i, k] = false;
                        //Do for all remaining elements in current row
                        for (int j = k + 1; j < n; j++) {
                            x[i, j] ^= (x[h, j] & f);
                        }
                    }
                    h++; k++; //Increase pivot row and column
                }
            }
            //Convert from row echelon form to reduced row echelon form via back substitution
            //upper triangle matrix
            /*h = m - 1; //Initialization of pivot row
            k = 0; //Initialization of pivot column
            while (h >= 0 && k < x.GetLength(1)) {
                //Find the k-th pivot
                int i_max = Enumerable.Range(k, x.GetLength(1) - k + 1 - 1).Where((int i) => x[h, i]).FirstOrDefault(); //index of maximum which is first one with a bit set, also should consider absolute value but here its not applicable since no negative values though zero still possible
                if (x[h, i_max] == false) //No pivot in this column, pass to next column
                    h--;
                else {
                    for (int i = 0; i < h; i++) {
                        bool f = x[i, i_max];
                        for (int j = k + 1; j < x.GetLength(1); j++)
                            x[h, j] = x[i, j] ^ (x[h, j] & f);

                    }
                }
                h--; k++;
            }*/
            return x; //ret;
        }

        static Tuple<bool[,], bool[][,]> calcAd(int nSize, byte[] cyphData, BigInteger M, bool [][,] Msis, int cyphDataLen = 0)
        {
            if (cyphDataLen == 0) cyphDataLen = cyphData.Length;
            bool[,] Ad = new bool[128, 128];
            bool[][,] Mdi = new bool[nSize + 1][,];
            bool[][,] Adn = new bool[nSize + 1][,];
            //for (int ctr = 32; ctr < cyphData.Length; ctr <<= 1) //only blocks 2^i but not i==0 since its the length block, but 2, 4, 8, 16, 32, 64, etc
            //int nSize = binlog2(cyphData.Length / 16)
            for (int c = 0; c < nSize + 1; c++)
            { //zero pad to block align
                int ctr = 16 * ((1 << c) - 1);
                BigInteger di;
                if (c == 0)
                {
                    di = new BigInteger(BitConverter.GetBytes((ulong)0).Reverse().Concat(BitConverter.GetBytes((ulong)cyphDataLen * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
                }
                else
                {
                    di = new BigInteger(cyphData.Skip(cyphData.Length - ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
                }
                //BigInteger di = new BigInteger(cyphData.Skip((int)cyphData.Length - ctr + 16).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
                //uint v = (uint)ctr / 16;
                //uint c = 32;
                //v &= (uint)(-((int)v));
                //if (v != 0) c--;
                //if ((v & 0x0000FFFF) != 0) c -= 16;
                //if ((v & 0x00FF00FF) != 0) c -= 8;
                //if ((v & 0x0F0F0F0F) != 0) c -= 4;
                //if ((v & 0x33333333) != 0) c -= 2;
                //if ((v & 0x55555555) != 0) c -= 1;
                //Console.WriteLine((cyphData.Length - ctr) + " " + ctr + " " + c);
                Mdi[c] = new bool[128, 128];
                for (int i = 0; i < 128; i++)
                {
                    BigInteger cnst = modmulGF2k(di, BigInteger.One << i, M);
                    for (int row = 0; row < 128; row++)
                    {
                        Mdi[c][row, i] = (cnst & (BigInteger.One << row)) != 0;
                    }
                }
                //compute Ad[i]
                Adn[c] = c == 0 ? Mdi[c] : matmul(Mdi[c], Msis[c - 1]);
                Ad = matsum(Adn[c], Ad);
                //now we have computed Ad=sum(Mdi*Ms^i)
                //check di * h^(2^i) == Ad[c] * h
            }
            return new Tuple<bool[,], bool[][,]>(Ad, Adn);
        }

        static void Set8()
        {
            //SET 8 CHALLENGE 57
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            BigInteger p = BigInteger.Parse("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771");
            BigInteger g = BigInteger.Parse("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143");
            BigInteger q = BigInteger.Parse("236234353446506858198510045061214171961");
            BigInteger j = (p - 1) / q; //30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570
            BigInteger RecX = BigInteger.Zero;
            //Pohlig-Hellman algorithm for discrete logarithms
            List<int> rs = new List<int>();
            List<int> bs = new List<int>();
            BigInteger rcum = 1;
            int curr = 0;
            BigInteger x;
            byte[] m = System.Text.Encoding.ASCII.GetBytes("crazy flamboyant for the rap enjoyment");
            goto p58;
            for (int i = 2; i < 1 << 16; i++) {
                BigInteger Rem = new BigInteger(), Quot = BigInteger.DivRem(j, i, out Rem);
                if (Rem == BigInteger.Zero) {
                    rs.Add(i);
                    do {
                        j = Quot;
                        Quot = BigInteger.DivRem(j, i, out Rem); //reduce powers of factors:
                        //(Friendly tip: maybe avoid any repeated factors. They only complicate things.)
                    } while (Rem == BigInteger.Zero);
                }
            }
            do { x = Crypto.GetNextRandomBig(rng, q); } while (x <= 1); //Bob's secret key
            Console.WriteLine("Secret key generated: " + HexEncode(x.ToByteArray()));
            do
            {
                BigInteger h;
                do {
                    //random number between 1..p
                    BigInteger rand;
                    do { rand = Crypto.GetNextRandomBig(rng, p); } while (rand <= 1);
                    h = BigInteger.ModPow(rand, (p - 1) / rs[curr], p); //There is no x such that h = g^x mod p
                } while (h == 1);
                BigInteger K = BigInteger.ModPow(h, x, p);
                byte[] t = hmac(K.ToByteArray(), m);
                BigInteger testK;
                for (int i = 0; i < rs[curr]; i++) {
                    testK = BigInteger.ModPow(h, i, p);
                    if (new ByteArrayComparer().Equals(t, hmac(testK.ToByteArray(), m))) {
                        bs.Add(i);
                        break;
                    }
                }
                rcum *= rs[curr];
                curr++;
            } while (rcum <= q);
            //Chinese Remainder Theorem - arbitrary size by interpolation
            //K = b1 (mod h1), K = b_n (mod r_n)
            for (int i = 0; i < curr; i++) {
                BigInteger curcum = rcum / rs[i];
                RecX += bs[i] * curcum * modInverse(curcum, rs[i]);
            }
            Console.WriteLine("8.57 Secret key recovered: " + HexEncode(BigInteger.Remainder(RecX, rcum).ToByteArray()));

            p58:
            goto p59;
            //SET 8 CHALLENGE 58
            p = BigInteger.Parse("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623");
            q = BigInteger.Parse("335062023296420808191071248367701059461");
            j = (p - 1) / q; //34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
            g = BigInteger.Parse("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357");
            BigInteger y = BigInteger.Parse("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119");
            /*for (int i = 0; i < 1 << 20; i++) { //small enough to brute force, AC3CD
                if (y == BigInteger.ModPow(g, i, p)) {
                    Console.WriteLine("Brute force secret key from public: " + i.ToString("X")); break;
                }
            }*/
            //[0, 2^20], y=g^x mod p
            Console.WriteLine("Pollard Kangaroo secret key from public: " + HexEncode(PollardKangaroo(0, 1 << 20, 7, g, p, y).ToByteArray().Reverse().ToArray()));
            y = BigInteger.Parse("9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733");
            //[0, 2^40], 53b89e66e4
            //Console.WriteLine("Pollard Kangaroo secret key from public: " + HexEncode(PollardKangaroo(0, (ulong)1 << 40, 23, g, p, y).ToByteArray().Reverse().ToArray()));
            do { x = Crypto.GetNextRandomBig(rng, q); } while (x <= 1); //Bob's secret key
            y = BigInteger.ModPow(g, x, p);
            Console.WriteLine("Secret key generated: " + HexEncode(x.ToByteArray()));
            rs = new List<int>();
            for (int i = 2; i < 1 << 16; i++) {
                BigInteger Rem = new BigInteger(), Quot = BigInteger.DivRem(j, i, out Rem);
                if (Rem == BigInteger.Zero) {
                    rs.Add(i);
                    do {
                        j = Quot;
                        Quot = BigInteger.DivRem(j, i, out Rem); //reduce powers of factors:
                        //(Friendly tip: maybe avoid any repeated factors. They only complicate things.)
                    } while (Rem == BigInteger.Zero);
                }
            }
            curr = 0;
            rcum = 1;
            bs = new List<int>();
            do
            {
                BigInteger h;
                do
                {
                    //random number between 1..p
                    BigInteger rand;
                    do { rand = Crypto.GetNextRandomBig(rng, p); } while (rand <= 1);
                    h = BigInteger.ModPow(rand, (p - 1) / rs[curr], p); //There is no x such that h = g^x mod p
                } while (h == 1);
                BigInteger K = BigInteger.ModPow(h, x, p);
                byte[] t = hmac(K.ToByteArray(), m);
                BigInteger testK;
                for (int i = 0; i < rs[curr]; i++)
                {
                    testK = BigInteger.ModPow(h, i, p);
                    if (new ByteArrayComparer().Equals(t, hmac(testK.ToByteArray(), m)))
                    {
                        bs.Add(i);
                        break;
                    }
                }
                rcum *= rs[curr];
                curr++;
            } while (curr < rs.Count); //(rcum <= q);
            //Chinese Remainder Theorem - arbitrary size by interpolation
            //K = b1 (mod h1), K = b_n (mod r_n)
            RecX = BigInteger.Zero;
            for (int i = 0; i < curr; i++) {
                BigInteger curcum = rcum / rs[i];
                RecX += bs[i] * curcum * modInverse(curcum, rs[i]);
            }
            RecX = BigInteger.Remainder(RecX, rcum);
            Console.WriteLine("CRT recovered: " + HexEncode(RecX.ToByteArray()));
            //[0, (q-1)/r]
            //x = n mod r, x = n + m * r therefore transform
            //y = g^x=g^(n+m*r)=g^n*g^(m*r)
            //y' = y * g^(-n)=g^(m*r), g'=g^r, y'=(g')^m
            BigInteger Gprime = BigInteger.ModPow(g, rcum, p);
            BigInteger Yprime = BigInteger.Remainder(y * modInverse(BigInteger.ModPow(g, RecX, p), p), p);
            BigInteger Mprime = PollardKangaroo(0, (p - 1) / rcum, 23, Gprime, p, Yprime); //(p - 1) / rcum is 40 bits in this case, 23 could also be good
            Console.WriteLine("8.58 Secret key recovered: " + HexEncode(BigInteger.Remainder(RecX + Mprime * rcum, p - 1).ToByteArray()));

            p59:
            //SET 8 CHALLENGE 59
            int EaOrig = -95051, Ea = EaOrig, Eb = 11279326;
            BigInteger Gx = 182, Gy = BigInteger.Parse("85518893674295321206118380980485522083"),
                GF = BigInteger.Parse("233970423115425145524320034830162017933"), BPOrd = BigInteger.Parse("29246302889428143187362802287225875743"), Ord = BPOrd * 2 * 2 * 2;
            //BPOrd*(Gx, Gy) = (0, 1)
            //factor Ord - then test all factors for BPOrd according to point multiplication equal to the infinite point (0, 1)
            //scaleEC(new Tuple<BigInteger, BigInteger>(Gx, Gy), BPOrd, Ea, GF).Equals(new Tuple<BigInteger, BigInteger>(0, 1));
            //Ord = SchoofElkiesAtkins(Ea, Eb, GF);
            Schoof(Ea, Eb, GF, rng, Ord);
            int[] PickGys = new int[] { 11279326, 210, 504, 727 };
            Tuple<BigInteger, BigInteger> G = new Tuple<BigInteger, BigInteger>(Gx, Gy);
            //goto p60;
            //http://magma.maths.usyd.edu.au/calc/
            //E: y^2+a_1xy+a_3y=x^3+a_2x^2+a_4x+a_6 over GF(p)
            //K:=GF(233970423115425145524320034830162017933);
            //g:= Generator(K);
            //E:= EllipticCurve([0, 0, 0, -95051 * g, 727 * g]);
            //#E;
            BigInteger[] Ords = new BigInteger[] { Ord, BigInteger.Parse("233970423115425145550826547352470124412"),
                BigInteger.Parse("233970423115425145544350131142039591210"),
                BigInteger.Parse("233970423115425145545378039958152057148") };
            //Ords[0] /= 2; //The correct way to find generators of required order is to use the order of the largest cyclic subgroup of an elliptic curve.
            BigInteger ASecret;
            do { ASecret = Crypto.GetNextRandomBig(rng, BPOrd); } while (ASecret <= 1);
            Tuple < BigInteger, BigInteger> APub = scaleEC(G, ASecret, Ea, GF);
            BigInteger BSecret;
            do { BSecret = Crypto.GetNextRandomBig(rng, BPOrd); } while (BSecret <= 1);
            Tuple < BigInteger, BigInteger> BPub = scaleEC(G, BSecret, Ea, GF);
            Tuple<BigInteger, BigInteger> AShared = scaleEC(BPub, ASecret, Ea, GF);
            Tuple<BigInteger, BigInteger> BShared = scaleEC(APub, BSecret, Ea, GF);
            Console.WriteLine("Base point and order correct: " + (scaleEC(G, BPOrd, Ea, GF).Equals(new Tuple<BigInteger, BigInteger>(0, 1))));
            Console.WriteLine("Shared Secrets Identical: " + (AShared.Item1 == BShared.Item1));

            //Pohlig-Hellman algorithm for discrete logarithms
            rs = new List<int>();
            List<int> rsidx = new List<int>();
            rs.Add(8);
            rsidx.Add(0);
            for (int prms = 1; prms < 4; prms++) {
                p = Ords[prms];
                for (int i = 2; i < 1 << 16; i++) {
                    BigInteger Rem = new BigInteger(), Quot = BigInteger.DivRem(p, i, out Rem);
                    if (Rem == BigInteger.Zero) {
                        if (i != 2 && !rs.Contains(i))
                        {//2^3 as a factor uses original curve, up to 31 result not found
                            rs.Add(i);
                            rsidx.Add(prms);
                        }
                        do {
                            p = Quot;
                            Quot = BigInteger.DivRem(p, i, out Rem); //reduce powers of factors:
                            //(Friendly tip: maybe avoid any repeated factors. They only complicate things.)
                            if (Rem == BigInteger.Zero)
                            {
                                Console.WriteLine(i);
                            }
                        } while (Rem == BigInteger.Zero);
                    }
                }
            }
            bs = new List<int>();
            rcum = 1;
            curr = 0;
            do { x = Crypto.GetNextRandomBig(rng, BPOrd); } while (x <= 1); //Bob's secret key
            Console.WriteLine("Secret key generated: " + x);
            do {
                BigInteger hx, hy;
                Tuple<BigInteger, BigInteger> h;
                do {
                    //random point with between x value between 1..Ord
                    do { hx = Crypto.GetNextRandomBig(rng, Ords[rsidx[curr]]); } while (hx <= 1);
                    hy = TonelliShanks(rng, posRemainder(hx * hx * hx + Ea * hx + PickGys[rsidx[curr]], GF), GF);
                    h = scaleEC(new Tuple<BigInteger, BigInteger>(hx, hy), Ords[rsidx[curr]] / rs[curr], Ea, GF);
                } while (hy == BigInteger.Zero || h.Equals(new Tuple<BigInteger, BigInteger>(0, 1)));
                //Console.WriteLine(BigInteger.Remainder(h.Item1 * h.Item1 * h.Item1 + Ea * h.Item1 + PickGys[rsidx[curr]], GF) + " " + BigInteger.Remainder(h.Item2 * h.Item2, GF));
                //h = new Tuple<BigInteger, BigInteger>(hx, hy);
                Tuple<BigInteger, BigInteger> K = scaleEC(h, x, Ea, GF);
                //Console.WriteLine(K); //x mod r = 0, then K = infinity
                //Console.WriteLine(scaleEC(h, Ord, Ea, GF));
                byte[] t = hmac(K.Item1.ToByteArray(), m);
                Tuple<BigInteger, BigInteger> testK;
                int i;
                for (i = 0; i < rs[curr]; i++) {
                    testK = scaleEC(h, i, Ea, GF);
                    if (new ByteArrayComparer().Equals(t, hmac(testK.Item1.ToByteArray(), m))) {
                        break;
                    }
                }
                if (i == rs[curr] || i == 0) {
                    //Console.WriteLine(rs[curr]);
                    rs.RemoveAt(curr);
                    rsidx.RemoveAt(curr);
                } else {
                    //k*u = -k*u, resulting in a combinatorial explosion of potential CRT outputs. 
                    //i or rs[curr] - i
                    //Console.WriteLine(rs[curr] + " " + (rs[curr] - i) + " " + i + " " + BigInteger.Remainder(x, rs[curr]));
                    bs.Add(i); //i or rs[curr] - i, only know i^2
                    rcum *= rs[curr];
                    curr++;
                }
            } while (rcum <= BPOrd);
            //Chinese Remainder Theorem - arbitrary size by interpolation
            //K = b1 (mod h1), K = b_n (mod r_n)
            //CRT trick: compute with bi^2 mod pi compute sqrt(s^2) over all integers (Z) BUT NEED rcum > BPOrd * BPOrd
            //combinatoric brute force search, could try combinations for each of the curves to group by positive/negative
            //then a combination to combine them also but makes for more code with same final result based on the different curves
            //but this is hardly a slow search in this context
            {
                BigInteger hx, hy;
                Tuple<BigInteger, BigInteger> h;
                do
                {
                    //random point with between x value between 1..Ord
                    do { hx = Crypto.GetNextRandomBig(rng, BPOrd); } while (hx <= 1);
                    hy = TonelliShanks(rng, posRemainder(hx * hx * hx + Ea * hx + Eb, GF), GF);
                } while (hy == BigInteger.Zero);
                h = new Tuple<BigInteger, BigInteger>(hx, hy);
                Tuple<BigInteger, BigInteger> finK = scaleEC(h, x, Ea, GF);
                byte[] t = hmac(finK.Item1.ToByteArray(), m);
                for (int r = 0; r < 1 << curr; r++) {
                    RecX = BigInteger.Zero;
                    for (int i = 0; i < curr; i++) {
                        BigInteger curcum = rcum / rs[i];
                        RecX += ((r & (1 << i)) != 0 ? bs[i] : rs[i] - bs[i]) * curcum * modInverse(curcum, rs[i]);
                    }
                    RecX = BigInteger.Remainder(RecX, rcum);
                    Tuple<BigInteger, BigInteger> testK = scaleEC(h, RecX, Ea, GF);
                    if (new ByteArrayComparer().Equals(t, hmac(testK.Item1.ToByteArray(), m))) {
                        break;
                    }
                }
            }
            Console.WriteLine("8.59 Secret key recovered: " + RecX);

        //SET 8 CHALLENGE 60
        p60:
            //goto p61;
            Ea = 534; Gx = Gx - 178;
            Console.WriteLine("Base point and order correct: " + ladder(Gx, BPOrd, Ea, GF) + " " + (ladder(Gx, BPOrd, Ea, GF) == BigInteger.Zero));
            BigInteger Pt = BigInteger.Parse("76600469441198017145391791613091732004");
            Console.WriteLine(ladder(Pt, 11, Ea, GF)); //0 or infinite
            Console.WriteLine(TonelliShanks(rng, posRemainder(Pt * Pt * Pt + Ea * Pt * Pt + Pt, GF), GF)); //0 meaning non-existent
            BigInteger TwistOrd = 2 * GF + 2 - Ord;
            rs = new List<int>();
            p = TwistOrd; //Montgomery curve order are always divisible by 4
            for (int i = 2; i < 1 << 24; i++) {
                BigInteger Rem = new BigInteger(), Quot = BigInteger.DivRem(p, i, out Rem);
                if (Rem == BigInteger.Zero) {
                    rs.Add(i);
                    do {
                        p = Quot;
                        Quot = BigInteger.DivRem(p, i, out Rem); //reduce powers of factors:
                        //(Friendly tip: maybe avoid any repeated factors. They only complicate things.)
                        if (Rem == BigInteger.Zero) {
                            Console.WriteLine(i);
                        }
                    } while (Rem == BigInteger.Zero);
                }
            }
            bs = new List<int>();
            rcum = 1;
            curr = 0;
            do { x = Crypto.GetNextRandomBig(rng, BPOrd); } while (x <= 1); //Bob's secret key
            //Y = scaleEC(G, x, EaOrig, GF);
            BigInteger hxu = ladder(Gx, x, Ea, GF); //public key used at end, can convert back to Weierstrass for additions in Pollard Kangaroo
            //positive and negative root do not yield same result so how to determine
            Tuple<BigInteger, BigInteger> Y = new Tuple<BigInteger, BigInteger>(hxu + 178, TonelliShanks(rng, posRemainder(hxu * hxu * hxu + Ea * hxu * hxu + hxu, GF), GF));
            Console.WriteLine("Secret key generated: " + x);
            Console.WriteLine("Public key: " + Y + " " + scaleEC(G, x, EaOrig, GF) + " " + TonelliShanks(rng, posRemainder((hxu + 178) * (hxu + 178) * (hxu + 178) + EaOrig * (hxu + 178) + Eb, GF), GF) + " " + ladder2(new Tuple<BigInteger, BigInteger>(Gx, Gy), x, Ea, EaOrig, Eb, GF, 178));
            Y = scaleEC(G, x, EaOrig, GF);
            Y = ladder2(new Tuple<BigInteger, BigInteger>(Gx, Gy), x, Ea, EaOrig, Eb, GF, 178);
            //cannot know the correct sign, but (r+1)G is calculated in other accumulator in ladder() function and hence
            //if x1 is to rG as x2 is to (r+1)G, then y1=(2b+(a+x0x1)(x0+x1)-x2(x0-x1)^2)/2y0
            //would need a double coordinate ladder, but it should be safe to assume that this need be provided or it doubles trials at the end
            //ECDH can either be x-only or x+sign, one way is to negate x if y/x is not positive
            do
            {
                BigInteger u, hy;
                do
                {
                    //random point with between x value between 1..Ord
                    do { u = Crypto.GetNextRandomBig(rng, GF); } while (u <= 1);
                    hy = TonelliShanks(rng, posRemainder(u * u * u + Ea * u * u + u, GF), GF);
                } while (hy != BigInteger.Zero);
                u = ladder(u, TwistOrd / rs[curr], Ea, GF);
                //hy = TonelliShanks(rng, posRemainder(u * u * u + EaOrig * u + Eb, GF), GF);
                //Console.WriteLine(BigInteger.Remainder(h.Item1 * h.Item1 * h.Item1 + Ea * h.Item1 + PickGys[rsidx[curr]], GF) + " " + BigInteger.Remainder(h.Item2 * h.Item2, GF));
                //Tuple<BigInteger, BigInteger> h = new Tuple<BigInteger, BigInteger>(u, hy);
                //Tuple<BigInteger, BigInteger> K = scaleEC(h, x, EaOrig, GF);
                BigInteger K = ladder(u, x, Ea, GF);
                //Console.WriteLine(K); //x mod r = 0, then K = infinity
                //Console.WriteLine(scaleEC(h, Ord, Ea, GF));
                byte[] t = hmac(K.ToByteArray(), m);
                //Tuple<BigInteger, BigInteger> testK;
                BigInteger testK;
                int i;
                for (i = 0; i < rs[curr]; i++)
                {
                    //testK = scaleEC(h, i, EaOrig, GF);
                    testK = ladder(u, i, Ea, GF);
                    //if (new ByteArrayComparer().Equals(t, hmac(testK.Item1.ToByteArray(), m)))
                    if (new ByteArrayComparer().Equals(t, hmac(testK.ToByteArray(), m)))
                    {
                        break;
                    }
                }
                if (i == rs[curr] || i == 0) {
                    //Console.WriteLine(rs[curr]);
                    rs.RemoveAt(curr);
                } else {
                    //k*u = -k*u, resulting in a combinatorial explosion of potential CRT outputs. 
                    //i or rs[curr] - i
                    Console.WriteLine(rs[curr] + " " + (rs[curr] - i) + " " + i + " " + BigInteger.Remainder(x, rs[curr]));
                    //bs.Add(BigInteger.Remainder(x, rs[curr]).Equals(i) ? i : rs[curr] - i);
                    bs.Add(i);
                    rcum *= rs[curr];
                    curr++;
                }
            } while (curr < rs.Count); //(rcum <= q);
                                       //Chinese Remainder Theorem - arbitrary size by interpolation
                                       //K = b1 (mod h1), K = b_n (mod r_n)
            List<BigInteger> recxs = new List<BigInteger>();
            for (int r = 0; r < 1 << curr; r++) {
                RecX = BigInteger.Zero;
                for (int i = 0; i < curr; i++)
                {
                    BigInteger curcum = rcum / rs[i];
                    RecX += ((r & (1 << i)) != 0 ? bs[i] : rs[i] - bs[i]) * curcum * modInverse(curcum, rs[i]);
                }
                RecX = BigInteger.Remainder(RecX, rcum);
                recxs.Add(RecX);
            }
            do {
                BigInteger u, hy; //keep querying until narrowed down to only a positive/negative pair
                do
                {
                    //random point with between x value between 1..Ord
                    do { u = Crypto.GetNextRandomBig(rng, GF); } while (u <= 1);
                    hy = TonelliShanks(rng, posRemainder(u * u * u + Ea * u * u + u, GF), GF);
                } while (hy != BigInteger.Zero);
                u = ladder(u, TwistOrd / rcum, Ea, GF);
                BigInteger K = ladder(u, x, Ea, GF);
                byte[] t = hmac(K.ToByteArray(), m);
                recxs = recxs.Where((BigInteger rx) => 
                    new ByteArrayComparer().Equals(t, hmac(ladder(u, rx, Ea, GF).ToByteArray(), m))).ToList();
            } while (recxs.Count != 2);
            //again still left with 2 possible values, the positive and negative one
            RecX = recxs[0];
            Console.WriteLine("CRT recovered: " + HexEncode(RecX.ToByteArray()) + " " + HexEncode((rcum - RecX).ToByteArray()));
            Console.WriteLine(((x - RecX) / rcum) + " " + BigInteger.Remainder(x - RecX, rcum));
            Console.WriteLine(((x - (rcum - RecX)) / rcum) + " " + BigInteger.Remainder(x - (rcum - RecX), rcum));
            //[0, (q-1)/r]
            //x = n mod r, x = n + m * r therefore transform
            //y = xG=nG+mrG
            //y' = mG', y'=y-nG, G'=rG
            //x == RecX + mval * rcum
            BigInteger mval = BigInteger.Remainder(x - RecX, rcum) == 0 ? ((x - RecX) / rcum) : ((x - (rcum - RecX)) / rcum);
            BigInteger fixRecX = BigInteger.Remainder(x - RecX, rcum) == 0 ? RecX : (rcum - RecX);
            Tuple <BigInteger, BigInteger> Yorig = scaleEC(G, x, EaOrig, GF);
            Tuple<BigInteger, BigInteger> Ycalc = addEC(scaleEC(G, fixRecX, EaOrig, GF), scaleEC(G, mval * rcum, EaOrig, GF), EaOrig, GF);
            //Yorig.Item1 == Ycalc.Item1 && Yorig.Item2 == Ycalc.Item2;
            Tuple<BigInteger, BigInteger> GprimeEC = scaleEC(G, rcum, EaOrig, GF);
            Tuple<BigInteger, BigInteger> YprimeEC = addEC(Yorig, invertEC(scaleEC(G, fixRecX, EaOrig, GF), GF), EaOrig, GF);
            Tuple<BigInteger, BigInteger> YprimeECcalc = scaleEC(GprimeEC, mval, EaOrig, GF);
            //YprimeECcalc.Item1 == YprimeEC.Item1 && YprimeECcalc.Item2 == YprimeEC.Item2
            //YprimeEC = addEC(Yorig, invertEC(scaleEC(G, RecX, EaOrig, GF), GF), EaOrig, GF);
            //Mprime = PollardKangarooEC(0, TwistOrd / rcum, 23, GprimeEC, EaOrig, GF, YprimeEC); //(q - 1) / rcum is 43 bits in this case, 26 could also be good
            //if (Mprime.Equals(BigInteger.Zero)) {
            //RecX = rcum - RecX;
            //YprimeEC = addEC(Yorig, invertEC(scaleEC(G, RecX, EaOrig, GF), GF), EaOrig, GF);
            //Mprime = PollardKangarooEC(0, TwistOrd / rcum, 23, GprimeEC, EaOrig, GF, YprimeEC); //(q - 1) / rcum is 43 bits in this case, 26 could also be good
            //}

            Ycalc = WSToMontg(addEC(montgToWS(ladder2(new Tuple<BigInteger, BigInteger>(Gx, Gy), fixRecX, Ea, EaOrig, Eb, GF, 178), 178), montgToWS(ladder2(new Tuple<BigInteger, BigInteger>(Gx, Gy), mval * rcum, Ea, EaOrig, Eb, GF, 178), 178), EaOrig, GF), 178);
            //Y.Item1 == Y.Item1 && Yorig.Item2 == Ycalc.Item2;
            GprimeEC = ladder2(new Tuple<BigInteger, BigInteger>(Gx, Gy), rcum, Ea, EaOrig, Eb, GF, 178);
            YprimeEC = WSToMontg(addEC(montgToWS(Y, 178), invertEC(montgToWS(ladder2(new Tuple<BigInteger, BigInteger>(Gx, Gy), fixRecX, Ea, EaOrig, Eb, GF, 178), 178), GF), EaOrig, GF), 178);
            YprimeECcalc = ladder2(GprimeEC, mval, Ea, EaOrig, Eb, GF, 178);
            //YprimeECcalc.Item1 == YprimeEC.Item1 && YprimeECcalc.Item2 == YprimeEC.Item2
            
            YprimeEC = addEC(montgToWS(Y, 178), invertEC(montgToWS(ladder2(new Tuple<BigInteger, BigInteger>(Gx, Gy), RecX, Ea, EaOrig, Eb, GF, 178), 178), GF), EaOrig, GF);
            Console.WriteLine(YprimeEC + " " + scaleEC(GprimeEC, ((x - RecX) / rcum), EaOrig, GF));
            Mprime = PollardKangarooECmontg(0, TwistOrd / rcum, 23, GprimeEC, EaOrig, Ea, Eb, GF, YprimeEC, 178); //(q - 1) / rcum is 43 bits in this case, 26 could also be good
            if (Mprime.Equals(BigInteger.Zero)) {
                RecX = rcum - RecX;
                //YprimeEC = addEC(Y, invertEC(scaleEC(G, RecX, EaOrig, GF), GF), EaOrig, GF);
                YprimeEC = addEC(montgToWS(Y, 178), invertEC(montgToWS(ladder2(new Tuple<BigInteger, BigInteger>(Gx, Gy), RecX, Ea, EaOrig, Eb, GF, 178), 178), GF), EaOrig, GF);
                Console.WriteLine(YprimeEC + " " + scaleEC(GprimeEC, ((x - RecX) / rcum), EaOrig, GF));
                Mprime = PollardKangarooECmontg(0, TwistOrd / rcum, 23, GprimeEC, EaOrig, Ea, Eb, GF, YprimeEC, 178); //(q - 1) / rcum is 43 bits in this case, 26 could also be good
            }
            Console.WriteLine("8.60 Secret key recovered: " + (RecX + Mprime * rcum) + " " + HexEncode((RecX + Mprime * rcum).ToByteArray()));

        //SET 8 CHALLENGE 61
        p61:
            BigInteger d;
            SHA1 hf = SHA1.Create();
            do { d = Crypto.GetNextRandomBig(rng, BPOrd); } while (d <= 1);
            Tuple<BigInteger, BigInteger> Q = scaleEC(G, d, EaOrig, GF);
            BigInteger hm = BytesToBigInt(hf.ComputeHash(m));
            Tuple<BigInteger, BigInteger> res = signECDSA(rng, hm, d, BPOrd, G, EaOrig, GF);
            //now generate a fake signer public key Q'
            BigInteger inv = modInverse(res.Item2, BPOrd), u1 = BigInteger.Remainder(hm * inv, BPOrd), u2 = BigInteger.Remainder(res.Item1 * inv, BPOrd);
            BigInteger dprime;
            do { dprime = Crypto.GetNextRandomBig(rng, BPOrd); } while (dprime <= 1);
            BigInteger tmp = u1 + u2 * dprime;
            GprimeEC = scaleEC(addEC(scaleEC(G, u1, EaOrig, GF), scaleEC(Q, u2, EaOrig, GF), EaOrig, GF), modInverse(tmp, BPOrd), EaOrig, GF);
            Tuple<BigInteger, BigInteger> Qprime = scaleEC(GprimeEC, dprime, EaOrig, GF);
            Console.WriteLine("Q and Q' verify: " + verifyECDSA(hm, res, Q, BPOrd, G, EaOrig, GF) + " " + verifyECDSA(hm, res, Qprime, BPOrd, GprimeEC, EaOrig, GF));
            goto p62;
            //RSA
            //sign: s=pad(m)^d mod N
            BigInteger _p;
            BigInteger _q;
            BigInteger et;
            do {
                do {
                    _p = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_p, 64));
                _p = BigInteger.Parse("252919978488117916147778994275562072491");
                do {
                    _q = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_q, 64));
                _q = BigInteger.Parse("212353757101997844028225694411779588517");
            } while (modInverse(3, et = (_p - 1) * (_q - 1)) == 1); //the totient must be coprime to our fixed e=3
            BigInteger n = _p * _q;
            d = modInverse(3, et);
            BigInteger s = BigInteger.ModPow(hm, d, n);
            //verify: s^e = pad(m) mod N
            //smooth p-1 (many small factors)
            BigInteger pprime, qprime;
            List<BigInteger> rsq = new List<BigInteger>();
            do
            {
                do
                {
                    pprime = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(pprime, 64));
                pprime = BigInteger.Parse("254020701007860332256656456025272804327");
                rsq = PollardRhoAll(pprime - 1); //check smoothness with Pollard's rho
                if (rsq.Count == 0 || rsq.Max() > (1 << 24)) continue;
                int i = 0;
                for (; i < rsq.Count; i++) {
                    if (BigInteger.ModPow(s, (pprime - 1) / rsq[i], pprime).Equals(BigInteger.One)) break;
                }
                if (i == rsq.Count) break;
            } while (true);
            rs = rsq.ConvertAll((BigInteger X) => (int)X); rsq.Clear();
            do
            {
                do {
                    qprime = GetPivotRandom(rng, 128);
                    if (pprime * qprime <= n) continue;
                } while (!IsProbablePrime(qprime, 64));
                qprime = BigInteger.Parse("266237645118740561410025069955757680311");
                int i = 0;
                for (; i < rs.Count; i++) {
                    if (rs[i] != 2 && BigInteger.Remainder(qprime - 1, rs[i]) == 0) break;
                }
                if (i != rs.Count) continue;
                rsq = PollardRhoAll(qprime - 1); //check smoothness with Pollard's rho
                if (rsq.Count == 0 || rsq.Max() > (1 << 24)) continue;
                i = 0;
                for (; i < rsq.Count; i++)
                {
                    if (BigInteger.ModPow(s, (pprime - 1) / rsq[i], pprime).Equals(BigInteger.One)) break;
                }
                if (i == rsq.Count) break;
            } while (true);
            bs = new List<int>(); rcum = 1;
            BigInteger nprime = pprime * qprime, npp = qprime - 1, npq = pprime - 1, ep = BigInteger.Zero, eq = BigInteger.Zero;
            //Pohlig-Hellman s^e=pad(m) mod n, s^ep=pad(m) mod p, s^eq=pad(m) mod q
            for (curr = 0; curr < rs.Count; curr++) {
                BigInteger gprime = BigInteger.ModPow(s, (pprime - 1) / rs[curr], pprime);
                BigInteger hprime = BigInteger.ModPow(hm, (pprime - 1) / rs[curr], pprime);
                for (int i = 0; i < rs[curr]; i++) {
                    if (BigInteger.ModPow(gprime, i, pprime).Equals(hprime)) {
                        bs.Add(i); rcum *= rs[curr]; break;
                    }
                }
            }
            for (int i = 0; i < rs.Count; i++)
            {
                BigInteger curcum = rcum / rs[i];
                ep += bs[i] * curcum * modInverse(curcum, rs[i]);
            }
            ep = BigInteger.Remainder(ep, rcum);
            bs.Clear(); rcum = 1;
            List<int> rso = rs;
            rs = rsq.ConvertAll((BigInteger X) => (int)X); rsq.Clear();
            for (curr = 0; curr < rs.Count; curr++) {
                BigInteger gprime = BigInteger.ModPow(s, (qprime - 1) / rs[curr], qprime);
                BigInteger hprime = BigInteger.ModPow(hm, (qprime - 1) / rs[curr], qprime);
                for (int i = 0; i < rs[curr]; i++) {
                    if (BigInteger.ModPow(gprime, i, qprime).Equals(hprime)) {
                        bs.Add(i); rcum *= rs[curr]; break;
                    }
                }
            }
            for (int i = 0; i < rs.Count; i++)
            {
                BigInteger curcum = rcum / rs[i];
                eq += bs[i] * curcum * modInverse(curcum, rs[i]);
            }
            eq = BigInteger.Remainder(eq, rcum);
            rso.AddRange(rs);
            Console.WriteLine("ep and eq verify: " + BigInteger.ModPow(s, ep, pprime).Equals(BigInteger.Remainder(hm, pprime)) + " " + BigInteger.ModPow(s, eq, qprime).Equals(BigInteger.Remainder(hm, qprime)));
            //BigInteger gpr = BigInteger.ModPow(s, qprime - 1, nprime);
            //BigInteger hpr = BigInteger.ModPow(hm, qprime - 1, nprime); // = BigInteger.ModPow(gpr, ep, nprime)
            //CRT but (p-1) and (q-1) and not pairwise coprime, share factor of 2
            BigInteger eprime = BigInteger.Remainder(ep * qprime * modInverse(qprime, pprime) + eq * pprime * modInverse(pprime, qprime), pprime * qprime);
            npp = qprime - 1;
            eprime = BigInteger.Remainder(ep * (npp / 2) * modInverse(npp / 2, npq) + eq * npq * modInverse(npq, npp / 2), npq * npp / 2);
            /*for (int i = 0; i < rso.Count; i++) {
                BigInteger rem, quot = BigInteger.DivRem(eprime, rso[i], out rem);
                while (rem.Equals(BigInteger.Zero)) {
                    Console.WriteLine(rso[i]);
                    eprime = quot;
                    quot = BigInteger.DivRem(eprime, rso[i], out rem);
                }
            }*/
            Console.WriteLine("eprime for ep and eq: " + BigInteger.Remainder(eprime, pprime-1).Equals(ep) + " " + BigInteger.Remainder(eprime, qprime-1).Equals(eq));
            //eprime must be coprime with npp * npq!!!
            //eprime = BigInteger.Remainder(ep * npp * modInverse(npp, npq) + eq * npq * modInverse(pprime, npp), npq * npp);
            dprime = modInverse(eprime / 2, npp * npq);
            Console.WriteLine(BigInteger.Remainder(dprime * eprime / 2, npp * npq)); //this must be 1
            //now there is a problem since this common factor of 2 (hence not having common factors in the problem description)
            //requires that whenever using this new decryption key, a square root is taken since it is only half (so its interpeted as m^(e/2) instead of m^e)
            Console.WriteLine("e and e' verify: " + BigInteger.ModPow(s, 3, n).Equals(hm) + " " + BigInteger.ModPow(s, eprime, nprime).Equals(BigInteger.Remainder(hm, nprime)));
            //must start over with new primes, encryption and decryption key specific to every plaintext to decrypt
            //4 possible CRT combinations - can verify correct one by reencrypting
            Console.WriteLine("Encrypt and decrypt original and new: " + new ByteArrayComparer().Equals(BigInteger.ModPow(BigInteger.ModPow(new BigInteger(m.Take(15).ToArray()), 3, n), d, n).ToByteArray(), m.Take(15).ToArray()) + " " +
                (BigInteger.Remainder(TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, pprime), pprime) * qprime * modInverse(qprime, pprime) + TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, qprime), qprime) * pprime * modInverse(pprime, qprime), pprime * qprime) == s) + " " +
                (BigInteger.Remainder((pprime - TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, pprime), pprime)) * qprime * modInverse(qprime, pprime) + TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, qprime), qprime) * pprime * modInverse(pprime, qprime), pprime * qprime) == s) + " " +
                (BigInteger.Remainder(TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, pprime), pprime) * qprime * modInverse(qprime, pprime) + (qprime - TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, qprime), qprime)) * pprime * modInverse(pprime, qprime), pprime * qprime) == s) + " " +
                (BigInteger.Remainder((pprime - TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, pprime), pprime)) * qprime * modInverse(qprime, pprime) + (qprime - TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, qprime), qprime)) * pprime * modInverse(pprime, qprime), pprime * qprime) == s) + " " +
                BigInteger.Remainder(TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, pprime), pprime) * qprime * modInverse(qprime, pprime) + TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, qprime), qprime) * pprime * modInverse(pprime, qprime), pprime * qprime) + " " +
                BigInteger.Remainder((pprime - TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, pprime), pprime)) * qprime * modInverse(qprime, pprime) + TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, qprime), qprime) * pprime * modInverse(pprime, qprime), pprime * qprime) + " " +
                BigInteger.Remainder(TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, pprime), pprime) * qprime * modInverse(qprime, pprime) + (qprime - TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, qprime), qprime)) * pprime * modInverse(pprime, qprime), pprime * qprime) + " " +
                BigInteger.Remainder((pprime - TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, pprime), pprime)) * qprime * modInverse(qprime, pprime) + (qprime - TonelliShanks(rng, BigInteger.ModPow(BigInteger.ModPow(s, 3, n), dprime, qprime), qprime)) * pprime * modInverse(pprime, qprime), pprime * qprime));
            Console.WriteLine("8.61");

        //SET 8 CHALLENGE 62
        p62:
            goto p63;
            List<List<Tuple<BigInteger, BigInteger>>> Result = LLL(new List<List<Tuple<BigInteger, BigInteger>>> { new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(1, 1), new Tuple<BigInteger, BigInteger>(1, 1), new Tuple<BigInteger, BigInteger>(1, 1) },
                new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(-1, 1), new Tuple<BigInteger, BigInteger>(0, 1), new Tuple<BigInteger, BigInteger>(2, 1) },
                new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(3, 1), new Tuple<BigInteger, BigInteger>(5, 1), new Tuple<BigInteger, BigInteger>(6, 1) }},
                new Tuple<BigInteger, BigInteger>(99, 100));
            Console.WriteLine("Wikipedia LLL result: " + Result.Zip(new List<List<Tuple<BigInteger, BigInteger>>> { new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(0, 1), new Tuple<BigInteger, BigInteger>(1, 1), new Tuple<BigInteger, BigInteger>(0, 1) },
                new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(1, 1), new Tuple<BigInteger, BigInteger>(0, 1), new Tuple<BigInteger, BigInteger>(1, 1) },
                new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(-1, 1), new Tuple<BigInteger, BigInteger>(0, 1), new Tuple<BigInteger, BigInteger>(2, 1) }}, (r1, r2) => r1.SequenceEqual(r2)).All((b) => b));
            Result = LLL(new List<List<Tuple<BigInteger, BigInteger>>> { new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(-2, 1), new Tuple<BigInteger, BigInteger>(0, 1), new Tuple<BigInteger, BigInteger>(2, 1), new Tuple<BigInteger, BigInteger>(0, 1) },
                new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(1, 2), new Tuple<BigInteger, BigInteger>(-1, 1), new Tuple<BigInteger, BigInteger>(0, 1), new Tuple<BigInteger, BigInteger>(0, 1) },
                new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(-1, 1), new Tuple<BigInteger, BigInteger>(0, 1), new Tuple<BigInteger, BigInteger>(-2, 1), new Tuple<BigInteger, BigInteger>(1, 2) },
                new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(-1, 1), new Tuple<BigInteger, BigInteger>(1, 1), new Tuple<BigInteger, BigInteger>(1, 1), new Tuple<BigInteger, BigInteger>(2, 1) } },
                new Tuple<BigInteger, BigInteger>(99, 100));
            Console.WriteLine("LLL verification: " + Result.Zip(new List<List<Tuple<BigInteger, BigInteger>>> { new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(1, 2), new Tuple<BigInteger, BigInteger>(-1, 1), new Tuple<BigInteger, BigInteger>(0, 1), new Tuple<BigInteger, BigInteger>(0, 1) },
                new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(-1, 1), new Tuple<BigInteger, BigInteger>(0, 1), new Tuple<BigInteger, BigInteger>(-2, 1), new Tuple<BigInteger, BigInteger>(1, 2) },
                new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(-1, 2), new Tuple<BigInteger, BigInteger>(0, 1), new Tuple<BigInteger, BigInteger>(1, 1), new Tuple<BigInteger, BigInteger>(2, 1) },
                new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(-3, 2), new Tuple<BigInteger, BigInteger>(-1, 1), new Tuple<BigInteger, BigInteger>(2, 1), new Tuple<BigInteger, BigInteger>(0, 1) }}, (r1, r2) => r1.SequenceEqual(r2)).All((b) => b));

            do { d = Crypto.GetNextRandomBig(rng, BPOrd); } while (d <= 1);
            Q = scaleEC(G, d, EaOrig, GF);
            hm = BytesToBigInt(hf.ComputeHash(m));
            List<List<Tuple<BigInteger, BigInteger>>> Basis = new List<List<Tuple<BigInteger, BigInteger>>>();
            const int trials = 20; //20 is possible per problem guidance
            for (int i = 0; i < trials; i++) {
                Basis.Add(Enumerable.Repeat(new Tuple<BigInteger, BigInteger>(0, 1), i).Concat(new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(BPOrd, 1) }).Concat(Enumerable.Repeat(new Tuple<BigInteger, BigInteger>(0, 1), trials + 2 - 1 - i)).ToList());
            }
            List<Tuple<BigInteger, BigInteger>> bt = new List<Tuple<BigInteger, BigInteger>>();
            List<Tuple<BigInteger, BigInteger>> bu = new List<Tuple<BigInteger, BigInteger>>();
            for (int i = 0; i < trials; i++) {
                res = signECDSAbiased(rng, hm, d, BPOrd, G, EaOrig, GF);
                //t = r / ( s * (1 << 8)), u = H(m) / (-s * (1 << 8))
                bt.Add(new Tuple<BigInteger, BigInteger>(BigInteger.Remainder(res.Item1 * modInverse(res.Item2 * (1 << 8), BPOrd), BPOrd), 1));
                bu.Add(new Tuple<BigInteger, BigInteger>(posRemainder(hm * modInverse(posRemainder(-res.Item2 * (1 << 8), BPOrd), BPOrd), BPOrd), 1));
                //bt.Add(new Tuple<BigInteger, BigInteger>(res.Item1, res.Item2 * (1 << 8)));
                //bu.Add(new Tuple<BigInteger, BigInteger>(hm, -res.Item2 * (1 << 8)));
            }
            //ct = 1/2^l, cu = q/2^l
            Tuple<BigInteger, BigInteger> cu = reducFrac(new Tuple<BigInteger, BigInteger>(BPOrd, 1 << 8));
            bt.Add(new Tuple<BigInteger, BigInteger>(1, 1 << 8));
            //Tuple<BigInteger, BigInteger> cu = reducFrac(new Tuple<BigInteger, BigInteger>(BigInteger.Remainder(BPOrd * modInverse(1 << 8, BPOrd), BPOrd), 1));
            //bt.Add(new Tuple<BigInteger, BigInteger>(modInverse(1 << 8, BPOrd), 1));
            bt.Add(new Tuple<BigInteger, BigInteger>(0, 1));
            bu.Add(new Tuple<BigInteger, BigInteger>(0, 1)); bu.Add(cu);
            Basis.Add(bt); Basis.Add(bu);
            LLL(Basis, new Tuple<BigInteger, BigInteger>(99, 100)); //about an hour with 22 vector basis, 3 minutes for 14 vector basis, 8 minutes for 16 vector basis
            dprime = BigInteger.Zero;
            for (int i = 0; i < trials + 2; i++) {
                if (Basis[i][trials + 1].Equals(cu)) {
                    //reducFrac(-Basis[i][trials].Item1 * (1 << 8), Basis[i][trials].Item2).Item1 == 1
                    dprime = posRemainder(reducFrac(new Tuple<BigInteger, BigInteger>(-Basis[i][trials].Item1 * (1 << 8), Basis[i][trials].Item2)).Item1, BPOrd);
                    break;
                }
            }
            Console.WriteLine("8.62 d recovered: " + (d == dprime));

        //SET 8 CHALLENGE 63
        p63:
            //BouncyCastle
            //BCryptEncrypt https://docs.microsoft.com/en-us/windows/desktop/api/bcrypt/nf-bcrypt-bcryptencrypt
            //https://archive.codeplex.com/?p=clrsecurity
            //https://codeplexarchive.blob.core.windows.net/archive/projects/clrsecurity/clrsecurity.zip

            byte[] key = new byte[16];
            rng.GetBytes(key);
            byte[] nonce = new byte[12]; // || 0^31 || 1
            rng.GetBytes(nonce);
            nonce = new byte[] { 0x51, 0x75, 0x3c, 0x65, 0x80, 0xc2, 0x72, 0x6f, 0x20, 0x71, 0x84, 0x14 };
            key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            //https://tools.ietf.org/html/rfc7714#section-16.1.1
            byte[] authData = System.Text.Encoding.ASCII.GetBytes("OFFICIAL SECRET: 12345678AB");
            BigInteger M = BigInteger.Parse("0100000000000000000000000000000087", System.Globalization.NumberStyles.HexNumber); //00E1000000000000000000000000000000 00E100000000000000000000000000000080 0100000000000000000000000000000087
            goto p64;
            //authData = new byte[] { 0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2 };
            //m = new byte[] { 0x47, 0x61, 0x6c, 0x6c, 0x69, 0x61, 0x20, 0x65, 0x73, 0x74, 0x20, 0x6f, 0x6d, 0x6e, 0x69, 0x73,
            //    0x20, 0x64, 0x69, 0x76, 0x69, 0x73, 0x61, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x61, 0x72, 0x74, 0x65,
            //    0x73, 0x20, 0x74, 0x72, 0x65, 0x73 };
            Tuple<byte[], BigInteger> cyphtag = crypt_gcm_fastlib(nonce, key, m, authData);
            byte[] cyphDataVerify = cyphtag.Item1;
            BigInteger VerifyTag = cyphtag.Item2;

            byte[] cyphData = crypt_gcm(nonce, key, m);
            BigInteger tag = calc_gcm_tag(nonce, key, cyphData, authData);
            //byte[] tgComp = tag.ToByteArray().Select((byte b) => ReverseBitsWith4Operations(b)).ToArray();
            //authData.Concat(cyphData).Concat(tag.ToByteArray()).ToArray();
            byte[] cyphData2 = crypt_gcm(nonce, key, m.Reverse().ToArray());
            BigInteger tag2 = calc_gcm_tag(nonce, key, cyphData2, authData.Reverse().ToArray());
            byte[] padAuthData = authData.Concat(Enumerable.Repeat((byte)0, (16 - (authData.Length % 16)) % 16)).ToArray();
            byte[] padAuthDataRev = authData.Reverse().Concat(Enumerable.Repeat((byte)0, (16 - (authData.Length % 16)) % 16)).ToArray();
            BigInteger[] coeff = new BigInteger[padAuthData.Length / 16 + (cyphData.Length + 15) / 16 + 2];
            for (int ctr = 0; ctr < padAuthData.Length; ctr += 16) { //zero pad to block align
                coeff[ctr / 16] = addGF2(new BigInteger(padAuthData.Skip((int)ctr).Take(Math.Min(padAuthData.Length - (int)ctr, 16)).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()),
                    new BigInteger(padAuthDataRev.Skip((int)ctr).Take(Math.Min(padAuthDataRev.Length - (int)ctr, 16)).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()));
            }
            for (int ctr = 0; ctr < cyphData.Length; ctr += 16) { //zero pad to block align
                coeff[padAuthData.Length / 16 + ctr / 16] = addGF2(new BigInteger(cyphData.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()),
                    new BigInteger(cyphData2.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()));
            }
            coeff[coeff.Length - 2] = addGF2(new BigInteger(BitConverter.GetBytes((ulong)authData.Length * 8).Reverse().Concat(BitConverter.GetBytes((ulong)cyphData.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()),
                new BigInteger(BitConverter.GetBytes((ulong)authData.Length * 8).Reverse().Concat(BitConverter.GetBytes((ulong)cyphData2.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()));
            coeff[coeff.Length - 1] = addGF2(tag, tag2);
            String str = String.Empty;
            BigInteger Sum = BigInteger.Zero;
            BigInteger hkey = new BigInteger(encrypt_ecb(key, Enumerable.Repeat((byte)0, 16).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()); //authentication key
            for (int i = 0; i < coeff.Length; i++) {
                str += "K.fetch_int(" + coeff[i].ToString() + ")" + ((i != coeff.Length - 1) ? "*x^" + (coeff.Length - 1 - i).ToString() + "+" : "");
                //str += new BigInteger(coeff[i].ToByteArray().Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()).ToString() + ((i != coeff.Length - 1) ? "*x^" + (coeff.Length - 1 - i).ToString() + "+" : "");
                //str += new BigInteger(coeff[i].ToByteArray().Reverse().Concat(new byte[] { 0 }).ToArray()).ToString() + ((i != coeff.Length - 1) ? "*x^" + (coeff.Length - 1 - i).ToString() + "+" : "");
                //str += new BigInteger(coeff[i].ToByteArray().Reverse().Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()).ToString() + ((i != coeff.Length - 1) ? "*x^" + (coeff.Length - 1 - i).ToString() + "+" : "");
                Sum = addGF2(Sum, modmulGF2k(coeff[i], modexpGF2k(hkey, coeff.Length - 1 - i, M), M));
            }
            Console.WriteLine(str); //for Sage Math
            Console.WriteLine(new BigInteger(key.Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()));
            Console.WriteLine(hkey);
            Console.WriteLine(Sum); //== 0
            //K.<a>=GF(2**128)
            //K.fetch_int(0x0) # returns a list
            //0x0.digits(2) # little endian converted number to list
            //ZZ([...], base=2) # converts bit list to integer
            //X.<x>=PolynomialRing(K, implementation='NTL')
            //f=K.fetch_int(210516491487439297890516450086636937392)*x^6+K.fetch_int(213831087762393238717613734)*x^5+K.fetch_int(75519418737987015648642996268311787752)*x^4+K.fetch_int(64135913958761740324356987267667485226)*x^3+K.fetch_int(255327767888114)*x^2+0*x^1+K.fetch_int(252539564172952511994475028137682775069)
            //f.factor()
            //f.roots()
            //f.roots()[0][0].integer_representation()
            //[q[0].integer_representation() for q in f.roots()]
            //[q.integer_representation() for q in f.list()]
            //f / f.list()[6]
            //(f / f.list()[6]).derivative()
            //(f / f.list()[6]).squarefree_decomposition()
            //f.gcd((f / f.list()[6]).derivative())
            //list(f.factor())
            //[[r.integer_representation() for r in q[0].list()] for q in list(f.factor())]
            //[[22432413633722445097943963007179307015L, 1],[170212518110133693769122543667194027856L, 1],[210158611274146281517224503535298446691L, 1],
            //[79510262696675812766390810347978617508L,35413549109971219848440623448364065564L,74290645703835062417165689337537425287L,1]]
            //[q.integer_representation() for q in ((f / f.list()[6]) / list(f.factor())[3][0]).numerator().list()]
            //(x^128-x) % (f / f.list()[6])
            //[q.integer_representation() for q in ((x^128-x) % (f / f.list()[6])).list()]

            //make monic polynomial
            BigInteger multiplier = modinvGF2k(coeff[0], M); //dividing by first coefficient means multiplying by its inverse!!!
            //319133248887973560380385766776623898219
            //Tuple<BigInteger[], BigInteger[]> monTup = divmodGFE2k(coeff, new BigInteger[] { coeff[0] });
            BigInteger [] monic = mulGFE2k(coeff, new BigInteger[] { multiplier });
            //BigInteger [] reslt = divmodGFE2k(monic, new BigInteger[] { BigInteger.One, BigInteger.Parse("74290645703835062417165689337537425287"), BigInteger.Parse("35413549109971219848440623448364065564"), BigInteger.Parse("79510262696675812766390810347978617508") }).Item1;
            //BigInteger[] monic = addGFE2k(monTup.Item1, mulGFE2k(new BigInteger[] { coeff[0] }, monTup.Item2));
            List<BigInteger[]> sqrF = sqrFree(monic);
            Tuple<BigInteger[], int>[] ddfRes = sqrF.SelectMany((sq) => ddf(sq)).ToArray();
            List<BigInteger> keyPosbl = new List<BigInteger>();
            for (int i = 0; i < ddfRes.Length; i++) {
                if (ddfRes[i].Item2 == 1)
                { //a degree one factor will be the key
                    BigInteger[][] edfRes = edf(rng, ddfRes[i].Item1, ddfRes[i].Item2);
                    for (int l = 0; l < edfRes.Length; l++) {
                        keyPosbl.Add(edfRes[l].Last());
                    }
                }
            }

            if (keyPosbl.Count != 1) {
                byte[] cyphDataOth = crypt_gcm(nonce, key, Enumerable.Repeat((byte)0, cyphData2.Length).ToArray());
                BigInteger tagOth = calc_gcm_tag(nonce, key, cyphDataOth, authData.Reverse().ToArray());
                //make forgery, query oracle for validity
                //forgery must have same length cypher text and authentication data or cannot be made with authentication key and must reverse AES key which is not possible
                for (int i = 0; i < keyPosbl.Count; i++) {
                    BigInteger stag = calc_gcm_s(nonce, keyPosbl[i], cyphData, authData, tag);
                    //try a forgery making sure the cypher data and authentication are the same length, the only way to forge
                    BigInteger trytag = calc_gcm_s(nonce, keyPosbl[i], cyphDataOth, authData, stag);
                    if (trytag == tagOth) { //oracle function
                        Console.WriteLine("Authentication Key found by forgery: " + keyPosbl[i]); break;
                    }
                }
                //also can solve by using the 3rd nonse to narrow down the root possibilities
                for (int ctr = 0; ctr < cyphData.Length; ctr += 16)
                { //zero pad to block align
                    coeff[padAuthData.Length / 16 + ctr / 16] = addGF2(new BigInteger(cyphData.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()),
                        new BigInteger(cyphDataOth.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()));
                }
                coeff[coeff.Length - 1] = addGF2(tag, tagOth);
                Sum = BigInteger.Zero;
                str = String.Empty;
                for (int i = 0; i < coeff.Length; i++)
                {
                    str += "K.fetch_int(" + coeff[i].ToString() + ")" + ((i != coeff.Length - 1) ? "*x^" + (coeff.Length - 1 - i).ToString() + "+" : "");
                    //str += new BigInteger(coeff[i].ToByteArray().Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()).ToString() + ((i != coeff.Length - 1) ? "*x^" + (coeff.Length - 1 - i).ToString() + "+" : "");
                    //str += new BigInteger(coeff[i].ToByteArray().Reverse().Concat(new byte[] { 0 }).ToArray()).ToString() + ((i != coeff.Length - 1) ? "*x^" + (coeff.Length - 1 - i).ToString() + "+" : "");
                    //str += new BigInteger(coeff[i].ToByteArray().Reverse().Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()).ToString() + ((i != coeff.Length - 1) ? "*x^" + (coeff.Length - 1 - i).ToString() + "+" : "");
                    Sum = addGF2(Sum, modmulGF2k(coeff[i], modexpGF2k(hkey, coeff.Length - 1 - i, M), M));
                }
                Console.WriteLine(str); //for Sage Math
                Console.WriteLine(new BigInteger(key.Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()));
                Console.WriteLine(hkey);
                Console.WriteLine(Sum); //== 0

                multiplier = modinvGF2k(coeff[0], M);
                monic = mulGFE2k(coeff, new BigInteger[] { multiplier });
                sqrF = sqrFree(monic);
                ddfRes = sqrF.SelectMany((sq) => ddf(sq)).ToArray();
                for (int i = 0; i < ddfRes.Length; i++) {
                    if (ddfRes[i].Item2 == 1)
                    { //a degree one factor will be the key
                        BigInteger[][] edfRes = edf(rng, ddfRes[i].Item1, ddfRes[i].Item2);
                        for (int l = 0; l < edfRes.Length; l++) {
                            if (keyPosbl.Contains(edfRes[l].Last())) {
                                Console.WriteLine("Authentication Key found by 3rd same nonce message: " + edfRes[l].Last());
                                break;
                            }
                        }
                    }
                }
            } else {
                Console.WriteLine("Authentication Key found: " + keyPosbl[0]);
            }
            Console.WriteLine("8.63");

            //SET 8 CHALLENGE 64
            p64:
            //https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf
            //messages of 2^17 blocks which are 128 bits each
            int nSize = 17; //too slow for now with 17 ~ 7 minutes for crypt_gcm and calc_gcm_tag, probably need GCM MAC library
            m = new byte[16 * (1 << nSize)];
            rng.GetBytes(m);

            cyphtag = crypt_gcm_fastlib(nonce, key, m, new byte[] { });
            cyphData = cyphDataVerify = cyphtag.Item1;
            tag = cyphtag.Item2 & 0xFFFFFFFF; //32-bit MAC
            //tag = calc_gcm_tag_fastlib(M, nonce, key, cyphData) & 0xFFFFFFFF; //32-bit MAC;
            //tag = calc_gcm_tag_fastlib(M, nonce, key, cyphData) & 0xFFFFFFFF; //32-bit MAC;

            //cyphData = crypt_gcm(nonce, key, m);
            //tag = calc_gcm_tag(nonce, key, cyphData, new byte[] { }) & 0xFFFFFFFF; //32-bit MAC
            //tgComp = tag.ToByteArray().Select((byte b) => ReverseBitsWith4Operations(b)).ToArray();

            hkey = new BigInteger(encrypt_ecb(key, Enumerable.Repeat((byte)0, 16).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()); //authentication key
            Console.WriteLine("Secret key: " + hkey);
            bool [,] Ms = new bool[128, 128];
            bool [][,] Msis = new bool[nSize][,];
            bool [,] Ad = new bool[128, 128];
            //can 0 out (n*128) / (ncols(X)) per operation, start with 16+1 non-zero row
            bool[,] T = null;
            bool [,] NT, Km = null, Xm = null;
            //compute Ms=1^2, x^2, (x^2)^2, ..., (x^127)^2
            for (int i = 0; i < 128; i++) {
                BigInteger sqr = modmulGF2k(BigInteger.One << i, BigInteger.One << i, M);
                for (int row = 0; row < 128; row++) {
                    Ms[row, i] = (sqr & (BigInteger.One << row)) != 0;
                }
            }
            //compute Ms^i
            Msis[0] = Ms;
            for (int ct = 1; ct < nSize; ct++) {
                Msis[ct] = matmul(Msis[ct-1], Ms);
            }
            //verify Ms*y=y^2
            /*for (int ct = 1; ct < nSize + 1; ct++) {
                BigInteger tagsqr = hkey; //modmulGF2k(hkey, hkey, M);
                for (int i = 0; i < (1 << ct) - 1; i++) {
                    tagsqr = modmulGF2k(tagsqr, hkey, M);
                }
                bool[,] tagm = new bool[128, 1];
                for (int i = 0; i < 128; i++)
                {
                    tagm[i, 0] = (hkey & (BigInteger.One << i)) != 0;
                }
                tagm = matmul(Msis[ct-1], tagm);
                BigInteger tagchk = BigInteger.Zero;
                for (int i = 0; i < 128; i++)
                {
                    if (tagm[i, 0]) tagchk |= (BigInteger.One << i);
                }
                if (tagchk != tagsqr) {}
            }*/
            //BigInteger sm = BigInteger.Zero;
            //bool[,] testMat = new bool[6, 4] { { false, false, false, false }, { false, true, false, false }, { false, false, true, true }, { true, true, false, true }, { true, true, false, true }, { true, true, true, true } };
            //testMat = transpose(gaussianElim(transpose(testMat)));
            //testMat = extractBasisMat(gaussianElim(augmentIdentityMat(testMat)));
            /*
            M = MatrixSpace(GF(2),6,4)
            A = M([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1])
            MI = MatrixSpace(GF(2),6,6)
            I = MI([1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1])
            A.echelon_form()
            I.echelon_form()
            A.kernel()
            I.kernel()
            A.transpose() * Matrix(GF(2), [1,0,0,0,0,0]).transpose()
            */
            //compute Mdi
            do
            {
                Tuple<bool[,], bool[][,]> AdAdn;
                AdAdn = calcAd(nSize, cyphData, M, Msis);
                Ad = AdAdn.Item1;
                bool[][,] Adn = AdAdn.Item2;

                bool[,] AdX = (Xm == null) ? Ad : matmul(Ad, Xm);
                bool[][,] AdnX = (Xm == null) ? Adn : Adn.Select((bool[,] curAdn) => matmul(curAdn, Xm)).ToArray();

                //compose T from Ad or Ad*X
                //build a dependency matrix T with n*128 columns and (n-1)*128 rows.Each column represents a bit we can flip,
                //and each row represents a cell of Ad(reading left - to - right, top - to - bottom).The cells where they intersect record whether a
                //particular free bit affects a particular bit of Ad.
                //16+13+11*9=128, 11 round solving, since rounds slow due to inefficient Gaussian and fast GCM tag makes collision search fast, balance with this
                int numcols = AdX.GetLength(1);
                int numrows = (Xm == null ? (nSize - 1) : Math.Min((nSize * 128) / numcols, 32 - 1 - 10));
                T = new bool[numrows * AdX.GetLength(1), nSize * 128];
                for (int c = 1; c < nSize + 1; c++) {
                    int ctr = 16 * ((1 << c) - 1);
                    //Console.WriteLine(c);
                    for (int flip = 0; flip < 128; flip++) {
                        byte[] cyphDataTest = cyphData.ToArray(); //make copy
                        cyphDataTest[cyphDataTest.Length - ctr + (flip / 8)] ^= (byte)(1 << (flip % 8));
                        BigInteger di = new BigInteger(cyphDataTest.Skip(cyphDataTest.Length - ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
                        //BigInteger olddi = new BigInteger(cyphData.Skip(cyphData.Length - ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
                        bool[,] Mdic = new bool[128, 128];
                        //int bit = (flip / 8) * 8 + 7 - (flip % 8);
                        for (int i = 0; i < 128; i++) {
                            BigInteger cnst = modmulGF2k(di, BigInteger.One << i, M);
                            for (int row = 0; row < 128; row++) {
                                Mdic[row, i] = (cnst & (BigInteger.One << row)) != 0;
                            }
                        }
                        bool[,] FlipAd = matmul(Mdic, Msis[c - 1]);
                        if (Xm != null) FlipAd = matmul(FlipAd, Xm);
                        //bool[,] Mdit = calcAd(nSize, cyphDataTest, M, Msis).Item1;
                        //each row represents a cell of Ad (reading left-to-right, top-to-bottom)
                        for (int row = 0; row < numrows; row++) { //first (n-1)*128 cells of Ad
                            for (int col = 0; col < numcols; col++) {
                                //if (Mdit[row, col] != ((FlipAd[row, col] == Adn[c][row, col]) ? Ad[row, col] : !Ad[row, col])) {
                                //    throw new ArgumentException();
                                //}
                                //if Ad set, hypothetical not set -> flip needed
                                //if Ad not set, hypothetical not set -> no flip
                                //if Ad set, hypothetical set -> flip does nothing
                                //if Ad not set, hypothetical set -> flip causes error
                                T[col + row * numcols, flip + (c - 1) * 128] = (FlipAd[row, col] != AdnX[c][row, col]); // ^ Ad[row, col]; // ((FlipAd[row, col] == Adn[c][row, col]) ? Ad[row, col] : !Ad[row, col]); //left to right, top to bottom
                            }
                        }
                    }
                    //sm = addGF2(sm, modmulGF2k(di, modexpGF2k(hkey, (BigInteger.One << (int)c), M), M));
                }
                //test T is correct by modifying bits calculating Ad and using T to calculate Ad
                /*{
                    bool[,] testT = matmul(T, testBits);
                    bool[,] FlipAd = (bool[,])Ad.Clone();
                    for (int i = 0; i < testT.GetLength(0); i++)
                    {
                        if (testT[i, 0]) FlipAd[i / 128, i % 128] = !FlipAd[i / 128, i % 128];
                    }
                    byte[] cyphDataTest = cyphData.ToArray(); //make copy
                    for (int i = 0; i < solutionBits.GetLength(0); i++) {
                        if (solutionBits[i, 0]) {
                            int c = i / 128 + 1;
                            int flip = i % 128;
                            int ctr = 16 * ((1 << c) - 1);
                            cyphDataTest[cyphDataTest.Length - ctr + (flip / 8)] ^= (byte)(1 << (flip % 8));
                        }
                    }
                    bool[,] cAd = calcAd(nSize, cyphDataTest, M, Msis).Item1;
                    for (int row = 0; row < nSize - 1; row++) {
                        for (int col = 0; col < 128; col++) {
                            if (FlipAd[row, col] != cAd[row, col]) {
                                throw new ArgumentException();
                            }
                        }
                    }
                }*/

                //already have transpose T, reduced row echelon form of transpose T via Gaussian elimination
                //https://en.wikipedia.org/wiki/Gaussian_elimination
                //https://en.wikipedia.org/wiki/Kernel_(linear_algebra)#Computation_by_Gaussian_elimination
                //bool[,] ident = new bool[(nSize - 1) * 128, (nSize - 1) * 128]; //identity matrix of size n*128
                //for (int i = 0; i < (nSize - 1) * 128; i++) ident[i, i] = true;
                NT = transpose(gaussianElim(T));
                //The rows that correspond to the zero rows in the reduced row echelon form of T transpose form a basis for N(T).
                //ident gaussian elimination yields ident but we need to concatenate the matrices via augmentation
                NT = extractBasisMat(gaussianElim(augmentIdentityMat(NT)));
                //since we are solving T * d = 0, can check all the d vectors of n*128 length to see if they satisfy this equation
                /*for (int i = 0; i < NT.GetLength(0); i++)
                {
                    bool[,] dvec = new bool[NT.GetLength(1), 1];
                    for (int col = 0; col < NT.GetLength(1); col++)
                    {
                        dvec[col, 0] = NT[i, col];
                    }
                    if (matmul(T, dvec).OfType<bool>().Any((bool v) => v))
                    {
                        //failure
                        throw new ArgumentException();
                    }
                }*/
                //query oracle
                numrows = NT.GetLength(0);
                numcols = NT.GetLength(1);
                byte[] rnd = new byte[numrows];
                int totalTries = 0;
                while (true) {
                    totalTries++;
                    bool[,] testBits = new bool[numcols, 1]; //new bool[solutionBits.GetLength(0), solutionBits.GetLength(1)]; //(bool[,])solutionBits.Clone();
                    rng.GetBytes(rnd);
                    for (int ci = 0; ci < numrows; ci++) {
                        if ((rnd[ci] & 1) != 0) { //odd byte means inclusion
                            for (int col = 0; col < numcols; col++) {
                                testBits[col, 0] ^= NT[ci, col];
                            }
                        }
                    }
                    byte[] cyphDataTest = cyphData.ToArray(); //make copy
                    for (int bit = 0; bit < numcols; bit++) {
                        if (testBits[bit, 0]) {
                            int c = bit / 128 + 1;
                            int flip = bit % 128;
                            int ctr = 16 * ((1 << c) - 1);
                            cyphDataTest[cyphDataTest.Length - ctr + (flip / 8)] ^= (byte)(1 << (flip % 8));
                        }
                    }
                    //FullTag = calc_gcm_tag(nonce, key, cyphDataTest, new byte[] { });
                    //BigInteger tagtest = FullTag & 0xFFFFFFFF; //32-bit MAC
                    BigInteger tagtest = calc_gcm_tag_fastlib(M, nonce, key, cyphDataTest) & 0xFFFFFFFF;
                    //tag = calc_gcm_tag_fastlib(M, nonce, key, cyphData) & 0xFFFFFFFF;
                    //tag & 0xFFFF == tagtest & 0xFFFF
                    if (tag == tagtest) {
                        //recompute Ad with flipped bits
                        //matsum(calcAd(nSize, cyphDataTest, M, Msis).Item1, Ad);
                        Ad = matsum(calcAd(nSize, cyphDataTest, M, Msis).Item1, Ad);
                        //AdX = matsum(matmul(calcAd(nSize, cyphDataTest, M, Msis).Item1, Xm), AdX);
                        AdX = Xm == null ? Ad : matmul(Ad, Xm);
                        break;
                    }
                }
                //If it succeeds, we've gained more than just an easy forgery. Examine
                //your matrix Ad.It should be a bunch of zero rows followed by a bunch
                //of nonzero rows.We care about the nonzero rows corresponding to the
                //bits of the tag.So if your tag is 16 bits, and you forced eight bits
                //to zero, you should have eight nonzero rows of interest.
                //update K
                List<int> AdRows = new List<int>();
                /*bool[,] tagm = new bool[128, 1];
                for (int i = 0; i < 128; i++) {
                    tagm[i, 0] = (hkey & (BigInteger.One << i)) != 0;
                }
                matmul(Ad, tagm);*/
                numcols = AdX.GetLength(1);
                for (int i = 0; i < 32; i++) {
                    int col;
                    for (col = 0; col < numcols; col++) {
                        if (AdX[i, col]) break;
                    }
                    if (col == numcols) continue;
                    AdRows.Add(i);
                }
                int CurRow = Km == null ? 0 : Km.GetLength(0);
                bool[,] KmNew = new bool[CurRow + AdRows.Count, Ad.GetLength(1)];
                if (Km != null) Array.Copy(Km, KmNew, Km.GetLength(0) * Km.GetLength(1));
                Km = KmNew;
                foreach (int i in AdRows) {
                    for (int col = 0; col < Ad.GetLength(1); col++) {
                        Km[CurRow, col] = Ad[i, col];
                    }
                    CurRow++;
                }
                //can verify K * h == 0
                //matmul(Km, tagm);
                //K needs 127 linearly independent vectors, if there are more should not make a difference in solution
                //instead of checking linear independence, its inferred by Xm being 1 row

                //X=transpose K, reduced row echelon form of K via Gaussian elimination
                Xm = transpose(gaussianElim(Km));
                Xm = extractBasisMat(gaussianElim(augmentIdentityMat(Xm)));
                Xm = transpose(Xm);
                //matmul(Ad, Xm);
                //if K has 127 linearly independent rows, X will be 1-dimensional subspace with exactly one nonzero vector - h
            } while (Xm.GetLength(1) != 1);
            BigInteger keyrecv = BigInteger.Zero;
            for (int i = 0; i < 128; i++)
            {
                if (Xm[i, 0]) keyrecv |= (BigInteger.One << i);
            }
            Console.WriteLine("Key found: " + keyrecv);
            //maximally zero out (1 << 17) * 128 / ncols(X) rows, 16 bits of each tag to start
            Console.WriteLine("8.64");

        }
        static bool fault(Tuple<BigInteger, BigInteger> Q1, Tuple<BigInteger, BigInteger> Q2)
        {
            BigInteger p = BigInteger.One << 20; //probability of fault is 1/p
            if (Q1.Item1 == 0 && Q1.Item2 == BigInteger.One) return false;
            return (Q1.Item1 * Q2.Item1) % p == 0;
        }
        static Tuple<BigInteger, BigInteger> addECfault(Tuple<BigInteger, BigInteger> P1, Tuple<BigInteger, BigInteger> P2, int a, BigInteger GF)
        {
            if (fault(P1, P2)) throw new ArgumentException();
            return addEC(P1, P2, a, GF);
        }
        //https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
        //there are two algorithms and in this problem we switch from index increasing to index decreasing
        static Tuple<BigInteger, BigInteger> scaleECdecrease(Tuple<BigInteger, BigInteger> x, BigInteger k, int a, BigInteger GF)
        {
            int count = GetBitSize(k) - 1 - 1;
            Tuple<BigInteger, BigInteger> result = x;
            while (count >= 0)
            {
                result = addEC(result, result, a, GF);
                if (((BigInteger.One << count) & k) != 0) result = addEC(result, x, a, GF);
                count--;
            }
            return result;
        }
        static bool scaleECfault(Tuple<BigInteger, BigInteger> x, BigInteger k, int a, BigInteger GF)
        {
            int count = GetBitSize(k) - 1 - 1;
            try {
                Tuple<BigInteger, BigInteger> result = x;
                while (count >= 0) {
                    result = addECfault(result, result, a, GF);
                    if (((BigInteger.One << count) & k) != 0) result = addECfault(result, x, a, GF);
                    count--;
                }
                return true; // result;
            }
            catch (ArgumentException) { return false; }
        }
        static int scaleECcheckfault(Tuple<BigInteger, BigInteger> x, BigInteger k, int a, BigInteger GF, int lastcount)
        {
            int count = GetBitSize(k) - 1 - 1;
            try {
                Tuple<BigInteger, BigInteger> result = x;
                while (count >= lastcount) {
                    result = addECfault(result, result, a, GF);
                    count--;
                    if (((BigInteger.One << (count+1)) & k) != 0) result = addECfault(result, x, a, GF);
                }
                return int.MinValue; // result;
            }
            catch (ArgumentException) { return count; }
        }
        static void Set9()
        {

            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] m = System.Text.Encoding.ASCII.GetBytes("crazy flamboyant for the rap enjoyment");
            goto p66;
            Tuple<byte[], BigInteger> cyphtag;
            byte[] cyphDataVerify;
            byte[] cyphData;
            BigInteger tag;
            BigInteger hkey; //authentication key

            byte[] key = new byte[16];
            rng.GetBytes(key);
            byte[] nonce = new byte[12]; // || 0^31 || 1
            rng.GetBytes(nonce);
            nonce = new byte[] { 0x51, 0x75, 0x3c, 0x65, 0x80, 0xc2, 0x72, 0x6f, 0x20, 0x71, 0x84, 0x14 };
            key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            //https://tools.ietf.org/html/rfc7714#section-16.1.1
            byte[] authData = System.Text.Encoding.ASCII.GetBytes("OFFICIAL SECRET: 12345678AB");
            BigInteger M = BigInteger.Parse("0100000000000000000000000000000087", System.Globalization.NumberStyles.HexNumber); //00E1000000000000000000000000000000 00E100000000000000000000000000000080 0100000000000000000000000000000087

            //https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf
            //messages of 2^17 blocks which are 128 bits each
            int nSize = 17; //too slow for now with 17 ~ 7 minutes for crypt_gcm and calc_gcm_tag, probably need GCM MAC library
            m = new byte[16 * (1 << nSize) - 8]; //partial 8 byte last block with 64 bits to attack via length variation
            rng.GetBytes(m);

            cyphtag = crypt_gcm_fastlib(nonce, key, m, new byte[] { });
            cyphData = cyphDataVerify = cyphtag.Item1;
            cyphData = cyphData.Concat(Enumerable.Repeat((byte)0, (16 - (cyphData.Length % 16)) % 16)).ToArray(); //just pad it up front
            tag = cyphtag.Item2 & 0xFFFFFFFF; //32-bit MAC
            //tag = calc_gcm_tag_fastlib(M, nonce, key, cyphData.Take(cyphData.Length - 8).ToArray()) & 0xFFFFFFFF; //32-bit MAC;
            //tag = calc_gcm_tag_fastlib(M, nonce, key, cyphData.Take(cyphData.Length - 8).ToArray()) & 0xFFFFFFFF; //32-bit MAC;

            //cyphData = crypt_gcm(nonce, key, m);
            //tag = calc_gcm_tag(nonce, key, cyphData, new byte[] { }) & 0xFFFFFFFF; //32-bit MAC
            //tgComp = tag.ToByteArray().Select((byte b) => ReverseBitsWith4Operations(b)).ToArray();

            hkey = new BigInteger(encrypt_ecb(key, Enumerable.Repeat((byte)0, 16).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()); //authentication key
            Console.WriteLine("Secret key: " + hkey);
            bool[,] Ms = new bool[128, 128];
            bool[][,] Msis = new bool[nSize][,];
            bool[,] Ad = new bool[128, 128];
            //can 0 out (n*128) / (ncols(X)) per operation, start with 16+1 non-zero row
            bool[,] T = null;
            bool[,] NT, Km = null, Xm = null;
            bool padLengthMode = true;
            //compute Ms=1^2, x^2, (x^2)^2, ..., (x^127)^2
            for (int i = 0; i < 128; i++)
            {
                BigInteger sqr = modmulGF2k(BigInteger.One << i, BigInteger.One << i, M);
                for (int row = 0; row < 128; row++)
                {
                    Ms[row, i] = (sqr & (BigInteger.One << row)) != 0;
                }
            }
            //compute Ms^i
            Msis[0] = Ms;
            for (int ct = 1; ct < nSize; ct++)
            {
                Msis[ct] = matmul(Msis[ct - 1], Ms);
            }
            //verify Ms*y=y^2
            /*for (int ct = 1; ct < nSize + 1; ct++) {
                BigInteger tagsqr = hkey; //modmulGF2k(hkey, hkey, M);
                for (int i = 0; i < (1 << ct) - 1; i++) {
                    tagsqr = modmulGF2k(tagsqr, hkey, M);
                }
                bool[,] tagm = new bool[128, 1];
                for (int i = 0; i < 128; i++)
                {
                    tagm[i, 0] = (hkey & (BigInteger.One << i)) != 0;
                }
                tagm = matmul(Msis[ct-1], tagm);
                BigInteger tagchk = BigInteger.Zero;
                for (int i = 0; i < 128; i++)
                {
                    if (tagm[i, 0]) tagchk |= (BigInteger.One << i);
                }
                if (tagchk != tagsqr) {}
            }*/
            //BigInteger sm = BigInteger.Zero;
            //bool[,] testMat = new bool[6, 4] { { false, false, false, false }, { false, true, false, false }, { false, false, true, true }, { true, true, false, true }, { true, true, false, true }, { true, true, true, true } };
            //testMat = transpose(gaussianElim(transpose(testMat)));
            //testMat = extractBasisMat(gaussianElim(augmentIdentityMat(testMat)));
            //compute Mdi
            do
            {
                Tuple<bool[,], bool[][,]> AdAdn;
                AdAdn = calcAd(nSize, cyphData, M, Msis, cyphData.Length - 8);
                Ad = AdAdn.Item1;
                bool[][,] Adn = AdAdn.Item2;
                //check Ad * h == sum(ci * h^i)
                /*for (int c = 0; c < Adn.Length + 1; c++) {
                    bool[,] tagm = new bool[128, 1];
                    for (int i = 0; i < 128; i++) {
                        tagm[i, 0] = (hkey & (BigInteger.One << i)) != 0;
                    }
                    tagm = matmul(c == Adn.Length ? Ad : Adn[c], tagm); //Ad * h = e
                    BigInteger tagchk = BigInteger.Zero;
                    for (int i = 0; i < 128; i++) {
                        if (tagm[i, 0]) tagchk |= (BigInteger.One << i);
                    }
                    Console.WriteLine(tagchk);
                }
                BigInteger valide = calc_gcm_tag_squares(nonce, key, cyphData.Take(cyphData.Length - 8).ToArray(), new byte[] { });*/
                //tagchk is e

                bool[,] AdX = (Xm == null) ? Ad : matmul(Ad, Xm);
                bool[][,] AdnX = (Xm == null) ? Adn : Adn.Select((bool[,] curAdn) => matmul(curAdn, Xm)).ToArray();

                //compose T from Ad or Ad*X
                //build a dependency matrix T with n*128 columns and (n-1)*128 rows.Each column represents a bit we can flip,
                //and each row represents a cell of Ad(reading left - to - right, top - to - bottom).The cells where they intersect record whether a
                //particular free bit affects a particular bit of Ad.
                //16+13+11*9=128, 11 round solving, since rounds slow due to inefficient Gaussian and fast GCM tag makes collision search fast, balance with this
                int numcols = AdX.GetLength(1);
                int numrows = (Xm == null ? (nSize - 1) : Math.Min((nSize * 128) / numcols, 32 - 1 - 10));
                T = new bool[numrows * AdX.GetLength(1), nSize * 128 - (padLengthMode ? 0 : (8 * 8))];
                for (int c = 1; c < nSize + 1; c++)
                {
                    int ctr = 16 * ((1 << c) - 1);
                    //Console.WriteLine(c + " " + ((padLengthMode || c != 1) ? 128 : 64) + " " + ((c - 1) * 128 - ((padLengthMode || c == 1) ? 0 : 64)));
                    for (int flip = 0; flip < ((padLengthMode || c != 1) ? 128 : 64); flip++)
                    {
                        byte[] cyphDataTest = cyphData.ToArray(); //make copy
                        cyphDataTest[cyphDataTest.Length - ctr + (flip / 8)] ^= (byte)(1 << (flip % 8));
                        BigInteger di = new BigInteger(cyphDataTest.Skip(cyphDataTest.Length - ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
                        //BigInteger olddi = new BigInteger(cyphData.Skip(cyphData.Length - ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
                        bool[,] Mdic = new bool[128, 128];
                        //int bit = (flip / 8) * 8 + 7 - (flip % 8);
                        for (int i = 0; i < 128; i++)
                        {
                            BigInteger cnst = modmulGF2k(di, BigInteger.One << i, M);
                            for (int row = 0; row < 128; row++)
                            {
                                Mdic[row, i] = (cnst & (BigInteger.One << row)) != 0;
                            }
                        }
                        bool[,] FlipAd = matmul(Mdic, Msis[c - 1]);
                        if (Xm != null) FlipAd = matmul(FlipAd, Xm);
                        //bool[,] Mdit = calcAd(nSize, cyphDataTest, M, Msis, cyphData.Length - 8).Item1;
                        //each row represents a cell of Ad (reading left-to-right, top-to-bottom)
                        for (int row = 0; row < numrows; row++)
                        { //first (n-1)*128 cells of Ad
                            for (int col = 0; col < numcols; col++)
                            {
                                //if (Mdit[row, col] != ((FlipAd[row, col] == Adn[c][row, col]) ? Ad[row, col] : !Ad[row, col])) {
                                //    throw new ArgumentException();
                                //}
                                //if Ad set, hypothetical not set -> flip needed
                                //if Ad not set, hypothetical not set -> no flip
                                //if Ad set, hypothetical set -> flip does nothing
                                //if Ad not set, hypothetical set -> flip causes error
                                T[col + row * numcols, flip + (c - 1) * 128 - ((padLengthMode || c == 1) ? 0 : 64)] = (FlipAd[row, col] != AdnX[c][row, col]); // ^ Ad[row, col]; // ((FlipAd[row, col] == Adn[c][row, col]) ? Ad[row, col] : !Ad[row, col]); //left to right, top to bottom
                            }
                        }
                    }
                    //sm = addGF2(sm, modmulGF2k(di, modexpGF2k(hkey, (BigInteger.One << (int)c), M), M));
                }
                //test T is correct by modifying bits calculating Ad and using T to calculate Ad
                //add column to T with Ad
                //solve using Gaussian elimination by zeroing out extra columns or last used row of Ad since they can be the free variables
                bool[,] solutionBits = new bool[T.GetLength(1), 1];
                bool[,] Adt = new bool[128, 128];
                bool[,] AdtX;
                if (padLengthMode) {
                    bool[,] solveT = new bool[T.GetLength(0), T.GetLength(1) + 1];
                    for (int row = 0; row < T.GetLength(0); row++) {
                        for (int col = 0; col < T.GetLength(1); col++) {
                            solveT[row, col] = T[row, col];
                        }
                    }
                    BigInteger dit = new BigInteger(BitConverter.GetBytes((ulong)0).Reverse().Concat(BitConverter.GetBytes((ulong)cyphData.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
                    for (int i = 0; i < 128; i++) {
                        BigInteger cnst = modmulGF2k(dit, BigInteger.One << i, M);
                        for (int row = 0; row < 128; row++) {
                            Adt[row, i] = (cnst & (BigInteger.One << row)) != 0;
                        }
                    }
                    AdtX = (Xm != null)  ? matmul(Adt, Xm) : Adt;
                    for (int row = 0; row < numrows; row++) {
                        for (int col = 0; col < numcols; col++) {
                            solveT[col + row * numcols, solveT.GetLength(1) - 1] = (AdtX[row, col] != AdnX[0][row, col]);
                        }
                    }
                    solveT = gaussianElim(solveT);
                    int ct = 0;
                    //last column is now the solution
                    for (int row = 0; row < solveT.GetLength(0); row++) {
                        while (!solveT[row, ct]) ct++;
                        solutionBits[ct, 0] = solveT[row, solveT.GetLength(1) - 1];
                        ct++;
                    }
                    Console.WriteLine(ct);
                }
                /*{
                    bool[,] testT = matmul(T, solutionBits);
                    bool[,] FlipAd = (bool[,])Ad.Clone();
                    for (int i = 0; i < testT.GetLength(0); i++)
                    {
                        if (testT[i, 0]) FlipAd[i / 128, i % 128] = !FlipAd[i / 128, i % 128];
                    }
                    byte[] cyphDataTest = cyphData.ToArray(); //make copy
                    for (int i = 0; i < solutionBits.GetLength(0); i++) {
                        if (solutionBits[i, 0]) {
                            int adjbit = (i + ((padLengthMode || (i < 64)) ? 0 : 64));
                            int c = adjbit / 128 + 1;
                            int flip = adjbit % 128;
                            int ctr = 16 * ((1 << c) - 1);
                            cyphDataTest[cyphDataTest.Length - ctr + (flip / 8)] ^= (byte)(1 << (flip % 8));
                        }
                    }
                    bool[,] cAd = calcAd(nSize, cyphDataTest, M, Msis, cyphData.Length - 8).Item1;
                    for (int row = 0; row < numrows; row++) {
                        for (int col = 0; col < numcols; col++) {
                            if (FlipAd[row, col] != cAd[row, col]) {
                                throw new ArgumentException();
                            }
                        }
                    }
                }*/

                //already have transpose T, reduced row echelon form of transpose T via Gaussian elimination
                //https://en.wikipedia.org/wiki/Gaussian_elimination
                //https://en.wikipedia.org/wiki/Kernel_(linear_algebra)#Computation_by_Gaussian_elimination
                //bool[,] ident = new bool[(nSize - 1) * 128, (nSize - 1) * 128]; //identity matrix of size n*128
                //for (int i = 0; i < (nSize - 1) * 128; i++) ident[i, i] = true;
                NT = transpose(gaussianElim(T));
                //The rows that correspond to the zero rows in the reduced row echelon form of T transpose form a basis for N(T).
                //ident gaussian elimination yields ident but we need to concatenate the matrices via augmentation
                NT = extractBasisMat(gaussianElim(augmentIdentityMat(NT)));
                //since we are solving T * d = 0, can check all the d vectors of n*128 length to see if they satisfy this equation
                /*for (int i = 0; i < NT.GetLength(0); i++)
                {
                    bool[,] dvec = new bool[NT.GetLength(1), 1];
                    for (int col = 0; col < NT.GetLength(1); col++)
                    {
                        dvec[col, 0] = NT[i, col];
                    }
                    if (matmul(T, dvec).OfType<bool>().Any((bool v) => v))
                    {
                        //failure
                        throw new ArgumentException();
                    }
                }*/
                //query oracle
                numrows = NT.GetLength(0);
                numcols = NT.GetLength(1);
                byte[] rnd = new byte[numrows];
                int totalTries = 0;
                while (true)
                {
                    totalTries++;
                    bool[,] testBits = padLengthMode ? (bool[,])solutionBits.Clone() : new bool[numcols, 1]; //new bool[solutionBits.GetLength(0), solutionBits.GetLength(1)];
                    if (numrows <= 16) { //exhaustive search before toggling mode and moving on to non-length padding mode
                        if (padLengthMode && totalTries == (1 << numrows)) {
                            padLengthMode = !padLengthMode;
                            totalTries = -1;
                            break;
                        }
                        for (int ci = 0; ci < numrows; ci++) {
                            if (((1 << ci) & totalTries) != 0) { //totalTries bits indicate combinations
                                for (int col = 0; col < numcols; col++) {
                                    testBits[col, 0] ^= NT[ci, col];
                                }
                            }
                        }
                    } else {
                        rng.GetBytes(rnd);
                        for (int ci = 0; ci < numrows; ci++) {
                            if ((rnd[ci] & 1) != 0) { //odd byte means inclusion
                                for (int col = 0; col < numcols; col++) {
                                    testBits[col, 0] ^= NT[ci, col];
                                }
                            }
                        }
                    }
                    byte[] cyphDataTest = padLengthMode ? cyphData.ToArray() : cyphData.Take(cyphData.Length - 8).ToArray(); //make copy
                    for (int bit = 0; bit < numcols; bit++)
                    {
                        if (testBits[bit, 0])
                        {
                            int adjbit = (bit + ((padLengthMode || (bit < 64)) ? 0 : 64));
                            int c = adjbit / 128 + 1;
                            int flip = adjbit % 128;
                            int ctr = 16 * ((1 << c) - 1);
                            cyphDataTest[cyphData.Length - ctr + (flip / 8)] ^= (byte)(1 << (flip % 8)); //careful to use original length here
                        }
                    }
                    //FullTag = calc_gcm_tag(nonce, key, cyphDataTest, new byte[] { });
                    //BigInteger tagtest = FullTag & 0xFFFFFFFF; //32-bit MAC
                    BigInteger tagtest = calc_gcm_tag_fastlib(M, nonce, key, cyphDataTest) & 0xFFFFFFFF;
                    //tag = calc_gcm_tag_fastlib(M, nonce, key, cyphData) & 0xFFFFFFFF;
                    //tag = calc_gcm_tag_fastlib(M, nonce, key, cyphData.Take(cyphData.Length - 8).ToArray()) & 0xFFFFFFFF;
                    //tag & 0xFFFF == tagtest & 0xFFFF
                    if (tag == tagtest)
                    {
                        //recompute Ad with flipped bits
                        //matsum(calcAd(nSize, cyphDataTest, M, Msis, cyphData.Length - 8).Item1, Ad);
                        if (!padLengthMode) cyphDataTest = cyphDataTest.Concat(Enumerable.Repeat((byte)0, (16 - (cyphDataTest.Length % 16)) % 16)).ToArray();
                        Ad = matsum(calcAd(nSize, cyphDataTest, M, Msis, cyphData.Length - 8).Item1, Ad);
                        if (padLengthMode) {
                            for (int ci = 0; ci < Adt.GetLength(0); ci++) {
                                for (int col = 0; col < Adt.GetLength(1); col++) {
                                    Ad[ci, col] ^= (Adt[ci, col] != Adn[0][ci, col]);
                                }
                            }
                        }
                        //AdX = matsum(matmul(calcAd(nSize, cyphDataTest, M, Msis, cyphData.Length - 8).Item1, Xm), AdX);
                        AdX = Xm == null ? Ad : matmul(Ad, Xm);
                        break;
                    }
                }
                if (totalTries == -1) continue;
                //If it succeeds, we've gained more than just an easy forgery. Examine
                //your matrix Ad.It should be a bunch of zero rows followed by a bunch
                //of nonzero rows.We care about the nonzero rows corresponding to the
                //bits of the tag.So if your tag is 16 bits, and you forced eight bits
                //to zero, you should have eight nonzero rows of interest.
                //update K
                List<int> AdRows = new List<int>();
                bool[,] tagm = new bool[128, 1];
                for (int i = 0; i < 128; i++) {
                    tagm[i, 0] = (hkey & (BigInteger.One << i)) != 0;
                }
                matmul(Ad, tagm);
                numcols = AdX.GetLength(1);
                for (int i = 0; i < 32; i++)
                {
                    int col;
                    for (col = 0; col < numcols; col++)
                    {
                        if (AdX[i, col]) break;
                    }
                    if (col == numcols) continue;
                    AdRows.Add(i);
                }
                int CurRow = Km == null ? 0 : Km.GetLength(0);
                bool[,] KmNew = new bool[CurRow + AdRows.Count, Ad.GetLength(1)];
                if (Km != null) Array.Copy(Km, KmNew, Km.GetLength(0) * Km.GetLength(1));
                Km = KmNew;
                foreach (int i in AdRows) {
                    for (int col = 0; col < Ad.GetLength(1); col++) {
                        Km[CurRow, col] = Ad[i, col];
                    }
                    CurRow++;
                }
                //Ad * h = Adt * h or (Ad - Adt) * h = 0
                //can verify K * h == 0 (if using Ad without subtracting Adt)
                matmul(Km, tagm);
                //K needs 127 linearly independent vectors, if there are more should not make a difference in solution
                //instead of checking linear independence, its inferred by Xm being 1 row

                //X=transpose K, reduced row echelon form of K via Gaussian elimination
                Xm = transpose(gaussianElim(Km));
                Xm = extractBasisMat(gaussianElim(augmentIdentityMat(Xm)));
                Xm = transpose(Xm);
                //matmul(Ad, Xm);
                //if K has 127 linearly independent rows, X will be 1-dimensional subspace with exactly one nonzero vector - h
            } while (Xm.GetLength(1) != 1);
            BigInteger keyrecv = BigInteger.Zero;
            for (int i = 0; i < 128; i++)
            {
                if (Xm[i, 0]) keyrecv |= (BigInteger.One << i);
            }
            Console.WriteLine("Key found: " + keyrecv);
            //maximally zero out (1 << 17) * 128 / ncols(X) rows, 16 bits of each tag to start
            Console.WriteLine("9.65");
        p66:
            //start with code from #59, addEC/scaleEC to inject fault
            int EaOrig = -95051, Ea = EaOrig, Eb = 11279326;
            BigInteger Gx = 182, Gy = BigInteger.Parse("85518893674295321206118380980485522083"),
                GF = BigInteger.Parse("233970423115425145524320034830162017933"), BPOrd = BigInteger.Parse("29246302889428143187362802287225875743"), Ord = BPOrd * 2 * 2 * 2;
            Tuple<BigInteger, BigInteger> G = new Tuple<BigInteger, BigInteger>(Gx, Gy);
            int count = GetBitSize(BPOrd);
            BigInteger ASecret;
            do { ASecret = Crypto.GetNextRandomBig(rng, BPOrd); } while (ASecret <= 1 || GetBitSize(ASecret) != count);
            Tuple<BigInteger, BigInteger> APub = scaleEC(G, ASecret, Ea, GF);
            BigInteger BSecret;
            do { BSecret = Crypto.GetNextRandomBig(rng, BPOrd); } while (BSecret <= 1 || GetBitSize(BSecret) != count);
            Tuple<BigInteger, BigInteger> BPub = scaleECdecrease(G, BSecret, Ea, GF);
            //BPub.Item1 == scaleEC(G, BSecret, Ea, GF).Item1 && BPub.Item2 == scaleEC(G, BSecret, Ea, GF).Item2;
            Tuple<BigInteger, BigInteger> AShared = scaleECdecrease(BPub, ASecret, Ea, GF);
            Tuple<BigInteger, BigInteger> BShared = scaleECdecrease(APub, BSecret, Ea, GF);
            Console.WriteLine("Base point and order correct: " + (scaleECdecrease(G, BPOrd, Ea, GF).Equals(new Tuple<BigInteger, BigInteger>(0, 1))));
            Console.WriteLine("Shared Secrets Identical: " + (AShared.Item1 == BShared.Item1));

            BigInteger d = BSecret;
            //do { d = Crypto.GetNextRandomBig(rng, BPOrd); } while (d <= 1 || GetBitSize(d) != count); //Bob's secret key
            Console.WriteLine("Secret key generated: " + d);
            BigInteger k, kset, hx, hy;
            Tuple<BigInteger, BigInteger> h;
            List<Tuple<int, bool>> recoveredBits = new List<Tuple<int, bool>>();
            //List<Tuple<int, bool>> probableBits = new List<Tuple<int, bool>>();
            count--;
            BigInteger knownKey = BigInteger.One << count;
            count--;
            //recoveredBits.Add(new Tuple<int, bool>(count, true));
            int res;
            while (count >= 1) {
                k = knownKey;
                kset = k ^ (BigInteger.One << count);
                do {
                    do {
                        //random point with between x value between 1..Ord
                        do { hx = Crypto.GetNextRandomBig(rng, Ord); } while (hx <= 1);
                        hy = TonelliShanks(rng, posRemainder(hx * hx * hx + Ea * hx + Eb, GF), GF);
                    } while (hy == BigInteger.Zero);
                    h = new Tuple<BigInteger, BigInteger>(hx, hy);
                    res = scaleECcheckfault(h, k, Ea, GF, count-1);
                } while (!((res != count-1) ^ (scaleECcheckfault(h, kset, Ea, GF, count-1) != count-1))); //instead of caring about only one match first, check both at once to speed up
                //query oracle
                bool leaksBit = scaleECfault(h, d, Ea, GF);
                if (!leaksBit) { //probably opposite but can confirm if find fault in other direction
                    if (res == count-1) {
                        BigInteger tmp = k;
                        k = kset;
                        kset = tmp;
                    }
                    do {
                        do {
                            //random point with between x value between 1..Ord
                            do { hx = Crypto.GetNextRandomBig(rng, Ord); } while (hx <= 1);
                            hy = TonelliShanks(rng, posRemainder(hx * hx * hx + Ea * hx + Eb, GF), GF);
                        } while (hy == BigInteger.Zero);
                        h = new Tuple<BigInteger, BigInteger>(hx, hy);
                        res = scaleECcheckfault(h, k, Ea, GF, count-1);
                    } while (res != count-1 || (scaleECcheckfault(h, kset, Ea, GF, count - 1) == count - 1));
                    leaksBit = scaleECfault(h, d, Ea, GF);
                }
                if (leaksBit) {
                    knownKey = (res != count-1) ? k : kset;
                    if ((knownKey & d) != knownKey) {
                        break;
                    }
                    count--;
                } //otherwise it found faults both ways so must try again as inconclusive
            }
            //last bit can only be determined if it is turned off since turned off yields no operations hence no fault and cannot establish turned on
            //so easier that we just determine it with a single simple operation
            Tuple<BigInteger, BigInteger> test = scaleECdecrease(APub, knownKey, Ea, GF);
            if (test.Item1 != AShared.Item1 || test.Item2 != AShared.Item2)
                knownKey |= BigInteger.One;
            Console.WriteLine("Secret key determined: " + knownKey);
            Console.WriteLine("9.66");
        }
        static void Main(string[] args)
        {
            //Set1();
            //Set2();
            //Set3();
            //Set4();
            //Set5();
            //Set6();
            //Set7();
            Set8();
            //Set9();

            Console.ReadKey();
        }
    }
}