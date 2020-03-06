using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Security.Cryptography;

namespace Cryptopals
{
    class Utility
    {
        public class ByteArrayComparer : EqualityComparer<byte[]>
        {
            public override bool Equals(byte[] left, byte[] right)
            {
                if (left == null || right == null)
                {
                    return left == right;
                }
                if (ReferenceEquals(left, right))
                {
                    return true;
                }
                if (left.Length != right.Length)
                {
                    return false;
                }
                return left.SequenceEqual(right);
            }
            public override int GetHashCode(byte[] obj)
            {
                if (obj == null)
                {
                    throw new ArgumentNullException("obj");
                }
                //shortcut which works well for crypto data since hash function must be fast
                if (obj.Length >= 4)
                {
                    return BitConverter.ToInt32(obj, 0);
                }
                // Length occupies at most 2 bits. Might as well store them in the high order byte
                int value = obj.Length;
                foreach (var b in obj)
                {
                    value <<= 8;
                    value += b;
                }
                return value;
            }
        }
        static public string HexEncode(byte[] input)
        {
            return string.Join(string.Empty, input.Select(d => d.ToString("x2")));
        }
        static public byte[] HexDecode(string input)
        {
            return Enumerable.Range(0, input.Length / 2)
                .Select(i => byte.Parse(input.Substring(i * 2, 2),
                    System.Globalization.NumberStyles.AllowHexSpecifier)).ToArray();
        }
        static public byte[] FixedXOR(byte[] a, byte[] b)
        {
            return a.Select((d, i) => (byte)(d ^ b[i])).ToArray();
        }
        static public byte[] XORRepKey(byte[] a, byte[] b)
        {
            return Enumerable.Repeat(b, a.Length / b.Length + 1)
                .SelectMany(d => d).Take(a.Length).ToArray();
        }
        static public double CharacterScore(byte[] s, byte[] exclude, Dictionary<byte, double> freqs)
        {
            Dictionary<byte, int> j = s.ToLookup(c => c).ToDictionary(k => k.Key, v => v.Count()); //group them by frequency
            //use unprintable characters as immediate exclusion except new line...
            if (exclude.Select(i => j.ContainsKey(i)).Any(i => i)) return 0;
            return freqs.Select(kv => j.ContainsKey(kv.Key) ? kv.Value * j[kv.Key] : 0).Sum() * 100;
        }
        static public Tuple<byte, double>[] GetLeastXORCharacterScore(byte[] s)
        {
            byte[] exclude = Enumerable.Range(0, 10).Concat(Enumerable.Range(11, 21)).Concat(Enumerable.Range(127, 129)).Select(i => (byte)i).Concat("$#<>[]{}+^*&%()~|".Select(i => (byte)i)).ToArray();
            //average word length in English is 4.79 letters, so space frequency 1/4.79, assuming punctuation was considered as apart of the word
            //http://www.viviancook.uk/Punctuation/PunctFigs.htm
            Dictionary<byte, double> freqs = new Dictionary<byte, double> {
                [(byte)'.'] = 0.0653, [(byte)','] = 0.0616, [(byte)';'] = 0.0032, [(byte)':'] = 0.0034, [(byte)'!'] = 0.0033,
                [(byte)'?'] = 0.0056, [(byte)'\''] = 0.0243, [(byte)'"'] = 0.0267, [(byte)'-'] = 0.0153, [(byte)' '] = 1 / 4.79 };
            //http://academic.regis.edu/jseibert/Crypto/Frequency.pdf a-z/A-Z
            //https://en.wikipedia.org/wiki/Letter_frequency
            double[] freq = { .08167, .01492, .02202, .04253, .12702, .02228, .02015, .06094, .06966, .00153,
                              .01292, .04025, .02406, .06749, .07507, .01929, .00095, .05987, .06327, .09356,
                              .02758, .00978, .02560, .00150, .01994, .00077};
            for (int i = 0; i < freq.Length; i++) {
                freqs.Add((byte)('A' + i), freq[i]);
                freqs.Add((byte)('a' + i), freq[i]);
            }
            return Enumerable.Range(0, 256).Select(i =>
                new Tuple<byte, double>((byte)i,
                    CharacterScore(FixedXOR(s, Enumerable.Repeat((byte)i, s.Length).ToArray()), exclude, freqs))).Where(x => x.Item2 != 0).OrderByDescending(x => x.Item2).ToArray();
        }
        static public int CountBitsSet(byte v) //Counting bits set, Brian Kernighan's way
        {
            int c;
            for (c = 0; v != 0; c++) { v &= (byte)(v - 1); }
            return c;
        }
        static public int HammingDistance(byte[] a, byte[] b)
        {
            return a.Select((d, i) => CountBitsSet((byte)(d ^ b[i]))).Sum();
        }
        static public byte[] decrypt_ecb(byte[] key, byte[] input)
        {
            System.Security.Cryptography.AesManaged aes128 =
                new System.Security.Cryptography.AesManaged();
            //System.Security.Cryptography.RijndaelManaged aes128 =
            //  new System.Security.Cryptography.RijndaelManaged();
            aes128.Key = key;
            aes128.Mode = System.Security.Cryptography.CipherMode.ECB;
            //critical or cannot do one block at a time...
            aes128.Padding = System.Security.Cryptography.PaddingMode.None;
            byte[] o = new byte[input.Length];
            int offset = 0;
            //could use a MemoryStream and CryptoStream to make this automated and robust...
            //but the block aspect is encapsulated away which is to be a highlight
            System.Security.Cryptography.ICryptoTransform transform = aes128.CreateDecryptor();
            while (offset < input.Length)
            {
                if (offset + aes128.BlockSize / 8 <= input.Length)
                {
                    offset += transform.TransformBlock(input, offset, aes128.BlockSize / 8,
                                                       o, offset);
                }
                else
                {
                    transform.TransformFinalBlock(input, offset, input.Length - offset)
                        .CopyTo(o, offset);
                    break;
                }
            }
            return o;
        }
        static public bool is_ecb_mode(byte[] data)
        {
            HashSet<byte[]> dict = new HashSet<byte[]>(new ByteArrayComparer());
            for (int i = 0; i < data.Length / 16; i++)
            {
                byte[] n = data.Skip(i * 16).Take(16).ToArray();
                if (dict.Contains(n))
                {
                    return true; //detected
                }
                else
                {
                    dict.Add(n);
                }
            };
            return false;
        }
        static public byte[] PKCS7Pad(byte[] input, int blocksize)
        {
            int rem = (blocksize - (input.Length % blocksize));
            return Enumerable.Concat(input, Enumerable.Repeat((byte)rem, rem)).ToArray();
        }
        static public byte[] encrypt_ecb(byte[] key, byte[] input)
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
            while (offset < input.Length)
            {
                if (offset + aes128.BlockSize / 8 <= input.Length)
                {
                    offset += transform.TransformBlock(input, offset, aes128.BlockSize / 8, o, offset);
                }
                else
                {
                    transform.TransformFinalBlock(input, offset, input.Length - offset).CopyTo(o, offset);
                    break;
                }
            }
            return o;
        }

        static public byte[] encrypt_cbc(byte[] iv, byte[] key, byte[] input)
        {
            byte[] o = new byte[input.Length];
            System.Security.Cryptography.AesManaged aes128 = new System.Security.Cryptography.AesManaged();
            aes128.Key = key;
            aes128.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes128.Padding = System.Security.Cryptography.PaddingMode.None; //critical or cannot do one block at a time...
            int offset = 0;
            System.Security.Cryptography.ICryptoTransform transform = aes128.CreateEncryptor();
            while (offset < input.Length)
            {
                if (offset + aes128.BlockSize / 8 <= input.Length)
                {
                    FixedXOR(input.Skip(offset).Take(aes128.BlockSize / 8).ToArray(),
                        (offset != 0) ? o.Skip(offset - aes128.BlockSize / 8).Take(aes128.BlockSize / 8).ToArray() : iv).CopyTo(o, offset);
                    offset += transform.TransformBlock(o, offset, aes128.BlockSize / 8, o, offset);
                }
                else
                {
                    FixedXOR(input.Skip(offset).Take(input.Length - offset).ToArray(),
                        (offset != 0) ? o.Skip(offset - aes128.BlockSize / 8).Take(input.Length - offset).ToArray() : iv).CopyTo(o, offset);
                    transform.TransformFinalBlock(o, offset, input.Length - offset).CopyTo(o, offset);
                }
            }
            return o;
        }
        static public byte[] decrypt_cbc(byte[] iv, byte[] key, byte[] input)
        {
            byte[] o = new byte[input.Length];
            System.Security.Cryptography.AesManaged aes128 = new System.Security.Cryptography.AesManaged();
            aes128.Key = key;
            aes128.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes128.Padding = System.Security.Cryptography.PaddingMode.None; //critical or cannot do one block at a time...
            int offset = 0;
            System.Security.Cryptography.ICryptoTransform transform = aes128.CreateDecryptor();
            while (offset < input.Length)
            {
                if (offset + aes128.BlockSize / 8 <= input.Length)
                {
                    offset += transform.TransformBlock(input, offset, aes128.BlockSize / 8, o, offset);
                    FixedXOR(o.Skip(offset - aes128.BlockSize / 8).Take(aes128.BlockSize / 8).ToArray(),
                        (offset != aes128.BlockSize / 8) ? input.Skip(offset - aes128.BlockSize / 8 * 2).Take(aes128.BlockSize / 8).ToArray() : iv).CopyTo(o, offset - aes128.BlockSize / 8);
                }
                else
                {
                    transform.TransformFinalBlock(input, offset, input.Length - offset).CopyTo(o, offset);
                    FixedXOR(o.Skip(offset - aes128.BlockSize / 8).Take(input.Length - offset).ToArray(),
                        (offset != aes128.BlockSize / 8) ? input.Skip(offset - aes128.BlockSize / 8 * 2).Take(input.Length - offset).ToArray() : iv).CopyTo(o, offset - aes128.BlockSize / 8);
                }
            }
            return o;
        }
        static public int GetBitSizeSlow(BigInteger num)
        {
            int s = 0;
            while ((BigInteger.One << s) <= num) s++;
            //if (s != GetBitSizeBinSearch(num)) throw new ArgumentException();
            return s;
        }
        static public int GetBitSizeReflection(BigInteger num)
        {
            //uint[] bits = (uint[])typeof(BigInteger).GetField("_bits", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).GetValue(num);
            uint[] bits = (uint[])typeof(BigInteger).GetProperty("_Bits", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).GetValue(num);
            if (bits == null)
            {
                //int sign = (int)typeof(BigInteger).GetField("_sign", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).GetValue(num);
                int sign = (int)typeof(BigInteger).GetProperty("_Sign", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).GetValue(num);
                bits = new uint[] { (uint)(sign < 0 ? sign & int.MaxValue : sign) };
            }
            int uintLength = (int)typeof(BigInteger).GetMethod("Length", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic).Invoke(null,
                new object[] { bits });
            int topbits = (int)typeof(BigInteger).GetMethod("BitLengthOfUInt", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic).Invoke(num, new object[] { bits[uintLength - 1] });
            return (uintLength - 1) * sizeof(uint) * 8 + topbits;
        }
        static public int GetBitSize(BigInteger num)
        {
            byte[] bytes = num.ToByteArray();
            int size = bytes.Length;
            if (size == 0) return 0;
            int v = bytes[size - 1]; // 8-bit value to find the log2 of 
            if (v == 0) return (size - 1) * 8;
            int r; // result of log2(v) will go here
            int shift;
            r = (v > 0xF) ? 4 : 0; v >>= r;
            shift = (v > 0x3) ? 2 : 0; v >>= shift; r |= shift;
            r |= (v >> 1);
            return (size - 1) * 8 + r + 1;
        }
        static public int GetBitSizeHiSearch(BigInteger num) //power of 2 search high, then binary search
        {
            if (num.IsZero) return 0;
            int lo = 0, hi = 1;
            while ((BigInteger.One << hi) <= num) { lo = hi; hi <<= 1; }
            //if (GetBitSizeCopy(num) != GetBitSizeBinSearch(num, lo, hi)) throw new ArgumentException();
            return GetBitSizeBinSearch(num, lo, hi);
        }
        static int GetBitSizeBinSearch(BigInteger num, int lo, int hi)
        {
            int mid = (hi + lo) >> 1;
            while (lo <= hi)
            {
                if ((BigInteger.One << mid) <= num) lo = mid + 1;
                else hi = mid - 1;
                mid = (hi + lo) >> 1;
            }
            return mid + 1;
        }
        static public int GetBitSizeRecurseBinSearch(BigInteger num)
        { //instead of 0, 1, 2, 3, 4... use 0, 1, 3, 7, 15, etc
            int s = 0, t = 1, oldt = 1;
            if (t <= 0) return 0;
            while (true)
            {
                if ((BigInteger.One << (s + t)) <= num) { oldt = t; t <<= 1; }
                else if (t == 1) break;
                else { s += oldt; t = 1; }
            }
            //if (s + 1 != GetBitSizeBinSearch(num)) throw new ArgumentException();
            return s + 1;
        }
        static public int GetNextRandom(RandomNumberGenerator rnd, int Maximum)
        {
            int i = GetBitSize(Maximum - 1);
            byte[] tmp = new byte[(i + 7) >> 3];
            int ret;
            do //try to avoid statistical bias but this is not perfect
            {
                rnd.GetBytes(tmp);
                if ((i % 8) != 0) tmp[0] &= (byte)((1 << (i % 8)) - 1);
                ret = BitConverter.ToInt32(tmp.Concat(new byte[] { 0, 0, 0, 0 }).ToArray(), 0);
            } while (Maximum <= ret);
            return ret;
        }
        static public byte[] PKCS7Strip(byte[] inp)
        {
            if (inp.Length == 0) return inp;
            //on even blocks a padding of a whole block is there so we can always properly strip
            byte last = inp.Last();
            if (last >= 1 && last <= 16 && inp.Skip(inp.Length - (int)last).All(x => x == last)) return inp.Take(inp.Length - (int)last).ToArray();
            throw new ArgumentException();
        }
        static public bool PKCS7Check(byte[] inp)
        {
            if (inp.Length == 0) return true;
            //on even blocks a padding of a whole block is there so we can always properly strip
            byte last = inp.Last();
            if (last >= 1 && last <= 16 && inp.Skip(inp.Length - (int)last).All(x => x == last)) return true;
            return false;

        }
        static public byte[] crypt_ctr(ulong nonce, byte[] key, byte[] input)
        {
            int l = input.Length;
            byte[] o = new byte[l];
            for (ulong ctr = 0; (int)ctr < l; ctr += 16)
            {
                //BitConverter uses little endian order
                int rem = Math.Min(l - (int)ctr, 16);
                FixedXOR(input.Skip((int)ctr).Take(rem).ToArray(), encrypt_ecb(key, BitConverter.GetBytes(nonce).Concat(BitConverter.GetBytes(ctr >> 4)).ToArray()).Take(rem).ToArray()).CopyTo(o, (int)ctr);
            }
            return o;
        }
    }
}
