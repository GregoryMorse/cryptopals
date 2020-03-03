using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
        static public int CharacterScore(byte[] s)
        {
            //http://academic.regis.edu/jseibert/Crypto/Frequency.pdf a-z/A-Z
            double[] freq = { .082, .015, .028, .043, .127, .022, .020, .061, .070, .002,
                              .008, .040, .024, .067, .075, .019, .001, .060, .063, .091,
                              .028, .010, .023, .001, .020, .001};
            ILookup<byte, byte> j = s.ToLookup(c => c); //group them by frequency
            //30% weight for space or a couple false positives with high weighted letters can win
            //a negative weight for bad characters would make it even better...
            return (int)(((j.Contains((byte)' ') ? .3 * j[(byte)' '].Count() : 0) +
                freq.Select((d, i) =>
                    d * ((j.Contains((byte)('a' + i)) ? j[(byte)('a' + i)].Count() : 0) +
                         (j.Contains((byte)('A' + i)) ? j[(byte)('A' + i)].Count() : 0))).Sum())
                * 100);
        }
        static public dynamic GetLeastXORCharacterScore(byte[] s)
        {
            //assume 0 is starting maximum is fine in this scenario regardless
            dynamic maxItem = new { index = 0, score = 0 };
            foreach (dynamic val in Enumerable.Range(0, 256).Select(i =>
                new { index = (byte)i, score =
                    CharacterScore(FixedXOR(s, Enumerable.Repeat((byte)i, s.Length).ToArray())) }))
            {
                if (val.score > maxItem.score) { maxItem = val; }
            }
            return maxItem;
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
    }
}
