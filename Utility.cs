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
        static public ValueTuple<int, byte[]> breakRepXorKey(int minLen, int maxLen, byte[] b)
        {
            Tuple<int, double> minItem = Enumerable.Range(2, maxLen - minLen + 1).
                Select(j => new Tuple<int, double>(
                //hamming all neighboring pieces except for the last one if its not a multiple
                //this is slower but maximal accuracy! must use double for divisions...
                j,
                //1 / (ciphLen / i - 1) / i == (i / (ciphLen - i)) / i == 1 / (ciphLen - i)
                (double)Enumerable.Range(0, b.Length / j - 1).Select(l =>
                        HammingDistance(b.Skip(l * j).Take(j).ToArray(),
                        b.Skip((l + 1) * j).Take(j).ToArray())).Sum()
                        / ((double)b.Length - (double)j)
            )).OrderBy(x => x.Item2).First();
            return (minItem.Item1, Enumerable.Range(0, (int)minItem.Item1).Select(j =>
                    (byte)GetLeastXORCharacterScore(b.Where((c, i) =>
                        i % (int)minItem.Item1 == j).ToArray()).First().Item1).ToArray());
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
        static public string[] ReadUtilityFile(string fileName)
        {
            return System.IO.File.ReadAllLines("../../" + fileName);
        }
        public delegate Tuple<byte, double>[] GetLeastXORBiTrigramScoreProto(byte[] p, byte[] r, byte[] s, byte[] t);
        static public GetLeastXORBiTrigramScoreProto GetLeastXORBiTrigramScoreGen(Dictionary<string, double> lastWords)
        {
            //http://norvig.com/mayzner.html
            /*Dictionary<string, double> bigramfreq = new Dictionary<string, double>
            {   ["TH"]= 3.56, ["HE"]= 3.07, ["IN"]= 2.43, ["ER"]= 2.05, ["AN"]= 1.99,
                ["RE"]= 1.85, ["ON"]= 1.76, ["AT"]= 1.49, ["EN"]= 1.45, ["ND"]= 1.35,
                ["TI"]= 1.34, ["ES"]= 1.34, ["OR"]= 1.28, ["TE"]= 1.20, ["OF"]= 1.17,
                ["ED"]= 1.17, ["IS"]= 1.13, ["IT"]= 1.12, ["AL"]= 1.09, ["AR"]= 1.07,
                ["ST"]= 1.05, ["TO"]= 1.04, ["NT"]= 1.04, ["NG"]= 0.95, ["SE"]= 0.93,
                ["HA"]= 0.93, ["AS"]= 0.87, ["OU"]= 0.87, ["IO"]= 0.83, ["LE"]= 0.83,
                ["VE"]= 0.83, ["CO"]= 0.79, ["ME"]= 0.79, ["DE"]= 0.76, ["HI"]= 0.76,
                ["RI"]= 0.73, ["RO"]= 0.73, ["IC"]= 0.70, ["NE"]= 0.69, ["EA"]= 0.69,
                ["RA"]= 0.69, ["CE"]= 0.65, ["LI"]= 0.62, ["CH"]= 0.60, ["LL"]= 0.58,
                ["BE"]= 0.58, ["MA"]= 0.57, ["SI"]= 0.55, ["OM"]= 0.55, ["UR"]= 0.54};*/
            Dictionary<char, double> punctfreqs = new Dictionary<char, double> {
                ['.'] = 0.0653, [','] = 0.0616, [';'] = 0.0032, [':'] = 0.0034, ['!'] = 0.0033,
                ['?'] = 0.0056, ['\''] = 0.0243, ['"'] = 0.0267, ['-'] = 0.0153, [' '] = 1 / 4.79 };
            double[] freq = { .08167, .01492, .02202, .04253, .12702, .02228, .02015, .06094, .06966, .00153,
                              .01292, .04025, .02406, .06749, .07507, .01929, .00095, .05987, .06327, .09356,
                              .02758, .00978, .02560, .00150, .01994, .00077};
            //practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/
            double totalWords = ReadUtilityFile("english_monograms.txt").Select(str => double.Parse(str.Split(' ')[1])).Sum() / 4.79;
            Dictionary<string, double> bigramfreq = ReadUtilityFile("english_bigrams.txt").Select(str => 
                { string[] sp = str.Split(' '); return new Tuple<string, double>(sp[0], double.Parse(sp[1])); }).ToDictionary(x => x.Item1, x => x.Item2);
            Dictionary<string, double> trigramfreq = ReadUtilityFile("english_trigrams.txt").Select(str =>
            { string[] sp = str.Split(' '); return new Tuple<string, double>(sp[0], double.Parse(sp[1])); }).ToDictionary(x => x.Item1, x => x.Item2);
            Dictionary<string, double> quadgramfreq = ReadUtilityFile("english_quadgrams.txt").Select(str =>
            { string[] sp = str.Split(' '); return new Tuple<string, double>(sp[0], double.Parse(sp[1])); }).ToDictionary(x => x.Item1, x => x.Item2);
            //Dictionary<string, double> quintgramfreq = ReadChallengeFile("english_quintgrams.txt").Select(str =>
            //{ string[] sp = str.Split(' '); return new Tuple<string, double>(sp[0], double.Parse(sp[1])); }).ToDictionary(x => x.Item1, x => x.Item2);
            return (byte[] p, byte[] r, byte[] s, byte[] t) =>
            {
                Tuple<byte, double>[] freqs = GetLeastXORCharacterScore(t);
                for (int top = 0; top < freqs.Length; top++)
                {
                    double score = 0;
                    for (int i = 0; i < t.Length; i++)
                    {
                        char nextChar = (char)(freqs[top].Item1 ^ t[i]);
                        if (t.Length <= 2)
                        { //statistical break down is basically guaranteed at this point under too many circumstances so must use word list

                            string str = new string(new char[] { (char)p[i], (char)r[i], (char)s[i], nextChar });
                            if (lastWords.ContainsKey(str)) { score = lastWords[str]; break; }
                        }
                        if (".,;:!? ".IndexOf((char)s[i]) != -1 && ".,;:!? ".IndexOf(nextChar) != -1 ||
                            ".,;:!? ".IndexOf((char)r[i]) != -1 && ".,;:!? ".IndexOf(nextChar) != -1 ||
                            char.IsLetter((char)s[i]) && char.IsNumber(nextChar) ||
                            char.IsLetter((char)s[i]) && char.IsUpper(nextChar))
                        {
                            score = 0; break;
                        }
                        /*if (char.IsLetter((char)o[i]) && char.IsLetter((char)p[i]) && char.IsLetter((char)r[i]) && char.IsLetter((char)s[i]) && char.IsLetter(nextChar)) {
                            string str = new string(new char[] { (char)o[i], (char)p[i], (char)r[i], (char)s[i], nextChar });
                            if (!quintgramfreq.ContainsKey(str.ToUpper())) { score = 0; break; }
                            score += quintgramfreq[str.ToUpper()] / totalWords * 5 * 5 * 5 * 5 * 5;
                        } else*/
                        if (char.IsLetter((char)p[i]) && char.IsLetter((char)r[i]) && char.IsLetter((char)s[i]) && char.IsLetter(nextChar))
                        {
                            string str = new string(new char[] { (char)p[i], (char)r[i], (char)s[i], nextChar });
                            //Console.WriteLine(str);
                            if (!quadgramfreq.ContainsKey(str.ToUpper())) { score = 0; break; }
                            score += quadgramfreq[str.ToUpper()] / totalWords * 4 * 4 * 4 * 4;
                        }
                        else if (char.IsLetter((char)r[i]) && char.IsLetter((char)s[i]) && char.IsLetter(nextChar))
                        {
                            string str = new string(new char[] { (char)r[i], (char)s[i], nextChar });
                            if (!trigramfreq.ContainsKey(str.ToUpper())) { score = 0; break; }
                            score += trigramfreq[str.ToUpper()] / totalWords * 3 * 3 * 3;
                        }
                        else if (char.IsLetter((char)s[i]) && char.IsLetter(nextChar))
                        {
                            string str = new string(new char[] { (char)s[i], nextChar });
                            if (!bigramfreq.ContainsKey(str.ToUpper())) { score = 0; break; }
                            score += bigramfreq[str.ToUpper()] / totalWords * 2 * 2;
                        }
                        else if (".,;:!? ".IndexOf(nextChar) != -1)
                        {
                            score += punctfreqs[nextChar];
                        }
                        else if (".,;:!? ".IndexOf((char)s[i]) != -1 && char.IsLetter(nextChar))
                        {
                            score += char.IsUpper(nextChar) ? freq[nextChar - 'A'] : freq[nextChar - 'a'];
                        }
                        else { score = 0; break; }
                        //if ((char1f[top].Item1 ^ s[m]) == bigraphfreq[i].Key[0] || (char1f[top].Item1 ^ s[m]) == (bigraphfreq[i].Key[0] - 'A' + 'a')) {
                        //char1f[top] = new Tuple<byte, double>(char1f[top].Item1, char1f[top].Item2 + char2f.First((c) => c.Item1 == (bigraphfreq[i].Key[1] ^ t[m]) || c.Item1 == ((bigraphfreq[i].Key[1] - 'A' + 'a') ^ t[m])).Item2 * bigraphfreq[i].Value * 26);
                        //}
                    }
                    freqs[top] = new Tuple<byte, double>(freqs[top].Item1, score);
                }
                return freqs.Where(x => x.Item2 != 0).OrderByDescending((c) => c.Item2).ToArray();
            };
        }
        static public Tuple<byte, double> BigramHandler(GetLeastXORBiTrigramScoreProto GetLeastXORBiTrigramScore, Tuple<byte, double> val, byte[][] lines, int i, byte[] b, byte[] analysis)
        {
            //look backward from a known good starting point
            IEnumerable<byte[]> e = lines.Where((bts) => bts.Length > i);
            Tuple<byte, double>[] vals = GetLeastXORBiTrigramScore(
                e.Select((bts) => (byte)(bts[i - 3] ^ b[i - 3])).ToArray(),
                e.Select((bts) => (byte)(bts[i - 2] ^ b[i - 2])).ToArray(),
                e.Select((bts) => (byte)(bts[i - 1] ^ b[i - 1])).ToArray(), analysis);
            //now look forward by one for confirmation of all possible scores
            if (vals.Length == 0) { }
            else if (b.Length == i + 1 || vals.Length == 1) val = vals.First();
            else
            {
                IEnumerable<byte[]> e1 = e.Where((bts) => bts.Length > i + 1);
                byte[] p = e1.Select((bts) => (byte)(bts[i - 2] ^ b[i - 2])).ToArray();
                byte[] q = e1.Select((bts) => (byte)(bts[i - 1] ^ b[i - 1])).ToArray();
                byte[] s = e1.Select((bts) => bts[i + 1]).ToArray();
                IEnumerable<byte[]> e2 = e1.Where((bts) => bts.Length > i + 2);
                byte[] p1 = e2.Select((bts) => (byte)(bts[i - 1] ^ b[i - 1])).ToArray();
                byte[] s1 = e2.Select((bts) => bts[i + 2]).ToArray();
                val = vals.Select(x =>
                {
                    Tuple<byte, double>[] vs = GetLeastXORBiTrigramScore(p, q,
                        e1.Select((bts) => (byte)(bts[i] ^ x.Item1)).ToArray(), s);
                    if (b.Length != i + 2 && vs.Length > 1)
                    { //second look ahead
                        byte[] q1 = e2.Select((bts) => (byte)(bts[i] ^ x.Item1)).ToArray();
                        return vs.Select(y =>
                        {
                            Tuple<byte, double>[] vls = GetLeastXORBiTrigramScore(p1, q1,
                                e2.Select((bts) => (byte)(bts[i + 1] ^ y.Item1)).ToArray(), s1);
                            return new Tuple<byte, double>(x.Item1, vls.Length == 0 ? 0 : vls.First().Item2 + y.Item2 + x.Item2);
                        }).OrderByDescending(y => y.Item2).First();
                    }
                    else return new Tuple<byte, double>(x.Item1, vs.Length == 0 ? 0 : vs.First().Item2 + x.Item2);
                }).OrderByDescending(x => x.Item2).First();
            }
            return val; //a tie in can cause errors
        }
        public class MersenneTwister
        {
            public uint[] x = new uint[624];
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
                x[0x26e] = 0; x[0x26f] = 0;
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
            static public uint Unextract(uint value) //untemper
            {
                value = value ^ value >> 18; //inverse of x ^ (x >> 18)
                value = value ^ ((value & 0x1DF8Cu) << 15); //inverse of ((x & 0xFFFFDF8C) << 15) ^ x = (x << 15) & 0xEFC60000 ^ x
                uint t = value; //inverse of ((x & 0xFF3A58AD) << 7) ^ x = ((x << 7) & 0x9D2C5680) ^ x
                t = ((t & 0x0000002D) << 7) ^ value; //7 bits
                t = ((t & 0x000018AD) << 7) ^ value; //14 bits
                t = ((t & 0x001A58AD) << 7) ^ value; //21 bits
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
        public class SHA1Context
        {
            /* This structure will hold context information for the SHA-1 hashing operation  */
            //static UInt32 SHA1HashSize = 20;
            public UInt32[] Intermediate_Hash = new UInt32[SHA1_Algo.SHA1HashSize / 4]; /* Message Digest  */
            public UInt32 Length_Low;                        /* Message length in bits      */
            public UInt32 Length_High;                       /* Message length in bits      */
            public int Message_Block_Index;                  /* Index into message block array   */
            public byte[] Message_Block = new byte[64];      /* 512-bit message blocks      */
            public int Computed;                             /* Is the digest computed?         */
            public int Corrupted;                            /* Is the message digest corrupted? */
        }
        public class SHA1_Algo
        {
            public static UInt32 SHA1HashSize = 20;
            enum SHA_enum
            {
                shaSuccess = 0,
                shaNull,            /* Null pointer parameter */
                shaInputTooLong,    /* input data too long */
                shaStateError       /* called Input after Result */
            };

            static public int SHA1ResetFromHashLen(SHA1Context context, byte[] h, int blocks)
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
                            context.Corrupted = (int)SHA_enum.shaInputTooLong;
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
                context.Message_Block[context.Message_Block_Index++] = 0x80;
                if (context.Message_Block_Index > 55) {
                    while (context.Message_Block_Index < 64)
                    {
                        context.Message_Block[context.Message_Block_Index++] = 0;
                    }
                    SHA1ProcessMessageBlock(context);
                }
                while (context.Message_Block_Index < 56)
                {
                    context.Message_Block[context.Message_Block_Index++] = 0;
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
        //https://referencesource.microsoft.com/#mscorlib/system/security/cryptography/hashalgorithm.cs
        //has source for ComputeHash
        public class MD4 : HashAlgorithm
        {
            private uint _a;
            private uint _b;
            private uint _c;
            private uint _d;
            private uint[] _x;
            private ulong _bytesProcessed;
            private bool _dontInit = false;
            public bool _dontPad = false;
            public bool _bigEndian = false;
            public MD4()
            {
                _x = new uint[16];
                Initialize();
            }
            public void InitFromHashLen(byte[] h, int blocks)
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
                    if (!_dontPad) ProcessMessage(Padding());

                    return new uint[] { _a, _b, _c, _d }.SelectMany(word => _bigEndian ? BitConverter.GetBytes(word).Reverse() : BitConverter.GetBytes(word)).ToArray();
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
                return new byte[] { 0x80 }
                   .Concat(Enumerable.Repeat((byte)0, (int)(((_bytesProcessed + 8) & 0x7fffffc0) + 55 - _bytesProcessed)))
                   .Concat(_bigEndian ? BitConverter.GetBytes((ulong)(_bytesProcessed << 3)) : BitConverter.GetBytes((ulong)(_bytesProcessed << 3)));
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
            public static byte[] ApplyWangDifferential(byte[] bytes)
            {
                uint[] x = new uint[16];
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
                unchecked
                {
                    x[1] += ((uint)1 << 31);
                    x[2] += ((uint)1 << 31) - (1 << 28);
                    x[12] -= ((uint)1 << 16);
                }
                return x.SelectMany((b) => BitConverter.GetBytes(b)).ToArray();
            }
            public static bool HasWangsConditions(uint[] x, bool bNaito, int stage = 0)
            { //stage 0 is first round, stages 1-7 around second round per modification variable, stage 8 is third round
                uint a0 = 0x67452301;
                uint b0 = 0xefcdab89;
                uint c0 = 0x98badcfe;
                uint d0 = 0x10325476;
                uint a1 = Round1Operation(a0, b0, c0, d0, x[0], 3);
                uint d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
                uint c1 = Round1Operation(c0, d1, a1, b0, x[2], 11);
                uint b1 = Round1Operation(b0, c1, d1, a1, x[3], 19);
                uint a2 = Round1Operation(a1, b1, c1, d1, x[4], 3);
                uint d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                uint c2 = Round1Operation(c1, d2, a2, b1, x[6], 11);
                uint b2 = Round1Operation(b1, c2, d2, a2, x[7], 19);
                uint a3 = Round1Operation(a2, b2, c2, d2, x[8], 3);
                uint d3 = Round1Operation(d2, a3, b2, c2, x[9], 7);
                uint c3 = Round1Operation(c2, d3, a3, b2, x[10], 11);
                uint b3 = Round1Operation(b2, c3, d3, a3, x[11], 19);
                uint a4 = Round1Operation(a3, b3, c3, d3, x[12], 3);
                uint d4 = Round1Operation(d3, a4, b3, c3, x[13], 7);
                uint c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
                uint b4 = Round1Operation(b3, c4, d4, a4, x[15], 19);
                if (!(((a1 & (1 << 6)) == (b0 & (1 << 6))) &&
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
                    (b4 & (1 << 25)) != 0 && (b4 & (1 << 26)) != 0 && (b4 & (1 << 28)) != 0 && (b4 & (1 << 18)) == 0 && (b4 & (1 << 29)) == 0 && (b4 & (1 << 25)) == (c4 & (1 << 25)) && (!bNaito || (b4 & ((uint)1 << 31)) == (c4 & ((uint)1 << 31))))) return false;
                if (stage == 0) return true;
                uint a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                uint d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                uint c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                uint b5 = Round2Operation(b4, c5, d5, a5, x[12], 13);
                uint a6 = Round2Operation(a5, b5, c5, d5, x[1], 3);
                uint d6 = Round2Operation(d5, a6, b5, c5, x[5], 5);
                uint c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                uint b6 = Round2Operation(b5, c6, d6, a6, x[13], 13);
                uint a7 = Round2Operation(a6, b6, c6, d6, x[2], 3);
                uint d7 = Round2Operation(d6, a7, b6, c6, x[6], 5);
                uint c7 = Round2Operation(c6, d7, a7, b6, x[10], 9);
                uint b7 = Round2Operation(b6, c7, d7, a7, x[14], 13);
                uint a8 = Round2Operation(a7, b7, c7, d7, x[3], 3);
                uint d8 = Round2Operation(d7, a8, b7, c7, x[7], 5);
                uint c8 = Round2Operation(c7, d8, a8, b7, x[11], 9);
                uint b8 = Round2Operation(b7, c8, d8, a8, x[15], 13);
                if (!((a5 & (1 << 18)) == (c4 & (1 << 18)) && (a5 & (1 << 25)) != 0 && (a5 & (1 << 28)) != 0 && (a5 & ((uint)1 << 31)) != 0 && (a5 & (1 << 26)) == 0 && (!bNaito || ((a5 & (1 << 19)) == (b4 & (1 << 19)) && (a5 & (1 << 21)) == (b4 & (1 << 21)))))) return false;
                if (stage == 1) return true;
                if (!((d5 & (1 << 18)) == (a5 & (1 << 18)) && (d5 & (1 << 25)) == (b4 & (1 << 25)) && (d5 & (1 << 26)) == (b4 & (1 << 26)) && (d5 & (1 << 28)) == (b4 & (1 << 28)) &&
                            (d5 & ((uint)1 << 31)) == (b4 & ((uint)1 << 31)))) return false;
                if (stage == 2) return true;
                if (!((c5 & (1 << 25)) == (d5 & (1 << 25)) && (c5 & (1 << 26)) == (d5 & (1 << 26)) && (c5 & (1 << 28)) == (d5 & (1 << 28)) && (c5 & (1 << 29)) == (d5 & (1 << 29)) && (c5 & ((uint)1 << 31)) == (d5 & ((uint)1 << 31)))) return false;
                if (stage == 3) return true;
                if (!((b5 & (1 << 28)) == (c5 & (1 << 28)) && (b5 & (1 << 29)) != 0 && (b5 & ((uint)1 << 31)) == 0)) return false;
                if (stage == 4) return true;
                if (!((a6 & (1 << 28)) != 0 && (!bNaito || (a6 & (1 << 29)) == 0) && (a6 & ((uint)1 << 31)) != 0)) return false;
                if (stage == 5) return true;
                if (!((d6 & (1 << 28)) == (b5 & (1 << 28)))) return false;
                if (stage == 6) return true;
                if (!((c6 & (1 << 28)) == (d6 & (1 << 28)) && (c6 & (1 << 29)) != (d6 & (1 << 29)) && (c6 & (1 << 31)) != (d6 & (1 << 31)))) return false;
                if (stage == 7) return true;
                uint a9 = Round3Operation(a8, b8, c8, d8, x[0], 3);
                uint d9 = Round3Operation(d8, a9, b8, c8, x[8], 9);
                uint c9 = Round3Operation(c8, d9, a9, b8, x[4], 11);
                uint b9 = Round3Operation(b8, c9, d9, a9, x[12], 15);
                uint a10 = Round3Operation(a9, b9, c9, d9, x[2], 3);
                return ((b9 & ((uint)1 << 31)) != 0 && (a10 & ((uint)1 << 31)) != 0);
            }
            public static bool VerifyConditions2(uint[] x, uint a0, uint b0, uint c0, uint d0, uint a5, uint b5, uint c5, uint d5, uint a6, uint b6, uint c6, uint d6, uint a7, uint b7, uint c7, uint d7, uint a8, uint b8, uint c8, uint d8)
            {
                uint a1 = Round1Operation(a0, b0, c0, d0, x[0], 3);
                uint d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
                uint c1 = Round1Operation(c0, d1, a1, b0, x[2], 11);
                uint b1 = Round1Operation(b0, c1, d1, a1, x[3], 19);
                uint a2 = Round1Operation(a1, b1, c1, d1, x[4], 3);
                uint d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                uint c2 = Round1Operation(c1, d2, a2, b1, x[6], 11);
                uint b2 = Round1Operation(b1, c2, d2, a2, x[7], 19);
                uint a3 = Round1Operation(a2, b2, c2, d2, x[8], 3);
                uint d3 = Round1Operation(d2, a3, b2, c2, x[9], 7);
                uint c3 = Round1Operation(c2, d3, a3, b2, x[10], 11);
                uint b3 = Round1Operation(b2, c3, d3, a3, x[11], 19);
                uint a4 = Round1Operation(a3, b3, c3, d3, x[12], 3);
                uint d4 = Round1Operation(d3, a4, b3, c3, x[13], 7);
                uint c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
                uint b4 = Round1Operation(b3, c4, d4, a4, x[15], 19);
                return (a5 == Round2Operation(a4, b4, c4, d4, x[0], 3) &&
                    d5 == Round2Operation(d4, a5, b4, c4, x[4], 5) &&
                    c5 == Round2Operation(c4, d5, a5, b4, x[8], 9) &&
                    b5 == Round2Operation(b4, c5, d5, a5, x[12], 13) &&
                    a6 == Round2Operation(a5, b5, c5, d5, x[1], 3) &&
                    d6 == Round2Operation(d5, a6, b5, c5, x[5], 5) &&
                    c6 == Round2Operation(c5, d6, a6, b5, x[9], 9) &&
                    b6 == Round2Operation(b5, c6, d6, a6, x[13], 13) &&
                    a7 == Round2Operation(a6, b6, c6, d6, x[2], 3) &&
                    d7 == Round2Operation(d6, a7, b6, c6, x[6], 5) &&
                    c7 == Round2Operation(c6, d7, a7, b6, x[10], 9) &&
                    b7 == Round2Operation(b6, c7, d7, a7, x[14], 13) &&
                    a8 == Round2Operation(a7, b7, c7, d7, x[3], 3) &&
                    d8 == Round2Operation(d7, a8, b7, c7, x[7], 5) &&
                    c8 == Round2Operation(c7, d8, a8, b7, x[11], 9) &&
                    b8 == Round2Operation(b7, c8, d8, a8, x[15], 13));
            }
            public static bool VerifyConditions(uint[] x, uint a0, uint b0, uint c0, uint d0, uint a1, uint b1, uint c1, uint d1, uint a2, uint b2, uint c2, uint d2, uint a3, uint b3, uint c3, uint d3, uint a4, uint b4, uint c4, uint d4)
            {
                return (a1 == Round1Operation(a0, b0, c0, d0, x[0], 3) &&
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
                    b4 == Round1Operation(b3, c4, d4, a4, x[15], 19));
            }
            public static byte[] WangsAttack(byte[] bytes, bool bMulti, bool bNaito)
            {
                //Naito et al. improvements: Add two sufficient conditions b4,32 = c4,32 and a6,30 = 0 probability 1/4
                //Change the modification method of d5,19 so that both of d5,19 = a5,19 and c5,26 = d5,26 can be corrected probability 7/8
                //wrong correction of c5,29 probability 1/2
                //Change the modification method of c5,32 so that both of c5,32 = d5,32 and c6,32 = d6,32 + 1 can be corrected probability 3/4
                //satisfying condition in 3rd round probability 1/4
                uint[] x = new uint[16];
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
                if (bMulti) b1 |= (1 << 0) | (uint)(bNaito ? (1 << 1) : 0) | (1 << 3);
                x[3] = Unround1Operation(b0, c1, d1, a1, b1, 19);

                //a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
                a2 = Round1Operation(a1, b1, c1, d1, x[4], 3);
                a2 |= (1 << 7) | (1 << 10);
                a2 &= ~(uint)(1 << 25);
                a2 ^= (a2 & (1 << 13)) ^ (b1 & (1 << 13));
                //extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
                if (bMulti) a2 ^= (a2 & (1 << (25 - 9))) ^ (b1 & (1 << (25 - 9))) ^ (a2 & (1 << (26 - 9))) ^ (b1 & (1 << (26 - 9))) ^ (bNaito ? (a2 & (1 << (30 - 9))) ^ (b1 & (1 << (30 - 9))) : (a2 & (1 << (28 - 9))) ^ (b1 & (1 << (28 - 9))) ^ (a2 & (1 << (31 - 9))) ^ (b1 & (1 << (31 - 9))));
                x[4] = Unround1Operation(a1, b1, c1, d1, a2, 3);

                //d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
                d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                d2 &= ~(uint)(1 << 13);
                d2 |= (1 << 25);
                d2 ^= (d2 & (1 << 18)) ^ (a2 & (1 << 18)) ^ (d2 & (1 << 19)) ^ (a2 & (1 << 19)) ^ (d2 & (1 << 20)) ^ (a2 & (1 << 20)) ^ (d2 & (1 << 21)) ^ (a2 & (1 << 21));
                //extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
                //(d2 & (1 << 19)) ^ (a2 & (1 << 19)) conflicts with (1 << (28 - 9))
                //if (bMulti) d2 &= ~(uint)((1 << (25 - 9)) | (1 << (26 - 9)) | (bNaito ? 0 : (1 << (28 - 9)) | (1 << (31 - 9))));
                if (bMulti) d2 &= ~(uint)((1 << (25 - 9)) | (1 << (26 - 9)) | (bNaito ? 0 : (1 << (31 - 9))));
                //extra condition to allow correcting c6,32 in 2nd round
                //(1 << (31 - 9)) conflicts with (d2 & (1 << 22)) ^ (a2 & (1 << 22))
                //unfortunately not knowing whether to correct for c5,32 or d2,32 makes a 3/8 chance of failure not 1/4 because of the additional case of when d2,23!=a2,23
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
                if (bMulti) c2 &= ~(uint)(1 << 22);
                x[6] = Unround1Operation(c1, d2, a2, b1, c2, 11);

                //b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0, b2,20 = 0, b2,21 = 0, b2,22 = 0
                b2 = Round1Operation(b1, c2, d2, a2, x[7], 19);
                b2 |= (1 << 12) | (1 << 13);
                b2 &= ~(uint)((1 << 14) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21));
                b2 ^= (b2 & (1 << 16)) ^ (c2 & (1 << 16));
                //extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
                //(b2 & (1 << 16)) ^ (c2 & (1 << 16)) conflicts with (1 << (25 - 9))
                if (bMulti) b2 &= ~(uint)((1 << (25 - 9)) | (1 << (26 - 9)) | (bNaito ? 0 : (1 << (28 - 9)) | (1 << (31 - 9))));
                //extra condition to allow correcting d6,29 in 2nd round
                if (bMulti) b2 |= (1 << 30);
                //extra condition to allow correcting c6,32 in 2nd round
                if (bMulti) b2 &= ~(uint)(1 << 22);
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
                if (bMulti) d3 ^= (d3 & (1 << 15)) ^ (a3 & (1 << 15)) ^ (d3 & (1 << 18)) ^ (a3 & (1 << 18));
                x[9] = Unround1Operation(d2, a3, b2, c2, d3, 7);

                //c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 = 0, c3,23 = 0, c3,26 = 0, c3,30 = 1, c3,32 = d3,32
                c3 = Round1Operation(c2, d3, a3, b2, x[10], 11);
                c3 &= ~(uint)((1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 25));
                c3 |= (1 << 16) | (1 << 29);
                c3 ^= (c3 & ((uint)1 << 31)) ^ (d3 & ((uint)1 << 31));
                //extra condition to allow correcting b5,29, b5,32 in 2nd round
                if (bMulti) c3 &= ~(uint)((1 << 15) | (1 << 18));
                //extra conditions to allow 3rd round corrections in x[11]
                if (bMulti && bNaito) c3 ^= (c3 & (1 << 0)) ^ (c3 & (1 << 1)) ^ (c3 & (1 << 2)) ^ (c3 & (1 << 3)) ^ (c3 & (1 << 4)) ^ (c3 & (1 << 5)) ^ (c3 & (1 << 6)) ^ (c3 & (1 << 7)) ^ (c3 & (1 << 8)) ^ (c3 & (1 << 9)) ^ (c3 & (1 << 10)) ^ (c3 & (1 << 11)) ^ (c3 & (1 << 12)) ^ (c3 & (1 << 13)) ^ (c3 & (1 << 14)) ^ (c3 & (1 << 17)) ^ (c3 & (1 << 23)) ^ (c3 & (1 << 24)) ^ (c3 & (1 << 30)) ^
                                            (d3 & (1 << 0)) ^ (d3 & (1 << 1)) ^ (d3 & (1 << 2)) ^ (d3 & (1 << 3)) ^ (d3 & (1 << 4)) ^ (d3 & (1 << 5)) ^ (d3 & (1 << 6)) ^ (d3 & (1 << 7)) ^ (d3 & (1 << 8)) ^ (d3 & (1 << 9)) ^ (d3 & (1 << 10)) ^ (d3 & (1 << 11)) ^ (d3 & (1 << 12)) ^ (d3 & (1 << 13)) ^ (d3 & (1 << 14)) ^ (d3 & (1 << 17)) ^ (d3 & (1 << 23)) ^ (d3 & (1 << 24)) ^ (d3 & (1 << 30));
                x[10] = Unround1Operation(c2, d3, a3, b2, c3, 11);

                //b3 uses 7 + 5 = 12 not 13 but b3,29 comes from a4,29 and d4,29 - b3,16, b3,17, b3,19, b3,20, b3,21, b3,22, b3,23, b3,26, b3,27, b3,28, b3,29, b3,30, b3,32
                //b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1, b3,30 = 0, b3,32 = 0
                b3 = Round1Operation(b2, c3, d3, a3, x[11], 19);
                b3 |= (1 << 20) | (1 << 21) | (1 << 25);
                b3 &= ~(uint)((1 << 19) | (1 << 29) | ((uint)1 << 31));
                b3 ^= (b3 & (1 << 22)) ^ (c3 & (1 << 22));
                //extra condition to allow correcting b5,29, b5,32 in 2nd round
                if (bMulti) b3 |= (1 << 15) | (1 << 18);
                //extra condition to allow correcting b5,30 in 2nd round
                if (bMulti) b3 &= ~(uint)(1 << 16);
                //extra condition to allow correcting c6,29, c6,30 in 2nd round
                if (bMulti) b3 |= (1 << 26) | (1 << 27);
                x[11] = Unround1Operation(b2, c3, d3, a3, b3, 19);

                //a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
                a4 = Round1Operation(a3, b3, c3, d3, x[12], 3);
                a4 |= (1 << 29);
                a4 &= ~(uint)((1 << 22) | (1 << 25) | ((uint)1 << 31));
                a4 ^= (a4 & (1 << 26)) ^ (b3 & (1 << 26)) ^ (a4 & (1 << 28)) ^ (b3 & (1 << 28));
                //extra condition to allow correcting b5,29, b5,32 in 2nd round
                if (bMulti) a4 |= (1 << 15) | (1 << 18);
                //extra condition to allow correcting b5,30 in 2nd round
                if (bMulti) a4 &= ~(uint)(1 << 16);
                //extra conditions to allow 3rd round corrections in x[11]
                if (bMulti && bNaito) a4 &= ~(uint)((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30));
                x[12] = Unround1Operation(a3, b3, c3, d3, a4, 3);

                //d4,23 = 0, d4,26 = 0, d4,27 = 1, d4,29 = 1, d4,30 = 0, d4,32 = 1
                d4 = Round1Operation(d3, a4, b3, c3, x[13], 7);
                d4 &= ~(uint)((1 << 22) | (1 << 25) | (1 << 29));
                d4 |= (1 << 26) | (1 << 28) | ((uint)1 << 31);
                //extra condition to allow correcting c5,29, c5,32 in 2nd round
                if (bMulti && bNaito) d4 ^= (d4 & (1 << 19)) ^ (a4 & (1 << 19)) ^ (d4 & (1 << 21)) ^ (a4 & (1 << 21));
                //extra condition to allow correcting b5,30 in 2nd round
                if (bMulti) d4 |= (1 << 16);
                //extra conditions to allow 3rd round corrections in x[11]
                //if (bMulti && bNaito) d4 &= ~(uint)((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30));
                if (bMulti && bNaito) d4 |= (uint)((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30));
                x[13] = Unround1Operation(d3, a4, b3, c3, d4, 7);

                //c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
                c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
                c4 &= ~(uint)((1 << 26) | (1 << 28) | (1 << 29));
                c4 |= (1 << 22) | (1 << 25);
                c4 ^= (c4 & (1 << 18)) ^ (d4 & (1 << 18));
                //extra condition to allow correcting c5,29, c5,32 in 2nd round
                if (bMulti && bNaito) c4 &= ~(uint)((1 << 19) | (1 << 21));
                x[14] = Unround1Operation(c3, d4, a4, b3, c4, 11);

                //b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
                b4 = Round1Operation(b3, c4, d4, a4, x[15], 19);
                b4 |= (1 << 25) | (1 << 26) | (1 << 28);
                b4 &= ~(uint)((1 << 18) | (1 << 29));
                b4 ^= (b4 & (1 << 25)) ^ (c4 & (1 << 25));
                //newly discovered condition: b4,32 = c4,32
                if (bNaito) b4 ^= (b4 & ((uint)1 << 31)) ^ (c4 & ((uint)1 << 31));
                //extra condition to allow correcting c5,29, c5,32 in 2nd round
                if (bMulti && bNaito) b4 ^= (b4 & (1 << 19)) ^ (d4 & (1 << 19)) ^ (b4 & (1 << 21)) ^ (d4 & (1 << 21));
                x[15] = Unround1Operation(b3, c4, d4, a4, b4, 19);
                //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito))
                //    throw new ArgumentException();

                if (!bMulti) return x.SelectMany((b) => BitConverter.GetBytes(b)).ToArray();

                //round/step 2 and 3 - multi-step modification
                //must not "stomp" on the first round conditions
                uint[] saveX = new uint[16];
                Array.Copy(x, saveX, 16);
                ulong n = 0;
                do
                {
                    if (!bNaito && n != 0)
                    {
                        //return null;
                        Array.Copy(saveX, x, 16);
                        a1 = Round1Operation(a0, b0, c0, d0, x[0], 3);
                        d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
                        c1 = Round1Operation(c0, d1, a1, b0, x[2], 11);
                        b1 = Round1Operation(b0, c1, d1, a1, x[3], 19);
                        a2 = Round1Operation(a1, b1, c1, d1, x[4], 3);
                        d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                        c2 = Round1Operation(c1, d2, a2, b1, x[6], 11);
                        b2 = Round1Operation(b1, c2, d2, a2, x[7], 19);
                        a3 = Round1Operation(a2, b2, c2, d2, x[8], 3);
                        d3 = Round1Operation(d2, a3, b2, c2, x[9], 7);
                        c3 = Round1Operation(c2, d3, a3, b2, x[10], 11);
                        b3 = Round1Operation(b2, c3, d3, a3, x[11], 19);
                        a4 = Round1Operation(a3, b3, c3, d3, x[12], 3);
                        d4 = Round1Operation(d3, a4, b3, c3, x[13], 7);
                        x[14] ^= (uint)(n & 0xFFFFFFFF);
                        x[15] ^= (uint)(n >> 32); //deliberate as we need to try to solve b4 condition without waiting 0xFFFFFFFF iterations
                        //c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
                        c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
                        c4 &= ~(uint)((1 << 26) | (1 << 28) | (1 << 29));
                        c4 |= (1 << 22) | (1 << 25);
                        c4 ^= (c4 & (1 << 18)) ^ (d4 & (1 << 18));
                        //extra condition to allow correcting c5,29, c5,32 in 2nd round
                        //if (bMulti && bNaito) c4 &= ~(uint)((1 << 19) | (1 << 21));
                        x[14] = Unround1Operation(c3, d4, a4, b3, c4, 11);

                        //b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
                        b4 = Round1Operation(b3, c4, d4, a4, x[15], 19);
                        b4 |= (1 << 25) | (1 << 26) | (1 << 28);
                        b4 &= ~(uint)((1 << 18) | (1 << 29));
                        b4 ^= (b4 & (1 << 25)) ^ (c4 & (1 << 25));
                        //newly discovered condition: b4,32 = c4,32
                        //if (bNaito) b4 ^= (b4 & ((uint)1 << 31)) ^ (c4 & ((uint)1 << 31));
                        //extra condition to allow correcting c5,29, c5,32 in 2nd round
                        //if (bMulti && bNaito) b4 ^= (b4 & (1 << 19)) ^ (d4 & (1 << 19)) ^ (b4 & (1 << 21)) ^ (d4 & (1 << 21));
                        x[15] = Unround1Operation(b3, c4, d4, a4, b4, 19);
                        //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito))
                        //    throw new ArgumentException();
                    }
                    if (!bNaito) {
                        n++;
                        if (n == 0) return null; //nothing found after 2^64 search...
                    }
                    //a5,19 = c4,19, a5,26 = 1, a5,27 = 0, a5,29 = 1, a5,32 = 1
                    //must do these in exact order as arithmetic over and underflows must be handled
                    a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                    //d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                    //c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                    //b5 = Round2Operation(b4, c5, d5, a5, x[12], 13);
                    //a6 = Round2Operation(a5, b5, c5, d5, x[1], 3);
                    //d6 = Round2Operation(d5, a6, b5, c5, x[5], 5);
                    //c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                    //b6 = Round2Operation(b5, c6, d6, a6, x[13], 13);
                    //a7 = Round2Operation(a6, b6, c6, d6, x[2], 3);
                    //d7 = Round2Operation(d6, a7, b6, c6, x[6], 5);
                    //c7 = Round2Operation(c6, d7, a7, b6, x[10], 9);
                    //b7 = Round2Operation(b6, c7, d7, a7, x[14], 13);
                    //a8 = Round2Operation(a7, b7, c7, d7, x[3], 3);
                    //d8 = Round2Operation(d7, a8, b7, c7, x[7], 5);
                    //c8 = Round2Operation(c7, d8, a8, b7, x[11], 9);
                    //b8 = Round2Operation(b7, c8, d8, a8, x[15], 13);

                    int[] a5mods = bNaito ? new int[] { 18, 19, 21, 25, 26, 28, 31 } : new int[] { 18, 25, 26, 28, 31 };
                    foreach (int i in a5mods) {
                        if (i == 18 && (a5 & (1 << 18)) == (c4 & (1 << 18)) ||
                            i == 19 && (a5 & (1 << 19)) == (b4 & (1 << 19)) || //extra conditions to allow correcting c5,29, c5,32
                            i == 21 && (a5 & (1 << 21)) == (b4 & (1 << 21)) ||
                            i == 25 && (a5 & (1 << 25)) != 0 ||
                            i == 26 && (a5 & (1 << 26)) == 0 ||
                            i == 28 && (a5 & (1 << 28)) != 0 ||
                            i == 31 && (a5 & ((uint)1 << 31)) != 0) continue;
                        x[0] = ((a1 & (1 << i)) == 0) ? x[0] + (uint)(1 << (i - 3)) : x[0] - (uint)(1 << (i - 3));
                        a1 = Round1Operation(a0, b0, c0, d0, x[0], 3);
                        x[1] = Unround1Operation(d0, a1, b0, c0, d1, 7);
                        x[2] = Unround1Operation(c0, d1, a1, b0, c1, 11);
                        x[3] = Unround1Operation(b0, c1, d1, a1, b1, 19);
                        x[4] = Unround1Operation(a1, b1, c1, d1, a2, 3);
                        a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                        //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito))
                        //    throw new ArgumentException();
                    }
                    //if (!VerifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 1))
                    //    throw new ArgumentException();

                    //d5,19 = a5,19, d5,26 = b4,26, d5,27 = b4,27, d5,29 = b4,29, d5,32 = b4,32
                    d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                    int[] d5mods = new int[] { 18, 25, 26, 28, 31 };
                    foreach (int i in d5mods)
                    {
                        if (i == 18 && (d5 & (1 << 18)) == (a5 & (1 << 18)) ||
                            i == 25 && (d5 & (1 << 25)) == (b4 & (1 << 25)) ||
                            i == 26 && (d5 & (1 << 26)) == (b4 & (1 << 26)) ||
                            i == 28 && (d5 & (1 << 28)) == (b4 & (1 << 28)) ||
                            i == 31 && (d5 & ((uint)1 << 31)) == (b4 & ((uint)1 << 31))) continue;
                        if (bNaito && i == 18) {
                            //if (!((d1 & (1 << 13)) == 0 && (a1 & (1 << 13)) == (b0 & (1 << 13)) && (c1 & (1 << 13)) == 0 && (b1 & (1 << 13)) == 0))
                            //    throw new ArgumentException();
                            x[1] = (d1 & (1 << 13)) == 0 ? x[1] + (1 << 6) : x[1] - (1 << 6);
                            d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
                            x[4] -= (1 << 13);
                            x[5] -= (1 << 13);
                        } else {
                            x[4] = ((a2 & (1 << (i - 2))) == 0) ? x[4] + (uint)(1 << (i - 5)) : x[4] - (uint)(1 << (i - 5));
                            a2 = Round1Operation(a1, b1, c1, d1, x[4], 3);
                            x[5] = Unround1Operation(d1, a2, b1, c1, d2, 7);
                            x[6] = Unround1Operation(c1, d2, a2, b1, c2, 11);
                            x[7] = Unround1Operation(b1, c2, d2, a2, b2, 19);
                            x[8] = Unround1Operation(a2, b2, c2, d2, a3, 3);
                        }
                        d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                        //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito))
                        //    throw new ArgumentException();
                    }
                    //if (!VerifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 2))
                    //    throw new ArgumentException();

                    //c5,26 = d5,26, c5,27 = d5,27, c5,29 = d5,29, c5,30 = d5,30, c5,32 = d5,32
                    c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                    int[] c5mods = bNaito ? new int[] { 25, 26, 28, 29, 30, 31 } :
                        new int[] { 25, 26, 28, 29, 31 };
                    //bool bContinue = false;
                    foreach (int i in c5mods)
                    {
                        if (i == 25 && (c5 & (1 << 25)) == (d5 & (1 << 25)) ||
                            i == 26 && (c5 & (1 << 26)) == (d5 & (1 << 26)) ||
                            i == 28 && (c5 & (1 << 28)) == (d5 & (1 << 28)) ||
                            i == 29 && (c5 & (1 << 29)) == (d5 & (1 << 29)) ||
                            i == 30 && (c5 & (1 << 30)) != 0 ||
                            i == 31 && (c5 & (1 << 31)) == (d5 & (1 << 31))) continue;
                        if (i == 29 || i == 30)
                        {
                            x[8] = ((a3 & ((uint)1 << (i - 6))) == 0) ? x[8] + ((uint)1 << (i - 9)) : x[8] - ((uint)1 << (i - 9));
                            a3 = Round1Operation(a2, b2, c2, d2, x[8], 3);
                            x[9] = Unround1Operation(d2, a3, b2, c2, d3, 7);
                            x[10] = Unround1Operation(c2, d3, a3, b2, c3, 11);
                            x[11] = Unround1Operation(b2, c3, d3, a3, b3, 19);
                            x[12] = Unround1Operation(a3, b3, c3, d3, a4, 3);
                        } else if ((i == 28 || i == 31) && bNaito) {
                            //if (i == 28 && !((c4 & (1 << (i - 9))) == 0 && (d4 & (1 << (i - 9))) == (a4 & (1 << (i - 9))) && (b4 & (1 << (i - 9))) == (d4 & (1 << (i - 9)))))
                            //    throw new ArgumentException();
                            //if (i == 31 && !((c4 & (1 << (i - 10))) == 0 && (d4 & (1 << (i - 10))) == (a4 & (1 << (i - 10))) && (b4 & (1 << (i - 10))) == (d4 & (1 << (i - 10)))))
                            //    throw new ArgumentException();
                            if (i == 28) x[14] += ((uint)1 << (i - 20));
                            else x[14] += ((uint)1 << (i - 21));
                            c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
                            c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                        } else {
                            //if (!((!bNaito && i == 28 || (d2 & (1 << (i - 9))) == 0) && (!bNaito && i == 25 || (a2 & (1 << (i - 9))) == (b1 & (1 << (i - 9)))) && (c2 & (1 << (i - 9))) == 0 && (b2 & (1 << (i - 9))) == 0))
                            //    throw new ArgumentException();
                            if (!bNaito && i == 28) { //c5,29 can break a first round condition and will never succeed if it occurs
                                return null;
                                //bContinue = true;
                                //break;
                            }
                            x[5] += (uint)(1 << (i - 16));
                            //x[5] = (d2 & ((uint)1 << (i - 9))) == 0 ? x[5] + (uint)(1 << (i - 16)) : x[5] - (uint)(1 << (i - 16));
                            //x[8] = (d2 & ((uint)1 << (i - 9))) == 0 ? x[8] - (uint)(1 << (i - 9)) : x[8] + (uint)(1 << (i - 9));
                            //x[9] = (d2 & ((uint)1 << (i - 9))) == 0 ? x[9] - (uint)(1 << (i - 9)) : x[9] + (uint)(1 << (i - 9));
                            d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                            x[8] -= (uint)(1 << (i - 9));
                            x[9] -= (uint)(1 << (i - 9));
                            //if i == 25 and d5,19 was corrected, then c2 is broken and c2 != Round1Operation(c1, d2, a2, b1, x[6], 11)
                            if (!bNaito && i == 25 && c2 != Round1Operation(c1, d2, a2, b1, x[6], 11)) { //!((a2 & (1 << (i - 9))) == (b1 & (1 << (i - 9))))
                                //probability 1/8 that we have to abort and no forgery can be found using Wang's method
                                //however if d6,26 is additionally corrected then c2 will be fixed even though Wang did not mention this
                                x[6] = Unround1Operation(c1, d2, a2, b1, c2, 11);
                                c2 = Round1Operation(c1, d2, a2, b1, x[6], 11);
                            }
                        }
                        c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                        //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito))
                        //    throw new ArgumentException();
                    }
                    //if (bContinue) continue;
                    //c5,26 when not equal to d5,19 and c5,29 are stomping on first round conditions and must have more modifications to correct
                    //if (!VerifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 3))
                    //    throw new ArgumentException();

                    //b5,29 = c5,29, b5,30 = 1, b5,32 = 0
                    b5 = Round2Operation(b4, c5, d5, a5, x[12], 13);
                    int[] b5mods = new int[] { 28, 29, 31 };
                    foreach (int i in b5mods)
                    {
                        if (i == 28 && (b5 & (1 << 28)) == (c5 & (1 << 28)) ||
                            i == 29 && (b5 & (1 << 29)) != 0 ||
                            i == 31 && (b5 & ((uint)1 << 31)) == 0) continue;
                        if (i == 29) {
                            //if (!((b3 & (1 << 16)) == 0 && (a4 & (1 << 16)) == 0 && (d4 & (1 << 16)) != 0))
                            //    throw new ArgumentException();
                            x[11] += (1 << 29);
                            //x[11] = (b3 & (1 << 16)) == 0 ? x[11] + (1 << 29) : x[11] - (1 << 29);
                            //x[12] = (b3 & (1 << 16)) == 0 ? x[12] - (1 << 16) : x[12] + (1 << 16);
                            //x[15] = (b3 & (1 << 16)) == 0 ? x[15] - (1 << 16) : x[15] + (1 << 16);
                            b3 = Round1Operation(b2, c3, d3, a3, x[11], 19);
                            x[12] -= (1 << 16);
                            x[15] -= (1 << 16);
                        } else {
                            //if (!((c3 & (1 << (i - 13))) == 0 && (d3 & (1 << (i - 13))) == (a3 & (1 << (i - 13))) && (b3 & (1 << (i - 13))) != 0 && (a4 & (1 << (i - 13))) != 0))
                            //    throw new ArgumentException();
                            x[10] += ((uint)1 << (i - 24));
                            //x[10] = (c3 & ((uint)1 << (i - 13))) == 0 ? x[10] + ((uint)1 << (i - 24)) : x[10] - ((uint)1 << (i - 24));
                            //x[12] = (c3 & ((uint)1 << (i - 13))) == 0 ? x[12] - ((uint)1 << (i - 13)) : x[12] + ((uint)1 << (i - 13));
                            //x[14] = (c3 & ((uint)1 << (i - 13))) == 0 ? x[14] - ((uint)1 << (i - 13)) : x[14] + ((uint)1 << (i - 13));
                            c3 = Round1Operation(c2, d3, a3, b2, x[10], 11);
                            x[12] -= ((uint)1 << (i - 13));
                            x[14] -= ((uint)1 << (i - 13));
                        }
                        b5 = Round2Operation(b4, c5, d5, a5, x[12], 13);
                        //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito))
                        ///    throw new ArgumentException();
                    }
                    //if (!VerifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 4))
                    //    throw new ArgumentException();

                    //a6,29 = 1, a6,32 = 1
                    //newly discovered condition: a6,30 = 0
                    a6 = Round2Operation(a5, b5, c5, d5, x[1], 3);
                    int[] a6mods = bNaito ? new int[] { 28, 29, 31 } : new int[] { 28, 31 };
                    foreach (int i in a6mods)
                    {
                        if (i == 28 && (a6 & (1 << 28)) != 0 ||
                            i == 29 && (a6 & (1 << 29)) == 0 ||
                            i == 31 && (a6 & ((uint)1 << 31)) != 0) continue;
                        //if (!((b1 & (1 << ((i + 4) % 32))) != 0))
                        //    throw new ArgumentException();
                        x[1] = ((d1 & (1 << ((i + 4) % 32))) == 0) ? x[1] + (uint)(1 << (i - 3)) : x[1] - (uint)(1 << (i - 3));
                        d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
                        x[2] = Unround1Operation(c0, d1, a1, b0, c1, 11);
                        x[3] = Unround1Operation(b0, c1, d1, a1, b1, 19);
                        x[5] = Unround1Operation(d1, a2, b1, c1, d2, 7);
                        a6 = Round2Operation(a5, b5, c5, d5, x[1], 3);
                        //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito))
                        //    throw new ArgumentException();
                    }
                    //if (!VerifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 5))
                    //    throw new ArgumentException();

                    //d6,29 = b5,29
                    d6 = Round2Operation(d5, a6, b5, c5, x[5], 5);
                    if ((d6 & (1 << 28)) != (b5 & (1 << 28)))
                    {
                        //if (!((b2 & (1 << 30)) != 0))
                        //    throw new ArgumentException();
                        x[5] = ((d2 & (1 << 30)) == 0) ? x[5] + (1 << 23) : x[5] - (1 << 23);
                        d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                        d6 = Round2Operation(d5, a6, b5, c5, x[5], 5);
                        x[6] = Unround1Operation(c1, d2, a2, b1, c2, 11);
                        x[7] = Unround1Operation(b1, c2, d2, a2, b2, 19);
                        x[9] = Unround1Operation(d2, a3, b2, c2, d3, 7);
                    }
                    //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito))
                    //    throw new ArgumentException();
                    //if (!VerifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 6))
                    //    throw new ArgumentException();

                    //c6,29 = d6,29, c6,30 = d6,30 + 1, c6,32 = d6,32 + 1
                    c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                    int[] c6mods = new int[] { 28, 29 };
                    foreach (int i in c6mods)
                    {
                        if (i == 28 && (c6 & (1 << 28)) == (d6 & (1 << 28)) ||
                            i == 29 && (c6 & (1 << 29)) != (d6 & (1 << 29))) continue;
                        //if (!((b3 & (1 << (i - 2))) != 0))
                        //    throw new ArgumentException();
                        x[9] = ((d3 & (1 << (i - 2))) == 0) ? x[9] + (uint)(1 << (i - 9)) : x[9] - (uint)(1 << (i - 9));
                        d3 = Round1Operation(d2, a3, b2, c2, x[9], 7);
                        x[10] = Unround1Operation(c2, d3, a3, b2, c3, 11);
                        x[11] = Unround1Operation(b2, c3, d3, a3, b3, 19);
                        x[13] = Unround1Operation(d3, a4, b3, c3, d4, 7);
                        c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                        //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito))
                        //    throw new ArgumentException();
                    }
                    if ((c6 & (1 << 31)) == (d6 & (1 << 31)))
                    {
                        //if (!((c2 & (1 << 22)) == 0 && (!bNaito || (d2 & (1 << 22)) == (a2 & (1 << 22))) && (b2 & (1 << 22)) == 0))
                        //    throw new ArgumentException();
                        if (!bNaito && !((d2 & (1 << 22)) == (a2 & (1 << 22)))) {
                            //if c5,32 and c6,32 are both corrected, an error will occur need to detect and return...
                            return null;
                            //continue;
                        }
                        x[6] = (c2 & (1 << 22)) == 0 ? x[6] + (1 << 11) : x[6] - (1 << 11);
                        c2 = Round1Operation(c1, d2, a2, b1, x[6], 11);
                        x[9] -= (1 << 22);
                        c6 = Round2Operation(c5, d6, a6, b5, x[9], 9);
                        x[10] -= (1 << 22);
                    }
                    //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito))
                    //    throw new ArgumentException();

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
                    //if (!VerifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 7))
                    //    throw new ArgumentException();

                    if ((bNaito || (b4 & ((uint)1 << 31)) == (c4 & ((uint)1 << 31)) && ((a6 & (1 << 29)) == 0)) && ((b9 & ((uint)1 << 31)) != 0 && (a10 & ((uint)1 << 31)) != 0))
                        return x.SelectMany((b) => BitConverter.GetBytes(b)).ToArray();
                } while (!bNaito);
                if (bNaito)
                {
                    //...round 3 modifications for exact collision not known how to hold without stomping on rounds 1 and 2
                    //for all values except b3,20, b3,21, b3,22, b3,23, b3,26, b3,27, b3,28, b3,29, b3,30, b3,32 + b3,16, b3,17, b3,19
                    //cannot stomp on these first round bit positions either: 10, 12, 29 + 7, 9, 10, 28, 31 + 0, 3, 7, 9, 12, 29
                    int[] permutebits = new int[] { 4, 5, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 30 }; //b3 free bit indexes: { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17, 23, 24, 30 };
                    uint b3save = b3, x11save = x[11], x15save = x[15];
                    //if (!((c3 & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))) ==
                    //     (d3 & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))) &&
                    //     (a4 & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))) == 0 &&
                    //     (d4 & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))) != 0))
                    //    throw new ArgumentException();
                    for (int i = 1; i < (1 << 19); i++) {
                        for (int c = 0; c < 19; c++) {
                            if ((i & (1 << c)) != 0)
                            {
                                //if (!((c3 & ((uint)1 << ((19 + permutebits[c]) % 32))) == (d3 & ((uint)1 << ((19 + permutebits[c]) % 32))) && (a4 & ((uint)1 << ((19 + permutebits[c]) % 32))) == 0 && (d4 & ((uint)1 << ((19 + permutebits[c]) % 32))) != 0))
                                //    throw new ArgumentException();
                                x[11] = (b3 & ((uint)1 << ((19 + permutebits[c]) % 32))) == 0 ? x[11] + ((uint)1 << (permutebits[c])) : x[11] - ((uint)1 << (permutebits[c]));
                                b3 = Round1Operation(b2, c3, d3, a3, x[11], 19);
                                //c4 = ROL(c3 + ((d4 & a4) | (~d4 & b3)) + x[14], 11) //d4 should be set not unset like the paper shows or this will fail
                                //c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
                                x[15] = Unround1Operation(b3, c4, d4, a4, b4, 19);
                            }
                        }
                        c8 = Round2Operation(c7, d8, a8, b7, x[11], 9);
                        b8 = Round2Operation(b7, c8, d8, a8, x[15], 13);
                        //if (!VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito) ||
                        //    !VerifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 7))
                        //{
                        //    throw new ArgumentException();
                        //}
                        a9 = Round3Operation(a8, b8, c8, d8, x[0], 3);
                        d9 = Round3Operation(d8, a9, b8, c8, x[8], 9);
                        c9 = Round3Operation(c8, d9, a9, b8, x[4], 11);
                        //b9,32 = 1
                        b9 = Round3Operation(b8, c9, d9, a9, x[12], 15);
                        //a10,32 = 1
                        a10 = Round3Operation(a9, b9, c9, d9, x[2], 3);
                        if (((b9 & ((uint)1 << 31)) != 0 && (a10 & ((uint)1 << 31)) != 0)) return x.SelectMany((b) => BitConverter.GetBytes(b)).ToArray();
                        b3 = b3save;
                        x[11] = x11save;
                        x[15] = x15save;
                    }
                }
                return null;
            }
        }
        //RFC 2104 HMAC(k,m)=H((K' xor opad) || H((K' xor ipad) || m))
        public static byte[] hmac(byte[] key, byte[] message)
        {
            SHA1Context sc = new SHA1Context(); //64 bit block size for SHA-1 and MD4
            if (key.Length > 64)
            {
                SHA1_Algo.SHA1Reset(sc);
                SHA1_Algo.SHA1Input(sc, key);
                key = new byte[64];
                SHA1_Algo.SHA1Result(sc, key);
            }
            else if (key.Length < 64)
            {
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
        public static BigInteger posRemainder(BigInteger dividend, BigInteger divisor)
        {
            if (dividend >= 0 && dividend < divisor) return dividend;
            BigInteger r = dividend % divisor;
            return r < 0 ? r + divisor : r;
        }
        //Extended Euclid GCD of 1
        public static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            if (a < 0) a = posRemainder(a, n);
            while (a > 0)
            {
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
        public static BigInteger KangF(BigInteger y, int k)
        {
            return BigInteger.One << (int)(BigInteger.Remainder(y, k));
            //return BigInteger.Pow(2, (int)BigInteger.Remainder(y, k));
        }
        public static BigInteger PollardKangaroo(BigInteger a, BigInteger b, int k, BigInteger g, BigInteger p, BigInteger y)
        {
            BigInteger xT = BigInteger.Zero;
            BigInteger yT = BigInteger.ModPow(g, b, p);
            //N is then derived from f -take the mean of all possible outputs of f and multiply it by a small constant, e.g. 4.
            //actual mean is:
            //int N = (1 << (k >> 1)) * 4;
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
            for (ulong i = 1; i <= N; i++)
            {
                BigInteger KF = BigInteger.Remainder(KangF(yT.Item1, k), p);
                xT = xT + KF;
                yT = addEC(yT, scaleEC(G, KF, Ea, p), Ea, p);
            }
            //now yT = g^(b + xT)
            //Console.WriteLine("yT = " + HexEncode(yT.ToByteArray()) + " g^(b + xT) = " + HexEncode(BigInteger.ModPow(g, b + xT, p).ToByteArray()));
            BigInteger xW = BigInteger.Zero;
            Tuple<BigInteger, BigInteger> yW = y;
            BigInteger upperBound = (b - a + xT);
            while (xW < upperBound)
            {
                BigInteger KF = BigInteger.Remainder(KangF(yW.Item1, k), p);
                xW = xW + KF;
                yW = addEC(yW, scaleEC(G, KF, Ea, p), Ea, p);
                if (yW.Item1 == yT.Item1 && yW.Item2 == yT.Item2)
                {
                    return b + xT - xW;
                }
            }
            return BigInteger.Zero;
        }
        //Montgomery gives in his paper "Speeding the Pollard and Elliptic Curve Methods of Factorization" from 1987 the formula on page 19:
        //x3=((y1-y2)/(x1-x2))^2-A-x1-x2, x coordinate point addition
        //Affine addition/doubling formulae: http://hyperelliptic.org/EFD/g1p/auto-montgom.html
        public static BigInteger PollardKangarooECmontg(BigInteger a, BigInteger b, int k, Tuple<BigInteger, BigInteger> G, int EaOrig, int Ea, int Eb, BigInteger p, Tuple<BigInteger, BigInteger> y, int conv)
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
            while (xW < upperBound)
            {
                BigInteger KF = BigInteger.Remainder(KangF(yW.Item1, k), p);
                xW = xW + KF;
                yW = addEC(yW, montgToWS(ladder2(G, KF, Ea, EaOrig, Eb, p, conv), conv), EaOrig, p);
                if (yW.Item1 == yT.Item1 && yW.Item2 == yT.Item2)
                {
                    return b + xT - xW;
                }
            }
            return BigInteger.Zero;
        }

        public static Tuple<BigInteger, BigInteger> invertEC(Tuple<BigInteger, BigInteger> P, BigInteger GF)
        {
            return new Tuple<BigInteger, BigInteger>(P.Item1, GF - P.Item2);
        }
        public static Tuple<BigInteger, BigInteger> addEC(Tuple<BigInteger, BigInteger> P1, Tuple<BigInteger, BigInteger> P2, int a, BigInteger GF)
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
        public static Tuple<BigInteger, BigInteger> scaleEC(Tuple<BigInteger, BigInteger> x, BigInteger k, int a, BigInteger GF)
        {
            Tuple<BigInteger, BigInteger> result = new Tuple<BigInteger, BigInteger>(0, 1);
            if (k < 0)
            {
                x = invertEC(x, GF);
                k = -k;
            }
            while (k > 0)
            {
                if (!k.IsEven) result = addEC(result, x, a, GF);
                x = addEC(x, x, a, GF);
                k = k >> 1;
            }
            return result;
        }
        public static BigInteger GetRandomBitSize(RandomNumberGenerator rng, int BitSize, BigInteger Max)
        {
            byte[] r = new byte[(BitSize >> 3) + 1];
            rng.GetBytes(r);
            r[r.Length - 1] &= (byte)((1 << (BitSize % 8)) - 1); //make sure it wont be interpreted as negative in little-endian order
            return new BigInteger(r) >= Max ? Max - 1 : new BigInteger(r);
        }
        public static BigInteger GetNextRandomBig(RandomNumberGenerator rnd, BigInteger Maximum)
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
        public static BigInteger TonelliShanks(RNGCryptoServiceProvider rng, BigInteger n, BigInteger p) //inverse modular square root
        {
            //Console.WriteLine(BigInteger.ModPow(n, (p - 1) / 2, p) == 1); //Euler's criterion must equal one or no square root exists
            //if ((n % p) == 0) return 0; //single root case if p is prime
            int S = 0;
            BigInteger Q = p - 1;
            while (Q.IsEven)
            {
                S++; Q >>= 1;
            }
            if (S == 1)
            {
                BigInteger r = BigInteger.ModPow(n, (p + 1) >> 2, p);
                return BigInteger.Remainder(r * r, p) == n ? r : 0;
            }
            BigInteger z;
            do { z = GetNextRandomBig(rng, p); } while (z <= 1 || BigInteger.ModPow(z, (p - 1) >> 1, p) != p - 1); //Euler's criterion for quadratic non-residue (== -1)
            int M = S;
            BigInteger c = BigInteger.ModPow(z, Q, p), t = BigInteger.ModPow(n, Q, p), R = BigInteger.ModPow(n, (Q + 1) >> 1, p);
            while (true)
            {
                if (t == 0 || M == 0) return 0;
                if (t == 1) return R;
                int i = 0; BigInteger tt = t;
                do
                {
                    i++;
                    tt = BigInteger.Remainder(tt * tt, p);
                } while (i < M && tt != 1);
                if (i == M) return 0; //no solution to the congruence exists
                BigInteger b = BigInteger.ModPow(c, BigInteger.ModPow(2, M - i - 1, p - 1), p);
                M = i; c = BigInteger.Remainder(b * b, p); t = BigInteger.Remainder(t * c, p); R = BigInteger.Remainder(R * b, p);
            }
        }
        public static int jacobi(BigInteger n, BigInteger k)
        {
            if (k <= 0 || k.IsEven) throw new ArgumentException();
            n = n % k;
            int t = 1;
            while (n != 0) {
                while (n.IsEven) {
                    n >>= 1;
                    int r = (int)(k & 7);
                    if (r == 3 || r == 5) t = -t;
                }
                (n, k) = (k, n);
                if ((n & 3) == 3 && (k & 3) == 3) t = -t;
                n = n % k;
            }
            return k == 1 ? t : 0;
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
                else if (a[aoffs] >= 0 && a[aoffs] < GF && b[boffs] >= 0 && b[boffs] >= 0 && b[boffs] < GF)
                {
                    c[coffs] = a[aoffs] + b[boffs];
                    if (c[coffs] >= GF) c[coffs] -= GF;
                }
                else c[coffs] = posRemainder(a[aoffs] + b[boffs], GF);
            }
            return clen == 0 || c[0] != BigInteger.Zero ? c : c.SkipWhile((BigInteger cr) => cr == BigInteger.Zero).ToArray(); ;
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
            if (a < 0)
            {
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
            for (int i = 0; i < bits; i++)
            {
                d = (d > mp2) ? (d << 1) - m : d << 1;
                if ((a & check) != 0) d += b;
                if (d >= m) d -= m;
                a <<= 1;
            }
            //if (res != d) throw new ArgumentException();
            return d;
        }
        static uint reverseBits(uint v)
        {
            v = ((v >> 1) & 0x55555555) | ((v & 0x55555555) << 1);
            v = ((v >> 2) & 0x33333333) | ((v & 0x33333333) << 2);
            v = ((v >> 4) & 0x0F0F0F0F) | ((v & 0x0F0F0F0F) << 4);
            v = ((v >> 8) & 0x00FF00FF) | ((v & 0x00FF00FF) << 8);
            return (v >> 16) | (v << 16);
            //return BitConverter.ToUInt32(BitConverter.GetBytes(idx).Select((b) => (byte)(((b * (UInt64)0x80200802U) & 0x0884422110U) * 0x0101010101U >> 32)).Reverse().ToArray(), 0);
        }
        static BigInteger[] dft(BigInteger[] A, int m, int n, BigInteger subMask)
        {
            bool even = (m & 1) == 0;
            int len = A.Length;
            int v = 1;
            int twoton = 1 << n;
            int twotonp1 = 1 << (n + 1);
            BigInteger testMask = BigInteger.One << twotonp1;
            BigInteger testMaskm1 = testMask - BigInteger.One;
            Dictionary<int, BigInteger> xmasks = new Dictionary<int, BigInteger>();
            //BigInteger subMask = (BigInteger.One << twoton) - BigInteger.One;
            for (int slen = len >> 1; slen > 0; slen >>= 1)
            {
                for (int j = 0; j < len; j += (slen << 1))
                {
                    int idx = j;
                    int x = (int)((reverseBits((uint)(idx + len)) << (n - v)) >> (32 - 1 - n));
                    if (even) x >>= 1;
                    if (!xmasks.ContainsKey(twotonp1 - x)) xmasks.Add(twotonp1 - x, getBitMaskBigInteger(twotonp1 - x));
                    BigInteger xmask = xmasks[twotonp1 - x]; // (BigInteger.One << (twotonp1 - x)) - BigInteger.One;
                    for (int k = slen - 1; k >= 0; k--)
                    {
                        BigInteger d = ((A[idx + slen] & xmask) << x) | (A[idx + slen] >> (twotonp1 - x)); //rotation based on gamma
                        A[idx + slen] = A[idx];
                        A[idx] += d;
                        if ((A[idx] & testMask) != BigInteger.Zero) A[idx] = (A[idx] & testMaskm1) + BigInteger.One;
                        A[idx + slen] += ((d & subMask) << twoton) | (d >> twoton); //even rotation
                        if ((A[idx + slen] & testMask) != BigInteger.Zero) A[idx + slen] = (A[idx + slen] & testMaskm1) + BigInteger.One;
                        idx++;
                    }
                }
                v++;
            }
            return A;
        }
        static BigInteger[] idft(BigInteger[] A, int m, int n, BigInteger subMask)
        {
            bool even = (m & 1) == 0;
            int len = A.Length;
            int v = n - 1;
            int twoton = 1 << n;
            int twotonp1 = 1 << (n + 1);
            BigInteger testMask = BigInteger.One << twotonp1;
            BigInteger testMaskm1 = testMask - BigInteger.One;
            //if (testMaskm1 != getBitMaskBigInteger(twotonp1)) throw new ArgumentException();
            //BigInteger subMask = (BigInteger.One << twoton) - BigInteger.One;
            for (int slen = 1; slen <= (len >> 1); slen <<= 1)
            {
                for (int j = 0; j < len; j += (slen << 1))
                {
                    int idx = j;
                    int idx2 = idx + slen;
                    int x = (int)((reverseBits((uint)(idx)) << (n - v)) >> (32 - n));
                    x += (1 << (n - v - (even ? 0 : 1))) + 1;
                    BigInteger xmask = getBitMaskBigInteger(x); //(BigInteger.One << x) - BigInteger.One;
                    for (int k = slen - 1; k >= 0; k--)
                    {
                        BigInteger c = A[idx];
                        A[idx] += A[idx2];
                        if ((A[idx] & testMask) != BigInteger.Zero) A[idx] = (A[idx] & testMaskm1) + BigInteger.One; //1 bit rotation
                        if (A[idx].IsEven) A[idx] = (A[idx] >> 1);
                        else A[idx] = (A[idx] >> 1) | (BigInteger.One << (twotonp1 - 1));
                        c += ((A[idx2] & subMask) << twoton) | (A[idx2] >> twoton); //even rotation
                        if ((c & testMask) != BigInteger.Zero) c = (c & testMaskm1) + BigInteger.One;
                        A[idx2] = (c >> x) | ((c & xmask) << (twotonp1 - x)); //rotation based on gamma
                        idx++; idx2++;
                    }
                }
                v--;
            }
            return A;
        }
        //https://github.com/tbuktu/ntru/blob/master/src/main/java/net/sf/ntru/arith/SchönhageStrassen.java
        static BigInteger mulSchonhageStrassen(BigInteger num1, BigInteger num2, int num1bits, int num2bits)
        {
            int M = Math.Max(num1bits, num2bits);
            int m = GetBitSize(M) + 1; //smallest m >= log2(2*M) //minimum of at least one bit number
            //m = (n - 1) << 1; or (6 - 1) << 1 == 10
            int n = (m >> 1) + 1; //n >= 6 only for this implementation and small sizes would not be useful here anyway
            bool even = (m & 1) == 0;
            int numPieces = 1 << (even ? n : (n + 1));
            int pieceLog = n - 1 - 5;
            int pieceSize = 1 << pieceLog;
            int pieceBits = 1 << (n - 1);
            int numPiecesA = (num1bits + pieceSize) >> pieceLog;
            int numPiecesB = (num2bits + pieceSize) >> pieceLog;
            BigInteger u = BigInteger.Zero;
            BigInteger v = BigInteger.Zero;
            int uBitLength = 0, vBitLength = 0;
            BigInteger pieceMask = (BigInteger.One << (n + 2)) - BigInteger.One;
            int threen5 = 3 * n + 5;
            //build u and v from a and b allocating 3n+5 bits in u and v per n+2 bits from a and b respectively
            //for (int i = 0; i < numPiecesA && (i << (n - 1)) < num1bits; i++) {
            //u |= ((num1 >> (i << (n - 1))) & pieceMask) << uBitLength;
            //uBitLength += threen5;
            //}
            //for (int i = 0; i < numPiecesB && (i << (n - 1)) < num2bits; i++) {
            //v |= ((num2 >> (i << (n - 1))) & pieceMask) << vBitLength;
            //vBitLength += threen5;
            //}
            //if (u != combineBigIntegers(multiSplitBigInteger(num1, pieceBits, numPiecesA).Select((BigInteger nm) => nm & pieceMask).ToArray(), threen5)) throw new ArgumentException();
            //if (v != combineBigIntegers(multiSplitBigInteger(num2, pieceBits, numPiecesB).Select((BigInteger nm) => nm & pieceMask).ToArray(), threen5)) throw new ArgumentException();
            numPiecesA = Math.Min(numPiecesA, ((num1bits >> (n - 1)) + 1));
            numPiecesB = Math.Min(numPiecesB, ((num2bits >> (n - 1)) + 1));
            u = combineBigIntegers(multiSplitBigInteger(num1, pieceBits, numPiecesA).Select((BigInteger nm) => nm & pieceMask).ToArray(), threen5);
            v = combineBigIntegers(multiSplitBigInteger(num2, pieceBits, numPiecesB).Select((BigInteger nm) => nm & pieceMask).ToArray(), threen5);
            uBitLength = threen5 * numPiecesA;
            vBitLength = threen5 * numPiecesB;
            //BigInteger gamma = u * v;
            BigInteger gamma = doBigMul(u, v, uBitLength, vBitLength);
            u = BigInteger.Zero; v = BigInteger.Zero;
            int halfNumPcs = numPieces >> 1;
            int numPiecesG = (GetBitSize(gamma) + threen5 - 1) / threen5;
            //BigInteger[] gammai = new BigInteger[numPiecesG];
            //BigInteger threen5mask = (BigInteger.One << threen5) - BigInteger.One;
            //for (int i = 0; i < numPiecesG; i++) {
            //gammai[i] = (gamma >> (i * threen5)) & threen5mask;
            //}
            BigInteger[] gammai = multiSplitBigInteger(gamma, threen5, numPiecesG);
            gamma = BigInteger.Zero;
            BigInteger[] zi = new BigInteger[numPiecesG];
            Array.Copy(gammai, 0, zi, 0, numPiecesG);
            for (int i = 0; i < gammai.Length - halfNumPcs; i++)
                zi[i] = (zi[i] - gammai[i + halfNumPcs]) & pieceMask;
            for (int i = 0; i < gammai.Length - (halfNumPcs << 1); i++)
                zi[i] = (zi[i] + gammai[i + (halfNumPcs << 1)]) & pieceMask;
            for (int i = 0; i < gammai.Length - 3 * halfNumPcs; i++)
                zi[i] = (zi[i] - gammai[i + 3 * halfNumPcs]) & pieceMask;

            //BigInteger[] ai = new BigInteger[halfNumPcs], bi = new BigInteger[halfNumPcs];
            //BigInteger fullPieceMask = (BigInteger.One << pieceBits) - 1;
            //for (int i = 0; i < halfNumPcs; i++) {
            //    int shiftl = i << (n - 1);
            //    if (num1bits > shiftl) ai[i] = (num1 >> shiftl) & fullPieceMask;
            //    if (num2bits > shiftl) bi[i] = (num2 >> shiftl) & fullPieceMask;
            //}
            BigInteger[] ai = multiSplitBigInteger(num1, pieceBits, halfNumPcs);
            BigInteger[] bi = multiSplitBigInteger(num2, pieceBits, halfNumPcs);
            //if (!ai.SequenceEqual(multiSplitBigInteger(num1, pieceBits, halfNumPcs))) throw new ArgumentException();
            //if (!bi.SequenceEqual(multiSplitBigInteger(num2, pieceBits, halfNumPcs))) throw new ArgumentException();
            int nbits = 1 << n;
            BigInteger halfMask = (BigInteger.One << nbits) - BigInteger.One;
            ai = dft(ai, m, n, halfMask);
            bi = dft(bi, m, n, halfMask);
            BigInteger adjHalf = halfMask + 2; // (BigInteger.One << nbits) + BigInteger.One;
            for (int i = 0; i < halfNumPcs; i++)
            {
                ai[i] = (ai[i] & halfMask) - (ai[i] >> nbits);
                if (ai[i] < BigInteger.Zero) ai[i] += adjHalf;
                bi[i] = (bi[i] & halfMask) - (bi[i] >> nbits);
                if (bi[i] < BigInteger.Zero) bi[i] += adjHalf;
            }
            BigInteger[] c = new BigInteger[halfNumPcs];
            for (int i = 0; i < halfNumPcs; i++)
                c[i] = doBigMul(ai[i], bi[i], nbits, nbits);
            //c[i] = ai[i] * bi[i];
            ai = null; bi = null;
            c = idft(c, m, n, halfMask);
            for (int i = 0; i < c.Length; i++)
            {
                c[i] = (c[i] & halfMask) - (c[i] >> nbits);
                if (c[i] < BigInteger.Zero) c[i] += adjHalf;
            }
            BigInteger z = BigInteger.Zero, hipart = BigInteger.Zero; //, z2 = BigInteger.Zero;
            BigInteger pieceBitMask = (BigInteger.One << pieceBits) - BigInteger.One;
            BigInteger[] zs = new BigInteger[halfNumPcs];
            for (int i = 0; i < halfNumPcs; i++)
            {
                BigInteger eta = i >= zi.Length ? 0 : zi[i];
                if (eta.IsZero && c[i].IsZero)
                {
                    zs[i] = hipart;
                    //z |= hipart << (i << (n - 1));
                    hipart = BigInteger.Zero;
                    continue;
                }
                eta = (eta - c[i]) & pieceMask;
                int shift = i << (n - 1);
                //if (eta.IsZero) z2 += c[i] << shift;
                //else z2 += ((c[i] + eta) << shift) | (eta << (shift + nbits));
                if (i == halfNumPcs - 1)
                {
                    zs[i] = c[i] + eta + hipart;
                    //zs[i + 1] = eta; //technically this cannot occur
                    //z |= ((c[i] + eta + hipart) << shift) | (eta << (shift + nbits));
                }
                else if (eta.IsZero)
                {
                    BigInteger part = c[i] + hipart;
                    zs[i] = part & pieceBitMask;
                    //z |= (part & pieceBitMask) << shift;
                    hipart = part >> pieceBits;
                }
                else
                {
                    BigInteger part = c[i] + eta + hipart;
                    zs[i] = part & pieceBitMask;
                    //z |= (part & pieceBitMask) << shift;
                    hipart = (part >> pieceBits) | (eta << (nbits - pieceBits));
                }
                //if (z != (z2 & ((BigInteger.One << ((i + 1) << (n - 1))) - 1))) throw new ArgumentException();
            }
            //if (z != combineBigIntegers(zs, pieceBits)) throw new ArgumentException();
            //z = combineBigIntegers(zs, pieceBits);
            //nbits = 1 << m;
            //halfMask = (BigInteger.One << nbits) - BigInteger.One;
            //adjHalf = halfMask + 2; //(BigInteger.One << nbits) + BigInteger.One;
            //z = (z & halfMask) - (z >> nbits);
            //if (z < BigInteger.Zero) z += adjHalf;
            z = combineBigIntegers(zs.Take(halfNumPcs >> 2).ToArray(), pieceBits) - combineBigIntegers(zs.Skip(halfNumPcs >> 2).ToArray(), pieceBits);
            if (z < BigInteger.Zero) z += (BigInteger.One << nbits) + BigInteger.One;
            return z;

        }
        static BigInteger getBitMaskBigInteger(int bits)
        {
            //byte[] bytes = Enumerable.Repeat<byte>(255, (bits + 7) >> 3).Concat(new byte[] { 0 }).ToArray();
            //if ((bits & 7) != 0) bytes[bytes.Length - 2] &= (byte)((1 << (bits & 7)) - 1);
            byte[] bytes = new byte[((bits + 7) >> 3) + 1];
            bytes[bytes.Length - 2] = ((bits & 7) == 0) ? (byte)255 : (byte)(255 & ((1 << (bits & 7)) - 1));
            for (int i = bytes.Length - 3; i >= 0; i--) bytes[i] = 255;
            return new BigInteger(bytes);
        }
        static BigInteger combineBigIntegers(BigInteger[] nums, int bits)
        {
            int nlen = nums.Length;

            byte[] b = new byte[((nlen * bits + 7) >> 3) + (((nlen * bits) & 7) == 0 ? 1 : 0)]; //+1 for avoiding negatives
            int curBit = 0;
            for (int i = 0; i < nlen; i++)
            {
                int curByte = curBit >> 3, bit = curBit & 7;
                if (bit != 0)
                {
                    byte[] src = (nums[i] << bit).ToByteArray();
                    b[curByte] |= src[0];
                    Array.Copy(src, 1, b, curByte + 1, src.Length - 1);
                }
                else
                {
                    byte[] src = nums[i].ToByteArray();
                    Array.Copy(src, 0, b, curByte, src.Length);
                }
                curBit += bits;
            }
            return new BigInteger(b);
        }
        static BigInteger[] multiSplitBigInteger(BigInteger num, int bits, int size)
        {
            BigInteger[] c = new BigInteger[size];
            if (bits == 0) return c; //impossible split size
            byte[] bytes = num.ToByteArray();
            int blen = bytes.Length;
            if (blen == 0) return c;
            int curbits = 0, count = 0, startByte = 0;
            while (count < size)
            {
                int lastByte = (curbits + bits + 7) >> 3;
                int rembits = (curbits + bits) & 7;
                if (blen < lastByte) { lastByte = blen; rembits = 0; }
                byte[] taken = new byte[lastByte - startByte + ((bytes[lastByte - 1] & 0x80) != 0 ? 1 : 0)];
                Array.Copy(bytes, startByte, taken, 0, lastByte - startByte);
                if (rembits != 0) taken[lastByte - startByte - 1] &= (byte)((1 << rembits) - 1);
                if ((curbits & 7) != 0) c[count] = new BigInteger(taken) >> (curbits & 7);
                else c[count] = new BigInteger(taken);
                if (blen < (curbits + bits + 7) >> 3) break;
                startByte = lastByte - (rembits != 0 ? 1 : 0); curbits += bits; count++;
            }
            return c;
        }
        static ValueTuple<BigInteger, BigInteger> splitBigInteger(BigInteger num, int bits) //replacement for num >> bits
        {
            if (bits == 0) return new ValueTuple<BigInteger, BigInteger>(num, BigInteger.Zero);
            byte[] bytes = num.ToByteArray();
            int blen = bytes.Length;
            int bytesWanted = (bits + 7) >> 3;
            if (blen == 0 || blen < bytesWanted) return new ValueTuple<BigInteger, BigInteger>(BigInteger.Zero, num);
            bits = bits & 7;
            byte[] taken = new byte[bytesWanted + (bits == 0 && (bytes[bytesWanted - 1] & 0x80) != 0 ? 1 : 0)]; //need extra 0 byte in case would become negative
            Array.Copy(bytes, 0, taken, 0, bytesWanted);
            if (bits != 0) taken[bytesWanted - 1] &= (byte)((1 << bits) - 1);
            bytesWanted = bytesWanted - (bits == 0 ? 0 : 1);
            byte[] upper = new byte[blen - bytesWanted];
            Array.Copy(bytes, bytesWanted, upper, 0, blen - bytesWanted);
            if (bits != 0) return new ValueTuple<BigInteger, BigInteger>(new BigInteger(upper) >> bits, new BigInteger(taken));
            else return new ValueTuple<BigInteger, BigInteger>(new BigInteger(upper), new BigInteger(taken));
        }
        static BigInteger takeBitsBigInteger(BigInteger num, int bits) //replacement for num & ((BigInteger.One << bits) - 1)
        {
            if (bits == 0) return BigInteger.Zero;
            byte[] bytes = num.ToByteArray();
            int blen = bytes.Length;
            int bytesWanted = (bits + 7) >> 3;
            if (blen == 0 || blen < bytesWanted) return num;
            bits = bits & 7;
            byte[] taken = new byte[bytesWanted + (bits == 0 && (bytes[bytesWanted - 1] & 0x80) != 0 ? 1 : 0)]; //need extra 0 byte in case would become negative
            Array.Copy(bytes, 0, taken, 0, bytesWanted);
            if (bits != 0) taken[bytesWanted - 1] &= (byte)((1 << bits) - 1);
            return new BigInteger(taken);
        }

        static BigInteger mulKaratsubaFast(BigInteger num1, BigInteger num2, int num1bits, int num2bits)
        {
            return mulKaratsubaFastImpl(multiSplitBigInteger(num1, 4096, (num1bits + 4095) / 4096),
                multiSplitBigInteger(num2, 4096, (num2bits + 4095) / 4096));
        }
        static BigInteger[] addBigIntArrays(BigInteger[] num1, BigInteger[] num2)
        {
            int l1 = num1.Length, l2 = num2.Length;
            BigInteger[] c = new BigInteger[Math.Max(l1, l2) + 1];
            BigInteger carry = 0, carryMask = ((BigInteger.One << 4096) - 1);
            int i;
            for (i = 0; i < Math.Min(l1, l2); i++)
            {
                c[i] = num1[i] + num2[i] + carry;
                carry = c[i] >> 4096;
                if (carry != BigInteger.Zero) c[i] &= carryMask;
            }
            if (l1 > l2)
            {
                Array.Copy(num1, i, c, i, l1 - i);
            }
            else if (l2 > l1)
            {
                Array.Copy(num2, i, c, i, l2 - i);
            }
            while (carry != BigInteger.Zero)
            {
                c[i] += carry;
                carry = c[i] >> 4096;
                if (carry != BigInteger.Zero) c[i] &= carryMask;
                i++;
            }
            return c.Last() == BigInteger.Zero ? c.Take(c.Length - 1).ToArray() : c;
        }
        static BigInteger mulKaratsubaFastImpl(BigInteger[] num1, BigInteger[] num2)
        {
            int l1 = num1.Length, l2 = num2.Length;
            if (l1 == 0 || l2 == 0) return BigInteger.Zero;
            else if (l1 == 1) return doBigMul(num1[0], combineBigIntegers(num2, 4096), 4096, l2 * 4096);
            else if (l2 == 1) return doBigMul(combineBigIntegers(num1, 4096), num2[0], l1 * 4096, 4096);
            int m = Math.Min(l1, l2);
            int m2 = m >> 1;
            BigInteger[] low1 = new BigInteger[m2], low2 = new BigInteger[m2];
            Array.Copy(num1, 0, low1, 0, m2); Array.Copy(num2, 0, low2, 0, m2);
            BigInteger[] high1 = new BigInteger[l1 - m2], high2 = new BigInteger[l2 - m2];
            Array.Copy(num1, m2, high1, 0, l1 - m2); Array.Copy(num2, m2, high2, 0, l2 - m2);
            BigInteger z0 = mulKaratsubaFastImpl(low1, low2);
            BigInteger z1 = mulKaratsubaFastImpl(addBigIntArrays(low1, high1), addBigIntArrays(low2, high2));
            BigInteger z2 = mulKaratsubaFastImpl(high1, high2);
            m2 *= 4096;
            return ((z2 << (m2 << 1)) | z0) + ((z1 - z0 - z2) << m2);
        }
        static BigInteger mulKaratsuba(BigInteger num1, BigInteger num2, int num1bits, int num2bits)
        {
            //if (num1 < 2 || num2 < 2) return num1 * num2;
            //while ((BigInteger.One << (num1bits-1)) > num1) num1bits--;
            //while ((BigInteger.One << (num2bits-1)) > num2) num2bits--;
            //num1bits = GetBitSizeBinSearch(num1, 0, num1bits);
            //num2bits = GetBitSizeBinSearch(num2, 0, num2bits);
            //if (num1bits != GetBitSize(num1)) throw new ArgumentException();
            //if (num2bits != GetBitSize(num2)) throw new ArgumentException();
            int m = Math.Min(num1bits, num2bits);
            int m2 = m >> 1;
            BigInteger low1, low2, high1, high2;
            //(high1, low1) = splitBigInteger(num1, m2);
            //(high2, low2) = splitBigInteger(num2, m2);
            BigInteger m2shift = (BigInteger.One << m2) - BigInteger.One;
            //low1 = takeBitsBigInteger(num1, m2);
            low1 = num1 & m2shift;
            //low2 = takeBitsBigInteger(num2, m2);
            low2 = num2 & m2shift;
            high1 = num1 >> m2;
            high2 = num2 >> m2;
            BigInteger z0 = doBigMul(low1, low2, m2, m2);
            BigInteger lowhigh1 = low1 + high1, lowhigh2 = low2 + high2;
            BigInteger z1 = doBigMul(lowhigh1, lowhigh2, num1bits - m2 + 1, num2bits - m2 + 1);
            BigInteger z2 = doBigMul(high1, high2, num1bits - m2, num2bits - m2);
            return ((z2 << (m2 << 1)) | z0) + ((z1 - z0 - z2) << m2);
        }
        static BigInteger doBigMul(BigInteger num1, BigInteger num2, int num1bits, int num2bits)
        {
            if (num1 <= uint.MaxValue && num2 <= uint.MaxValue)
            {
                UInt64 res = (UInt64)num1 * (UInt64)num2;
                return new BigInteger(res);
            }
            if (num1 <= uint.MaxValue || num2 <= uint.MaxValue ||
                num1bits <= 4096 || num2bits <= 4096) return num1 * num2; //experimentally determined threshold 8192 is next best
                                                                          //if (num1bits >= 1728 * 64 && num2bits >= 1728 * 64)
                                                                          //return mulSchonhageStrassen(num1, num2, num1bits, num2bits);
            return mulKaratsuba(num1, num2, num1bits, num2bits);
        }
        static BigInteger bigMul(BigInteger num1, BigInteger num2)
        {
            int signum = num1.Sign * num2.Sign;
            if (num1.Sign < 0) num1 = -num1;
            if (num2.Sign < 0) num2 = -num2;
            BigInteger res = doBigMul(num1, num2, GetBitSize(num1), GetBitSize(num2));
            return signum < 0 ? -res : res;
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
            //for (int i = 0; i < alen; i++) {
            //    if (A[i] < 0) Apack |= posRemainder(A[i], GF) << ((alen - i - 1) * packSize);
            //    else Apack |= A[i] << ((alen - i - 1) * packSize);
            //}
            //for (int i = 0; i < blen; i++) {
            //    if (B[i] < 0) Bpack |= posRemainder(B[i], GF) << ((blen - i - 1) * packSize);
            //    else Bpack |= B[i] << ((blen - i - 1) * packSize);
            //}
            //if (Apack != combineBigIntegers(A.Select((BigInteger nm) => nm < 0 ? posRemainder(nm, GF) : nm).Reverse().ToArray(), packSize)) throw new ArgumentException();
            //if (Bpack != combineBigIntegers(B.Select((BigInteger nm) => nm < 0 ? posRemainder(nm, GF) : nm).Reverse().ToArray(), packSize)) throw new ArgumentException();
            Apack = combineBigIntegers(A.Select((BigInteger nm) => nm < 0 ? posRemainder(nm, GF) : nm).Reverse().ToArray(), packSize);
            Bpack = combineBigIntegers(B.Select((BigInteger nm) => nm < 0 ? posRemainder(nm, GF) : nm).Reverse().ToArray(), packSize);
            //BigInteger Cpack = Apack * Bpack; //should use Schonhage-Strassen here
            BigInteger Cpack = doBigMul(Apack, Bpack, packSize * alen, packSize * blen);
            //BigInteger[] p = new BigInteger[alen + blen - 1];
            //BigInteger packMask = (BigInteger.One << packSize) - 1;
            //for (int i = 0; i < alen + blen - 1; i++) {
            //p[i] = posRemainder((Cpack >> ((alen + blen - 1 - i - 1) * packSize)) & packMask, GF);
            //}
            IEnumerable<BigInteger> p = multiSplitBigInteger(Cpack, packSize, alen + blen - 1).Select((BigInteger nm) => posRemainder(nm, GF)).Reverse();
            //for (int i = alen + blen - 1 - 1; i >= 0; i--) {                
            //    p[i] = posRemainder(Cpack & packMask, GF);
            //    Cpack >>= packSize;
            //}
            //if (!p.SequenceEqual(ps)) throw new ArgumentException();
            return p.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray();
        }
        static BigInteger[] mulPolyRing(BigInteger[] A, BigInteger[] B, BigInteger GF)
        {
            int alen = A.Length, blen = B.Length;
            if (GetBitSize(GF) * Math.Min(alen, blen) > 16384) return mulPolyRingKronecker(A, B, GF);
            if (alen == 0) return A; if (blen == 0) return B;
            BigInteger[] p = new BigInteger[alen + blen - 1];
            for (int i = 0; i < blen; i++)
            {
                if (B[i] == BigInteger.Zero) continue;
                for (int j = 0; j < alen; j++)
                {
                    if (A[j] == BigInteger.Zero) continue;
                    int ijoffs = i + j;
                    //if (posRemainder(A[j] * B[i], GF) != posRemainder(mulKaratsuba(A[j] < 0 ? posRemainder(A[j], GF) : A[j], B[i] < 0 ? posRemainder(B[i], GF) : B[i]), GF)) throw new ArgumentException();
                    //p[ijoffs] += posRemainder(mulKaratsuba(A[j] < 0 ? posRemainder(A[j], GF) : A[j], B[i] < 0 ? posRemainder(B[i], GF) : B[i]), GF);
                    //p[ijoffs] += modmul(A[j], B[i], GF);
                    //p[ijoffs] += posRemainder(A[j] * B[i], GF);
                    //if (p[ijoffs] >= GF) p[ijoffs] -= GF;
                    if (B[i] == -1) p[ijoffs] += (GF - A[j]);
                    else if (A[j] == -1) p[ijoffs] += (GF - B[i]);
                    else p[ijoffs] += A[j] * B[i];
                }
            }
            //while (!A.All((BigInteger c) => c == BigInteger.Zero)) {
            //    if (A[0] != BigInteger.Zero) p = posRemainder(p + B, GF);
            //    A = A.Skip(1).ToArray(); B = B.Concat(new BigInteger[] { BigInteger.Zero }).ToArray();
            //}
            //if (!mulPolyRingKronecker(A, B, GF).SequenceEqual(p.SkipWhile((BigInteger c) => c == BigInteger.Zero).Select((x) => posRemainder(x, GF)).ToArray())) {
            //throw new ArgumentException();
            //}
            //return p.Length == 0 || p[0] != BigInteger.Zero ? p : p.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray();
            return p.SkipWhile((BigInteger c) => c == BigInteger.Zero).Select((x) => posRemainder(x, GF)).ToArray();
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
                //r = addPolyRing(r, mulPolyRing(bneg, q.Skip(aoffs).ToArray(), GF), GF);
                r = addPolyRing(r, mulPolyRing(bneg, new BigInteger[] { q[aoffs] }, GF).Concat(q.Skip(aoffs + 1)).ToArray(), GF);
                rlen = r.Length;
            }
            return new Tuple<BigInteger[], BigInteger[]>(q.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray(), r);
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
                if (q[d] == BigInteger.Zero)
                {
                    q.Remove(d);
                    break;
                }
                r = addPolyRingSparse(r, mulPolyRingSparse(bneg, new SortedList<BigInteger, BigInteger>(q.TakeWhile((kv) => kv.Key <= d).ToDictionary(x => x.Key, x => x.Value)), GF), GF);
            }
            BigInteger[] rret = new BigInteger[(int)r.Last().Key + 1];
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
            for (int r = 2; r <= n - m + 1; r++)
            {
                BigInteger sum = BigInteger.Zero;
                for (int i = 1; i <= Math.Min(r - 1, m); i++)
                {
                    sum = posRemainder(sum + (-B[i] * t[r - i - 1]), GF);
                }
                t[r - 1] = posRemainder(t[0] * sum, GF);
            }
            for (int k = 0; k < m; k++)
            {
                if (A.ContainsKey(k)) remainder[m - 1 - k] = A[k];
                BigInteger outersum = BigInteger.Zero;
                for (int i = 0; i <= k; i++)
                {
                    int j = k - i;
                    BigInteger sum = BigInteger.Zero;
                    //all in A between m+j and n
                    foreach (KeyValuePair<BigInteger, BigInteger> kval in A.Where((kv) => kv.Key >= m + j))
                    {
                        //for (int v = 0; v <= n - m - j; v++) {
                        int v = (int)(n - kval.Key);
                        //if (A.ContainsKey(n - v))
                        sum = posRemainder(sum + (t[(int)n - m - j + 1 - v - 1] * A[n - v]), GF);
                    }
                    outersum = posRemainder(outersum + ((i == m ? B[m - i] : (-B[m - i])) * sum), GF);
                }
                remainder[m - 1 - k] = posRemainder(remainder[m - 1 - k] + outersum, GF); //make monic with posRemainder(t[0] * outersum, GF)
            }
            return remainder.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray();
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
            foreach (KeyValuePair<BigInteger, BigInteger> elem in A)
            {
                BigInteger exp = elem.Key;
                BigInteger[] result = new BigInteger[] { BigInteger.One };
                BigInteger[] b = new BigInteger[] { BigInteger.One, BigInteger.Zero };
                while (exp > 0)
                {
                    if ((exp & 1) == 1)
                    {
                        result = divmodPolyRing(mulPolyRing(result, b, GF), B, GF).Item2;
                    }
                    exp >>= 1;
                    b = divmodPolyRing(mulPolyRing(b, b, GF), B, GF).Item2;
                }
                result = mulPolyRing(result, new BigInteger[] { elem.Value }, GF);
                remainder = addPolyRing(result, remainder, GF);
            }
            return remainder.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray();
        }
        static BigInteger[] substitutePolyRing(BigInteger[] A, BigInteger[] B, BigInteger[] divpoly, BigInteger GF)
        {
            BigInteger[] result = new BigInteger[] { BigInteger.Zero };
            int alen = A.Length;
            for (int i = 0; i < alen; i++)
            {
                if (i == alen - 1)
                {
                    result = addPolyRing(result, new BigInteger[] { A[i] }, GF);
                }
                else
                {
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
            if (i.Length > 1) return null; //no modular inverse exists if degree more than 0...
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
            if (P1.Item1.SequenceEqual(P2.Item1) && P1.Item2.SequenceEqual(P2.Item2))
            {
                BigInteger[] factor = divmodPolyRing(mulPolyRing(mulPolyRing(new BigInteger[] { 2 }, y1, GF), f, GF), divpoly, GF).Item2;
                BigInteger[] div = modInversePolyRing(factor, divpoly, GF);
                if (div == null) return new Tuple<BigInteger[], BigInteger[]>(null, factor);
                m = divmodPolyRing(mulPolyRing(addPolyRing(mulPolyRing(new BigInteger[] { 3 }, mulPolyRing(x1, x1, GF), GF), new BigInteger[] { a }, GF), div, GF), divpoly, GF).Item2;
            }
            else
            {
                BigInteger[] factor = divmodPolyRing(addPolyRing(x2, mulPolyRing(x1, new BigInteger[] { -1 }, GF), GF), divpoly, GF).Item2;
                BigInteger[] div = modInversePolyRing(factor, divpoly, GF);
                if (div == null) return new Tuple<BigInteger[], BigInteger[]>(null, factor);
                m = divmodPolyRing(mulPolyRing(addPolyRing(y2, mulPolyRing(y1, new BigInteger[] { -1 }, GF), GF), div, GF), divpoly, GF).Item2;
            }
            BigInteger[] x3 = divmodPolyRing(addPolyRing(addPolyRing(mulPolyRing(f, mulPolyRing(m, m, GF), GF), mulPolyRing(x1, new BigInteger[] { -1 }, GF), GF), mulPolyRing(x2, new BigInteger[] { -1 }, GF), GF), divpoly, GF).Item2;
            return new Tuple<BigInteger[], BigInteger[]>(x3, divmodPolyRing(addPolyRing(mulPolyRing(m, addPolyRing(x1, mulPolyRing(x3, new BigInteger[] { -1 }, GF), GF), GF), mulPolyRing(y1, new BigInteger[] { -1 }, GF), GF), divpoly, GF).Item2);
        }
        static Tuple<BigInteger[], BigInteger[]> scaleECPolyRing(Tuple<BigInteger[], BigInteger[]> x, BigInteger k, int a, BigInteger GF, BigInteger[] divpoly, BigInteger[] f)
        {
            Tuple<BigInteger[], BigInteger[]> result = new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.Zero }, new BigInteger[] { BigInteger.One });
            while (k > 0)
            {
                if (!k.IsEven)
                {
                    result = addECPolyRing(result, x, a, GF, divpoly, f);
                    if (result.Item1 == null) return result; //division by zero case
                }
                x = addECPolyRing(x, x, a, GF, divpoly, f);
                if (x.Item1 == null) return x; //division by zero case
                k = k >> 1;
            }
            return result;
        }
        static Tuple<BigInteger[], BigInteger[]> scaleECDivPoly(Tuple<BigInteger[], BigInteger[]> x, int k, BigInteger GF, List<BigInteger[]> divpolys, BigInteger[] divpoly, BigInteger[] f)
        {
            BigInteger[] ysub = mulPolyRing(f, new BigInteger[] { 4 }, GF); //2*y or 4*y^2 really
            BigInteger[] num = mulPolyRing(mulPolyRing(divpolys[k + 1], divpolys[k - 1], GF), new BigInteger[] { -1 }, GF);
            BigInteger[] ynum = divpolys[2 * k]; //this is even so need to divide out a y...
            BigInteger[] denom = mulPolyRing(divpolys[k], divpolys[k], GF);
            BigInteger[] ydenom = mulPolyRing(mulPolyRing(denom, denom, GF), new BigInteger[] { 2 }, GF);
            if ((k & 1) != 0)
            {
                num = divmodPolyRing(num, ysub, GF).Item1;
            }
            else
            {
                denom = divmodPolyRing(denom, ysub, GF).Item1;
                ydenom = divmodPolyRing(ydenom, mulPolyRing(ysub, ysub, GF), GF).Item1;
            }
            BigInteger[] modinv = modInversePolyRing(denom, divpoly, GF);
            BigInteger[] rx = addPolyRing(new BigInteger[] { BigInteger.One, BigInteger.Zero },
                modinv == null ? num : divmodPolyRing(mulPolyRing(num, modinv, GF), divpoly, GF).Item2, GF);
            BigInteger[] ymodinv = modInversePolyRing(divmodPolyRing(ydenom, divpoly, GF).Item2, divpoly, GF);
            BigInteger[] ry = ymodinv == null ? ynum : divmodPolyRing(mulPolyRing(ynum, ymodinv, GF), divpoly, GF).Item2; //this likely needs a modInverse to make the y coefficient in the numerator
            BigInteger[] yinv = modInversePolyRing(divmodPolyRing(mulPolyRing(f, mulPolyRing(x.Item2, new BigInteger[] { 2 }, GF), GF), divpoly, GF).Item2, divpoly, GF); //divide by y
            //BigInteger[] yinv = modInversePolyRing(ysub, divpoly, GF); //divide by y
            return new Tuple<BigInteger[], BigInteger[]>(substitutePolyRing(rx, x.Item1, divpoly, GF), divmodPolyRing(mulPolyRing(substitutePolyRing(ry, x.Item1, divpoly, GF), yinv, GF), divpoly, GF).Item2);
        }

        static bool isSqrt(BigInteger n, BigInteger root)
        {
            BigInteger lowerBound = root * root;
            return (n >= lowerBound && n <= lowerBound + root + root);
        }
        public static BigInteger Sqrt(BigInteger n)
        {
            if (n == 0) return BigInteger.Zero;
            if (n > 0)
            {
                int bitLength = GetBitSize(n);
                BigInteger root = BigInteger.One << (bitLength >> 1);
                while (!isSqrt(n, root))
                {
                    root += (n / root);
                    root >>= 1;
                }
                return root;
            }
            return new BigInteger(double.NaN); //throw new ArithmeticException("NaN");
        }
        static bool isPrime(BigInteger n)
        {
            BigInteger mx = Sqrt(n);
            for (BigInteger i = 2; i <= mx; i++)
            {
                if (BigInteger.Remainder(n, i) == BigInteger.Zero) return false;
            }
            return true;
        }
        public static BigInteger nextPrime(BigInteger n)
        {
            if (n == 2) return 3;
            do
            {
                n += 2;
            } while (!isPrime(n));
            return n;
        }
        static int[] getPrimes(int n) //sieve of Eratosthenes
        {
            bool[] A = new bool[n - 2 + 1];
            int mx = (int)Sqrt(new BigInteger(n));
            for (int i = 2; i <= mx; i++)
            {
                if (!A[i - 2])
                {
                    for (int j = i * i; j <= n; j += i)
                    {
                        A[j - 2] = true;
                    }
                }
            }
            return A.Select((b, i) => !b ? i + 2 : -1).Where((i) => i != -1).ToArray();
        }
        static List<BigInteger[]> getDivPolys(List<BigInteger[]> curDivPolys, BigInteger l, int Ea, int Eb, BigInteger[] f, BigInteger GF)
        {
            BigInteger[] ysub = mulPolyRing(new BigInteger[] { 2 }, f, GF);
            //BigInteger[] ysquared = mulPolyRing(ysub, ysub, GF);
            BigInteger[] b6sqr = mulPolyRing(new BigInteger[] { new BigInteger(2 * 2) }, mulPolyRing(ysub, ysub, GF), GF);
            //BigInteger b6sqrinv = modInverse(2 * 2 * y * y * 2 * 2 * y * y, GF); //(4y^2)^2
            List<BigInteger[]> divPolys = curDivPolys == null ? new List<BigInteger[]>(new BigInteger[][] {
                new BigInteger[] { BigInteger.Zero },
                new BigInteger[] { BigInteger.One },
                mulPolyRing(new BigInteger[] { 2 }, ysub, GF),
                new BigInteger[] { 3, 0, 6 * Ea, 12 * Eb, -new BigInteger(Ea) * Ea}, //-new BigInteger(Ea) * Ea, 12 * Eb, 6 * Ea, 0, 3
                mulPolyRing(mulPolyRing(new BigInteger[] { 4 }, ysub, GF), new BigInteger[] { 1, 0, 5 * Ea, 20 * Eb, -5 * new BigInteger(Ea) * Ea, -4 * new BigInteger(Ea) * Eb, -8 * new BigInteger(Eb) * Eb - new BigInteger(Ea) * Ea * Ea }, GF) //-8 * new BigInteger(Eb) * Eb - new BigInteger(Ea) * Ea * Ea, -4 * new BigInteger(Ea) * Eb, -5 * new BigInteger(Ea) * Ea, 20 * Eb, 5 * Ea, 0, 1
                }) : curDivPolys;
            while (divPolys.Count <= l)
            {
                int m = divPolys.Count / 2; //m >= 2
                                            //even ones in odd psis need adjustment by b6^2=(2*y)^2=4y^2
                if ((m & 1) == 0)
                {
                    divPolys.Add(addPolyRing(divmodPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m], GF), divPolys[m], GF), divPolys[m], GF), b6sqr, GF).Item1, mulPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 1], divPolys[m + 1], GF), divPolys[m + 1], GF), divPolys[m + 1], GF), new BigInteger[] { -1 }, GF), GF));
                }
                else
                {
                    divPolys.Add(addPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m], GF), divPolys[m], GF), divPolys[m], GF), mulPolyRing(divmodPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 1], divPolys[m + 1], GF), divPolys[m + 1], GF), divPolys[m + 1], GF), b6sqr, GF).Item1, new BigInteger[] { -1 }, GF), GF));
                }
                //divPolys.Add(addPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m], GF), divPolys[m], GF), divPolys[m], GF), mulPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 1], divPolys[m + 1], GF), divPolys[m + 1], GF), divPolys[m + 1], GF), new BigInteger[] { -1 }, GF), GF));
                m++; //m >= 3
                divPolys.Add(divmodPolyRing(mulPolyRing(divPolys[m], addPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m - 1], GF), divPolys[m - 1], GF), mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 2], divPolys[m + 1], GF), divPolys[m + 1], GF), new BigInteger[] { -1 }, GF), GF), GF), mulPolyRing(new BigInteger[] { 2 }, ysub, GF), GF).Item1);
            }
            return divPolys;
        }
        static BigInteger getSchoofRemainder(int Ea, int Eb, BigInteger GF, RNGCryptoServiceProvider rng, int l, List<BigInteger[]> divPolys, BigInteger[] f)
        {
            divPolys = getDivPolys(divPolys, l * 2, Ea, Eb, f, GF); //l * 2 required for fast variant of point multiplication algorithm
            BigInteger tl = BigInteger.Zero;
            BigInteger[] divpoly = divPolys[l]; //even ones need to be divided by 2*y
            if (l == 2)
            {
                SortedList<BigInteger, BigInteger> xp = new SortedList<BigInteger, BigInteger>();
                xp.Add(GF, 1); //gcd should return 1
                BigInteger[] gcdres = addPolyRing(gcdPolyRing(remainderPolyRingSparsePow2(xp, f, GF), f, GF), mulPolyRing(new BigInteger[] { 1, 0 }, new BigInteger[] { -1 }, GF), GF);
                if (gcdres.Length == 1 && gcdres[0] == BigInteger.One) tl = 1;
            }
            else
            {
                BigInteger pl = posRemainder(GF, l);
                if (pl >= l / 2) pl -= l;
                //SortedList<BigInteger, BigInteger> xp = new SortedList<BigInteger, BigInteger>();
                //xp.Add(GF, 1);
                do
                {
                    //remainderPolyRingSparse(xp, divpoly, GF);
                    //divmodPolyRingSparse(xp, divpoly, GF);
                    //BigInteger[] modinv = modInversePolyRing(new BigInteger[] { BigInteger.One, BigInteger.Zero }, divpoly, GF);
                    //divmodPolyRing(mulPolyRing(modinv, new BigInteger[] { BigInteger.One, BigInteger.Zero }, GF), divpoly, GF).Item2;
                    //BigInteger[] xprem = remainderPolyRingSparsePow2(xp, divpoly, GF);
                    BigInteger[] xprem = modexpPolyRing(new BigInteger[] { BigInteger.One, BigInteger.Zero }, GF, divpoly, GF);
                    BigInteger[] yprem = modexpPolyRing(f, (GF - 1) / 2, divpoly, GF);
                    //correct method of squaring is to substitute x value of prior fields into x, y of itself with the y multiplied by the original y
                    //BigInteger[] xpsquared = divmodPolyRing(substitutePolyRing(xprem, xprem, divpoly, GF), divpoly, GF).Item2;
                    BigInteger[] xpsquared = modexpPolyRing(xprem, GF, divpoly, GF);
                    //BigInteger[] ypsquared = divmodPolyRing(mulPolyRing(substitutePolyRing(yprem, xprem, divpoly, GF), yprem, GF), divpoly, GF).Item2;
                    //ypsquared calculation can be delayed by computing the x' of S using alternate equation and then computing it only if needed
                    //BigInteger[] ypsquared = modexpPolyRing(mulPolyRing(substitutePolyRing(f, xprem, divpoly, GF), f, GF), (GF - 1) / 2, divpoly, GF);
                    BigInteger[] ypsquared = modexpPolyRing(yprem, GF + 1, divpoly, GF);
                    //using identity element with x and y as 1 but this will not suffice in comparisons with x^p or x^p^2
                    Tuple<BigInteger[], BigInteger[]> Q = scaleECPolyRing(new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.One, BigInteger.Zero }, new BigInteger[] { BigInteger.One }), BigInteger.Abs(pl), Ea, GF, divpoly, f);
                    //use identity element since factoring y out of this and making it a function r(x) * y which means r(x)==1 for simple (x, y)
                    //Tuple<BigInteger[], BigInteger[]> Q = scaleECPolyRing(new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.One, BigInteger.Zero }, f), BigInteger.Abs(pl), Ea, GF, divpoly, f);
                    //Q = scaleECDivPoly(new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.One, BigInteger.Zero }, new BigInteger[] { BigInteger.One }), BigInteger.Abs(pl), GF, divPolys, divpoly, f);
                    //if (!Q.Item1.SequenceEqual(qalt.Item1)) throw new ArgumentException();
                    //if (!Q.Item2.SequenceEqual(qalt.Item2)) throw new ArgumentException();
                    BigInteger m = BigInteger.One;
                    if (Q.Item1 != null)
                    {
                        if (pl < BigInteger.Zero) Q = new Tuple<BigInteger[], BigInteger[]>(Q.Item1, mulPolyRing(Q.Item2, new BigInteger[] { BigInteger.MinusOne }, GF));
                        //if (!Q.Item1.SequenceEqual(xpsquared) || !Q.Item2.SequenceEqual(ypsquared)) {
                        Tuple<BigInteger[], BigInteger[]> S = addECPolyRing(new Tuple<BigInteger[], BigInteger[]>(xpsquared, ypsquared), Q, Ea, GF, divpoly, f);
                        if (S.Item1 == null) Q = S; //also can check xpsquared == Q.Item1
                        else if (!S.Item1.SequenceEqual(new BigInteger[] { BigInteger.Zero }) || !S.Item2.SequenceEqual(new BigInteger[] { BigInteger.One }))
                        { //redundant with last check
                            BigInteger[] modinv = modInversePolyRing(addPolyRing(xpsquared, mulPolyRing(Q.Item1, new BigInteger[] { -1 }, GF), GF), divpoly, GF);
                            if (modinv != null)
                            { //xpsquared != qalt.Item1
                                BigInteger[] diffsqr = divmodPolyRing(mulPolyRing(addPolyRing(ypsquared, mulPolyRing(Q.Item2, new BigInteger[] { -1 }, GF), GF),
                                    modinv, GF), divpoly, GF).Item2;
                                BigInteger[] xprime = addPolyRing(addPolyRing(divmodPolyRing(mulPolyRing(mulPolyRing(diffsqr, diffsqr, GF), f, GF), divpoly, GF).Item2,
                                    mulPolyRing(xpsquared, new BigInteger[] { -1 }, GF), GF), mulPolyRing(Q.Item1, new BigInteger[] { -1 }, GF), GF); //need to remember to multiply by y^2
                                if (!xprime.SequenceEqual(S.Item1)) throw new ArgumentException();
                                //xprime + yprime/lambda = xpsquared - ypsquared/lambda, or yprime = xpsquared*lambda - ypsquared - xprime*lambda
                                //lambda=(ypsquared-ypl)/(xpsquared-xpl)
                                BigInteger[] yprime = addPolyRing(divmodPolyRing(mulPolyRing(addPolyRing(xpsquared, mulPolyRing(xprime, new BigInteger[] { -1 }, GF), GF), diffsqr, GF), divpoly, GF).Item2, mulPolyRing(ypsquared, new BigInteger[] { -1 }, GF), GF);
                                if (!yprime.SequenceEqual(S.Item2)) throw new ArgumentException();
                            }
                            //limited by 1 in y, and (l^2 - 3) / 2 in x
                            Tuple<BigInteger[], BigInteger[]> P = new Tuple<BigInteger[], BigInteger[]>(xprem, yprem);
                            for (; m <= (l - 1) / 2; m++)
                            {
                                if (addPolyRing(S.Item1, mulPolyRing(P.Item1, new BigInteger[] { -1 }, GF), GF).Length == 0)
                                {
                                    tl = addPolyRing(S.Item2, mulPolyRing(P.Item2, new BigInteger[] { -1 }, GF), GF).Length == 0 ? m : l - m;
                                    break;
                                }
                                if (m == (l - 1) / 2) break;
                                //P = scaleECDivPoly(new Tuple<BigInteger[], BigInteger[]>(xprem, yprem), m + 1, GF, divPolys, divpoly, f);
                                P = addECPolyRing(P, new Tuple<BigInteger[], BigInteger[]>(xprem, yprem), Ea, GF, divpoly, f);
                                //if (!P.Item1.SequenceEqual(palt.Item1)) throw new ArgumentException();
                                //if (!P.Item2.SequenceEqual(palt.Item2)) throw new ArgumentException();
                                if (P.Item1 == null) { Q = P; break; }
                            }
                        } //else tl = 0;
                    } //else m = (l - 1) / 2;
                    if (Q.Item1 == null) divpoly = gcdPolyRing(divpoly, Q.Item2, GF);
                    else break;
                    if (Q.Item1 == null || m > (l - 1) / 2)
                    { //one thing to do here is factor the division polynomial since we have hit a root in the point arithmetic
                      //quadratic non-residue of x^2 === GF (mod l) === pl
                      //since l is prime, do not need to deal with composite or prime power cases
                      //instead of Tonelli-Shanks, can show non-residue by excluding 1 root (GF === 0 (mod l)), and 2 roots (gcd(GF, l) == 1) and is residue
                      //but easier to just use Legendre symbol is -1 and prove non-residue = GF ^ ((l - 1) / 2) (mod l)
                      //if (BigInteger.ModPow(GF, (l - 1) / 2, l) == -1) tl = 0;
                      //if (pl != BigInteger.Zero && BigInteger.GreatestCommonDivisor(GF, l) != BigInteger.One) tl = 0;
                        int w = (int)TonelliShanks(rng, posRemainder(GF, l), l); //since we need result anyway might as well compute unless non-residue very common and much faster other methods
                        if (w == BigInteger.Zero) tl = 0; //no square root, or one square root if posRemainder(GF, l) == 0 but zero either way...
                        else
                        {
                            //posRemainder(GF, l) != 0 //so there are 2 square roots
                            //w = l - w; //l - w is also square root //both roots should give same result though
                            //Tuple<BigInteger[], BigInteger[]> xyw = scaleECPolyRing(new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.One, BigInteger.Zero }, new BigInteger[] { BigInteger.One }), w, Ea, GF, divpoly, f);
                            Tuple<BigInteger[], BigInteger[]> xyw = scaleECDivPoly(new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.One, BigInteger.Zero }, new BigInteger[] { BigInteger.One }), w, GF, divPolys, divpoly, f);
                            //if (!xprem.SequenceEqual(xyw.Item1))
                            if (!gcdPolyRing(addPolyRing(xprem, xyw.Item1, GF), divpoly, GF).SequenceEqual(new BigInteger[] { BigInteger.One })) { tl = BigInteger.Zero; }
                            //else { tl = posRemainder((yprem.SequenceEqual(xyw.Item2) ? 2 : -2) * w, l); }
                            else { tl = posRemainder((gcdPolyRing(addPolyRing(yprem, xyw.Item2, GF), divpoly, GF).SequenceEqual(new BigInteger[] { BigInteger.One }) ? 2 : -2) * w, l); }
                        }
                        break; //no need to continue using reduced polynomial since this method is certainly better and faster
                    }
                } while (true);
            }
            return tl;
        }
        //https://en.wikipedia.org/wiki/Schoof%27s_algorithm
        public static BigInteger Schoof(int Ea, int Eb, BigInteger GF, RNGCryptoServiceProvider rng, BigInteger ExpectedBase)
        {
            BigInteger realT = GF + 1 - ExpectedBase;
            //BigInteger sqrtp = TonelliShanks(rng, GF, GF);
            BigInteger sqrtGF = Sqrt(16 * GF);
            BigInteger sqrtp4 = sqrtGF + (sqrtGF * sqrtGF < 16 * GF ? 1 : 0); //64-bit square root, can bump this up by one if less than lower bound if that is needed
            //getPrimes(1024);
            int l = 2;
            BigInteger prodS = BigInteger.One;
            //https://en.wikipedia.org/wiki/Division_polynomials
            //y=2*y^2 where y^2=x^3+ax+b
            //BigInteger ysub = 2 * (x * x * x + Ea * x + Eb);
            BigInteger[] f = new BigInteger[] { 1, 0, Ea, Eb }; //Eb, Ea, 0, 1
            List<BigInteger[]> divPolys = null;
            List<Tuple<BigInteger, BigInteger>> ts = new List<Tuple<BigInteger, BigInteger>>();
            BigInteger t = BigInteger.Zero;
            while (prodS < sqrtp4)
            { //log2(GF) primes required on average
                BigInteger tl = getSchoofRemainder(Ea, Eb, GF, rng, l, divPolys, f);
                Console.WriteLine(l + " " + tl + " " + posRemainder(realT, l));
                //posRemainder(realT, l) == tl;
                ts.Add(new Tuple<BigInteger, BigInteger>(tl, l));
                BigInteger a = prodS * modInverse(prodS, l);
                BigInteger b = l * modInverse(l, prodS);
                prodS *= l;
                t = posRemainder(a * tl + b * t, prodS);
                l = (int)nextPrime(l);
            }
            //GetBitSize(GF) == int(Math.Ceiling(BigInteger.Log(GF, 2))); //128-bit field
            //BigInteger t = BigInteger.Zero;
            //chinese remainder theorem (CRT) on ts while |t| < 2*Sqrt(GF)
            if (t > Sqrt(4 * GF))
                t -= prodS;
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
            while (c < psN)
            {
                if (even)
                {
                    c += ce + 1;
                    ce += 2;
                    while (res.Count() < c) res.Add(BigInteger.Zero);
                    res.Add(one);
                }
                else
                {
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
            return clen == 0 || c[0] != BigInteger.Zero ? c : c.SkipWhile((BigInteger cr) => cr == BigInteger.Zero).ToArray(); ;
        }
        static BigInteger[] mulPoly(BigInteger[] A, BigInteger[] B)
        {
            int alen = A.Length, blen = B.Length;
            if (alen == 0) return A; if (blen == 0) return B;
            BigInteger[] p = new BigInteger[alen + blen - 1];
            for (int i = 0; i < blen; i++)
            {
                if (B[i] == BigInteger.Zero) continue;
                for (int j = 0; j < alen; j++)
                {
                    if (A[j] == BigInteger.Zero) continue;
                    int ijoffs = i + j;
                    p[ijoffs] += A[j] * B[i];
                }
            }
            return p.Length == 0 || p[0] != BigInteger.Zero ? p : p.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray();
        }
        static BigInteger[] mulPolyPow(BigInteger[] A, BigInteger[] B, int psN)
        {
            int alen = A.Length, blen = B.Length;
            if (alen == 0) return A; if (blen == 0) return B;
            BigInteger[] p = new BigInteger[alen + blen - 1];
            for (int i = 0; i < blen; i++)
            {
                if (B[i] == BigInteger.Zero) continue;
                for (int j = Math.Max(0, p.Length - psN - i - 1); j < alen; j++) //p.Length - (j + i) > psN, p.Length - psN - i > j
                {
                    if (A[j] == BigInteger.Zero) continue;
                    int ijoffs = i + j;
                    p[ijoffs] += A[j] * B[i];
                }
            }
            return p.Length == 0 || p[0] != BigInteger.Zero ? p : p.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray();
        }
        static BigInteger[] modexpPoly(BigInteger[] X, BigInteger m)
        {
            BigInteger[] d = { BigInteger.One };
            int bs = GetBitSize(m);
            for (int i = bs; i > 0; i--)
            {
                if (((BigInteger.One << (bs - i)) & m) != 0)
                {
                    d = mulPoly(d, X);
                }
                X = mulPoly(X, X);
            }
            return d;
        }
        static BigInteger[] modexpPolyPow(BigInteger[] X, BigInteger m, int psN)
        {
            BigInteger[] d = { BigInteger.One };
            int bs = GetBitSize(m);
            for (int i = bs; i > 0; i--)
            {
                if (((BigInteger.One << (bs - i)) & m) != 0)
                {
                    d = reducePoly(mulPoly(d, X), 0, psN).Item2;
                }
                X = reducePoly(mulPoly(X, X), 0, psN).Item2;
            }
            return d;
        }
        static BigInteger[] substPowerPoly(BigInteger[] X, int m)
        {
            if (X.Length == 0) return X;
            BigInteger[] p = new BigInteger[(X.Length - 1) * m + 1];
            for (int i = 0; i < X.Length; i++) p[i * m] = X[i];
            return p;
        }
        static Tuple<BigInteger[], BigInteger[]> divmodPoly(BigInteger[] A, BigInteger[] B)
        {
            //if (B.Length == 0) throw;
            //if B is not monic, this poses a problem - rational numbers might work, Sage seems to use matrix system to solve modInversePoly
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
            return new Tuple<BigInteger[], BigInteger[]>(q.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray(), r);
        }
        static BigInteger[,] gaussianElimZZ(BigInteger[,] x)
        {
            int h = 0; //Initialization of pivot row
            int k = 0; //Initialization of pivot column
            int m = x.GetLength(0);
            int n = x.GetLength(1);
            BigInteger[,] vect = new BigInteger[1, n];
            while (h < m && k < n)
            {
                //Find the k-th pivot
                Tuple<BigInteger, int>[] res = Enumerable.Range(h, m - h + 1 - 1).Where((int i) => x[i, k] != BigInteger.Zero).Select((int i) => new Tuple<BigInteger, int>(BigInteger.Abs(x[i, k]), i)).ToArray();
                int i_max = res.Length == 0 ? -1 : res.Min().Item2; //index of maximum which is first one with a bit set, also should consider absolute value but here its not applicable since no negative values though zero still possible
                if (i_max < h || x[i_max, k] == BigInteger.Zero) //No pivot in this column, pass to next column
                    k++;
                else
                {
                    //swap rows h and i_max
                    if (h != i_max)
                    {
                        Array.Copy(x, i_max * n, vect, 0, n);
                        Array.Copy(x, h * n, x, i_max * n, n);
                        Array.Copy(vect, 0, x, h * n, n);
                    }
                    //Do for all rows below pivot
                    //for (int i = h + 1; i < m; i++) {
                    //reduced row echelon form (RREF) is obtained without a back substitution step by starting from 0 and skipping h
                    for (int i = 0; i < m; i++)
                    {
                        if (h == i) continue;
                        BigInteger f = x[i, k] / x[h, k];
                        x[i, k] = BigInteger.Zero;
                        //Do for all remaining elements in current row
                        for (int j = k + 1; j < n; j++)
                        {
                            x[i, j] -= (x[h, j] * f);
                        }
                    }
                    h++; k++; //Increase pivot row and column
                }
            }
            return x; //ret;
        }
        //Extended Euclid GCD of 1
        static BigInteger[] modInversePoly(BigInteger[] a, BigInteger[] n)
        {
            //https://github.com/sagemath/sage/blob/master/src/sage/rings/polynomial/polynomial_element.pyx
            //use matrix to solve this as linear system since there can be non-monic polynomials or intermediate ones
            //Gaussian elimination row reduction to solve
            /*
             [a[2] 0 0 0 0] = 1
             [a[1] a[2] 0 0 0] = 0
             [a[0] a[1] a[2] 0 0] = 0
             [0 a[0] a[1] b[3]  0] = 0
             [0 0 a[0] 0  b[3]] = 0
             M=matrix(ZZ,[[1,0,0,0,0,1],[-24,1,0,0,0,0],[252,-24,1,0,0,0],[0,252,-24,1,0,0],[0,0,252,0,1,0]])
             M.echelon_form() # last column 1, 24, 324, 1728, -81648
             */
            //if we have a power series here, we want the result also to be in coefficients of the same power series, and hence
            //the matrix equations can be reduced by this to eliminate all the known 0 coefficients
            //otherwise this is way too computationally complex
            //cannot necessarily deduce this as 0 coefficients could be in any positions and best it could guess by the smallest gap which might not be correct
            //powers = a.Select((val, i) => new Tuple<BigInteger, int>(val, a.Length - 1 - i)).Where((val) => val.Item1 != BigInteger.Zero);


            BigInteger[,] M = new BigInteger[(n.Length - 1) * 2 - 1, (n.Length - 1) * 2];
            for (int i = 0; i < n.Length - 1; i++)
            {
                for (int j = 0; j < n.Length - 1; j++)
                {
                    M[i + j, j] = i <= a.Length - 1 ? a[a.Length - 1 - i] : BigInteger.Zero;
                }
            }
            for (int i = 0; i < n.Length; i++)
            {
                for (int j = 0; j < n.Length - 1 - 1; j++)
                {
                    M[i + j, j + n.Length - 1] = n[n.Length - 1 - i];
                }
            }
            M[0, M.GetLength(1) - 1] = BigInteger.One;
            M = gaussianElimZZ(M);
            BigInteger[] v = new BigInteger[n.Length - 1]; //no solution likely means identity matrix not seen - should check that case
            for (int i = 0; i < n.Length - 1; i++)
            {
                v[v.Length - 1 - i] = M[i, M.GetLength(1) - 1];
            }
            /*BigInteger[] i = n, v = new BigInteger[] { BigInteger.Zero }, d = new BigInteger[] { BigInteger.One };
            while (a.Length > 0)
            {
                BigInteger[] t = divmodPoly(i, a).Item1, x = a;
                a = divmodPoly(i, x).Item2;
                i = x;
                x = d;
                d = addPoly(v, mulPoly(mulPoly(t, x), new BigInteger[] { -1 }));
                v = x;
            }
            if (i.Length > 1) return null; //no modular inverse exists if degree more than 0...
            //v = mulPoly(new BigInteger[] { modInverse(i[0], GF) }, v);
            v = divmodPoly(v, n).Item2;
            //if (v < 0) v = (v + n) % n;*/
            return v.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray();
        }
        static BigInteger[] modInversePolyPow(BigInteger[] a, BigInteger[] n, int pow)
        {
            int powlen = (n.Length - 1) / pow + (((n.Length - 1) % pow) != 0 ? 1 : 0);
            BigInteger[,] M = new BigInteger[powlen * 2 - 1, powlen * 2];
            for (int i = 0; i < powlen; i++)
            {
                for (int j = 0; j < powlen; j++)
                {
                    M[i + j, j] = i * pow <= a.Length - 1 ? a[a.Length - 1 - i * pow] : BigInteger.Zero;
                }
            }
            for (int i = powlen; i < powlen + 1; i++)
            { //this will only work for x^n field
                for (int j = 0; j < powlen - 1; j++)
                {
                    M[i + j, j + powlen] = n[0];
                }
            }
            M[0, M.GetLength(1) - 1] = BigInteger.One;
            M = gaussianElimZZ(M);
            BigInteger[] v = new BigInteger[n.Length - 1]; //no solution likely means identity matrix not seen - should check that case
            for (int i = 0; i < powlen; i++)
            {
                v[v.Length - 1 - i * pow] = M[i, M.GetLength(1) - 1];
            }
            //if (!modInversePoly(a, n).SequenceEqual(v.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray())) {
            //    throw new ArgumentException();
            //}
            return v.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray();
        }
        static Tuple<int, BigInteger[]> reducePoly(BigInteger[] a, int offs, int psN)
        {
            if (a.Length == 0) return new Tuple<int, BigInteger[]>(0, a);
            int reduce = Enumerable.Range(0, offs).TakeWhile((val) => a[a.Length - 1 - val] == BigInteger.Zero).Count();
            if (reduce != 0)
            {
                a = a.Take(a.Length - reduce).ToArray();
                offs -= reduce;
            }
            if (a.Length - offs > psN)
            {
                a = a.Skip(a.Length - offs - psN).ToArray(); // mod x^psN
                a = a.SkipWhile((BigInteger cz) => cz == BigInteger.Zero).ToArray();
            }
            return new Tuple<int, BigInteger[]>(offs, a);
        }
        static Tuple<int, BigInteger[]> mulShiftedPoly(BigInteger[] a, int aoffs, BigInteger[] b, int boffs, int psN)
        {
            BigInteger[] c = mulPoly(a, b);
            return reducePoly(c, aoffs + boffs, psN);
        }
        static Tuple<int, BigInteger[]> addShiftedPoly(BigInteger[] a, int aoffs, BigInteger[] b, int boffs, int psN)
        {
            BigInteger[] c;
            if (aoffs < boffs)
            {
                c = addPoly(a.Concat(Enumerable.Repeat(BigInteger.Zero, boffs - aoffs)).ToArray(), b);
            }
            else if (aoffs > boffs)
            {
                c = addPoly(a, b.Concat(Enumerable.Repeat(BigInteger.Zero, aoffs - boffs)).ToArray());
            }
            else c = addPoly(a, b);
            return reducePoly(c, Math.Max(aoffs, boffs), psN);
        }
        static Tuple<int, BigInteger[]> phase(BigInteger[] z, int zf, int l, int psN)
        {
            int k; //degree of polynomial
            if (zf % l == 0) k = zf;
            else
            {
                k = (zf / l) * l;
                if (zf >= 0) k += l;
            }
            int offset = k < 0 ? -k : 0;
            BigInteger[] w = new BigInteger[psN + offset];
            for (; k < psN; k += l)
            {
                if (z.Length - 1 + zf < k) break;
                w[w.Length - 1 - offset - k] = l * z[z.Length - 1 + zf - k];
            }
            return new Tuple<int, BigInteger[]>(offset, w.SkipWhile((BigInteger cz) => cz == BigInteger.Zero).ToArray());
        }
        //https://sage.math.leidenuniv.nl/src/modular/ssmod/ssmod.py
        //https://github.com/miracl/MIRACL/blob/master/source/curve/mueller.cpp
        static List<List<Tuple<BigInteger, int>>> getModularPoly(int l)
        {
            //need mulPoly, divmodPoly, addPoly, modexpPoly since no ring here
            int s;
            for (s = 1; ; s++)
                if (s * (l - 1) % 12 == 0) break; //s is either 1, 2, 3 or 6 from fastest to slowest
            int v = s * (l - 1) / 12;
            int psN = v + 2;
            BigInteger[] divpoly = new BigInteger[psN + 1];
            divpoly[0] = BigInteger.One;
            BigInteger[] x = new BigInteger[] { BigInteger.Zero };
            //calculate Klein=j(tau) from its definition
            //x/(-x+1)==x+1
            //8x^2/(-x^2+1)==8x^2
            for (int n = 1; n < psN; n++)
            {
                //SortedList<BigInteger, BigInteger> a = new SortedList<BigInteger, BigInteger>();
                //a.Add(n, new BigInteger(n * n * n)); //a=n^3*x^n
                //SortedList<BigInteger, BigInteger> b = new SortedList<BigInteger, BigInteger>();
                //b.Add(0, 1);
                //b.Add(n, -1);
                BigInteger[] a = new BigInteger[n + 1];
                a[0] = new BigInteger(n * n * n); //a=n^3*x^n
                BigInteger[] b = new BigInteger[n + 1];
                b[0] = -1;
                b[n] = 1;
                BigInteger[] t = mulShiftedPoly(a, 0, modInversePolyPow(b, divpoly, n), 0, psN).Item2;
                x = addPoly(x, t);
            }
            x = mulPoly(x, new BigInteger[] { 240 });
            x[x.Length - 1] += BigInteger.One;
            x = reducePoly(modexpPoly(x, 3), 0, psN).Item2;
            BigInteger[] y = reducePoly(getEta(psN), 0, psN).Item2;
            y = reducePoly(modexpPoly(y, 24), 0, psN).Item2;
            //R.<x> = PolynomialRing(ZZ)
            //inverse_mod(252*x^2-24*x+1, x^3)
            BigInteger[] klein = reducePoly(mulPoly(x, modInversePoly(y, divpoly)), 0, psN).Item2; //new BigInteger[] { 324, 24, 1}
            //klein = divmodPoly(klein, new BigInteger[] {BigInteger.One, BigInteger.Zero}).Item1; // divide by x
            int kleindiv = 1; //divide by x but since negative powers just store this denominator
            psN *= l;
            divpoly = new BigInteger[psN + 1];
            divpoly[0] = BigInteger.One;
            klein = substPowerPoly(klein, l); // divmodPoly(substPowerPoly(klein, l), divpoly).Item2;
            kleindiv *= l;
            BigInteger[] z = reducePoly(getEta(psN), 0, psN).Item2;
            y = reducePoly(substPowerPoly(z, l), 0, psN).Item2;
            z = reducePoly(mulPoly(z, modInversePolyPow(y, divpoly, l)), 0, psN).Item2; //y = 1 / y; z *= y;
            BigInteger[] flt = reducePoly(modexpPolyPow(z, 2 * s, psN), 0, psN).Item2;
            //BigInteger[] xv = new BigInteger[v + 1];
            //xv[0] = 1;
            //flt = divmodPoly(flt, xv).Item1; // multiply by x^-v
            int fltdiv = v;
            BigInteger w = BigInteger.Pow(l, s);
            y = reducePoly(substPowerPoly(flt, l), 0, psN).Item2;
            int ydiv = fltdiv * l;
            BigInteger[] yinvw = new BigInteger[ydiv + 1];
            yinvw[0] = w;
            BigInteger[] zlt = reducePoly(mulPoly(yinvw, modInversePolyPow(y, divpoly, l)), 0, psN).Item2;
            // Calculate Power Sums
            z = new BigInteger[] { 1 };
            BigInteger[] f = new BigInteger[] { 1 };
            int fdiv = 0;
            BigInteger[][] ps = new BigInteger[l + 1 + 1][];
            int[] psdiv = new int[l + 1 + 1];
            ps[0] = new BigInteger[] { l + 1 };
            for (int i = 1; i <= l + 1; i++)
            {
                f = reducePoly(mulPolyPow(f, flt, psN), 0, psN).Item2;
                fdiv += fltdiv;
                z = reducePoly(mulPoly(z, zlt), 0, psN).Item2;
                Tuple<int, BigInteger[]> pswithdiv = phase(f, -fdiv, l, psN);
                pswithdiv = addShiftedPoly(pswithdiv.Item2, pswithdiv.Item1, z, 0, psN);
                ps[i] = pswithdiv.Item2;
                psdiv[i] = pswithdiv.Item1;
            }
            BigInteger[][] c = new BigInteger[l + 1 + 1][];
            int[] cdiv = new int[l + 1 + 1];
            c[0] = new BigInteger[] { BigInteger.One };
            for (int i = 1; i <= l + 1; i++)
            {
                c[i] = new BigInteger[] { BigInteger.Zero };
                for (int j = 1; j <= i; j++)
                {
                    Tuple<int, BigInteger[]> res = mulShiftedPoly(ps[j], psdiv[j], c[i - j], cdiv[i - j], psN);
                    res = addShiftedPoly(c[i], cdiv[i], res.Item2, res.Item1, psN);
                    c[i] = res.Item2;
                    cdiv[i] = res.Item1;
                }
                //c[i] = divmodPoly(mulPoly(c[i], new BigInteger[] { -1 }), new BigInteger[] { i }).Item1;
                c[i] = mulPoly(c[i], new BigInteger[] { -1 }).Select((BigInteger val) => val / i).ToArray();
            }
            BigInteger[][] jlt = new BigInteger[v + 1][];
            int[] jltdiv = new int[v + 1];
            jlt[0] = new BigInteger[] { BigInteger.One };
            jlt[1] = klein;
            jltdiv[1] = kleindiv;
            for (int i = 2; i <= v; i++)
            {
                Tuple<int, BigInteger[]> res = mulShiftedPoly(jlt[i - 1], jltdiv[i - 1], klein, kleindiv, psN);
                jlt[i] = res.Item2;
                jltdiv[i] = res.Item1;
            }
            //x^(l+1) is first term
            List<List<Tuple<BigInteger, int>>> coeffs = new List<List<Tuple<BigInteger, int>>>();
            //Console.Write("X^" + (l + 1));
            coeffs.Add(new List<Tuple<BigInteger, int>>(new Tuple<BigInteger, int>[] { new Tuple<BigInteger, int>(BigInteger.One, 0) }));
            for (int i = 1; i <= l + 1; i++)
            {
                z = c[i];
                int zdiv = cdiv[i];
                BigInteger cf;
                List<Tuple<BigInteger, int>> yvals = new List<Tuple<BigInteger, int>>();
                //Console.Write("+(");
                while (zdiv != 0)
                {
                    int j = zdiv / l;
                    cf = z[z.Length - 1];
                    Tuple<int, BigInteger[]> res = addShiftedPoly(z, zdiv, mulPoly(jlt[j], new BigInteger[] { -cf }), jltdiv[j], psN);
                    z = res.Item2;
                    zdiv = res.Item1;
                    //Console.Write("+" + cf + "*Y^" + j);
                    yvals.Add(new Tuple<BigInteger, int>(cf, j));
                    //(cf*Y^j;
                }
                cf = z[z.Length - 1];
                //+cf)*X^(l+1-i)
                //Console.Write(" + " + cf + ")*X^" + (l + 1 - i));
                yvals.Add(new Tuple<BigInteger, int>(cf, 0));
                coeffs.Add(yvals);
                if (l <= z.Length - 1 && z[z.Length - 1 - l] != BigInteger.Zero) throw new ArgumentException();
            }
            return coeffs; //coeff x^ y^ 
        }
        static Tuple<int, BigInteger[]> mulShiftedPolyRing(BigInteger[] a, int aoffs, BigInteger[] b, int boffs, int psN, BigInteger GF)
        {
            BigInteger[] c = mulPolyRing(a, b, GF);
            return reducePoly(c, aoffs + boffs, psN);
        }
        static Tuple<int, BigInteger[]> addShiftedPolyRing(BigInteger[] a, int aoffs, BigInteger[] b, int boffs, int psN, BigInteger GF)
        {
            BigInteger[] c;
            if (aoffs < boffs)
            {
                c = addPolyRing(a.Concat(Enumerable.Repeat(BigInteger.Zero, boffs - aoffs)).ToArray(), b, GF);
            }
            else if (aoffs > boffs)
            {
                c = addPolyRing(a, b.Concat(Enumerable.Repeat(BigInteger.Zero, aoffs - boffs)).ToArray(), GF);
            }
            else c = addPolyRing(a, b, GF);
            return reducePoly(c, Math.Max(aoffs, boffs), psN);
        }
        static BigInteger[] mulPolyRingPow(BigInteger[] A, BigInteger[] B, int psN, BigInteger GF)
        {
            int alen = A.Length, blen = B.Length;
            if (alen == 0) return A; if (blen == 0) return B;
            BigInteger[] p = new BigInteger[alen + blen - 1];
            for (int i = 0; i < blen; i++)
            {
                if (B[i] == BigInteger.Zero) continue;
                for (int j = Math.Max(0, p.Length - psN - i - 1); j < alen; j++)
                {
                    if (A[j] == BigInteger.Zero) continue;
                    int ijoffs = i + j;
                    if (B[i] == -1) p[ijoffs] += (GF - A[j]);
                    else if (A[j] == -1) p[ijoffs] += (GF - B[i]);
                    else p[ijoffs] += A[j] * B[i];
                }
            }
            return p.SkipWhile((BigInteger c) => c == BigInteger.Zero).Select((x) => posRemainder(x, GF)).ToArray();
        }
        static List<List<Tuple<BigInteger, int>>> getModularPolyGF(int l, BigInteger GF)
        {
            //need mulPoly, divmodPoly, addPoly, modexpPoly since no ring here
            int s;
            for (s = 1; ; s++)
                if (s * (l - 1) % 12 == 0) break; //s is either 1, 2, 3 or 6 from fastest to slowest
            int v = s * (l - 1) / 12;
            int psN = v + 2;
            BigInteger[] divpoly = new BigInteger[psN + 1];
            divpoly[0] = BigInteger.One;
            BigInteger[] x = new BigInteger[] { BigInteger.Zero };
            //calculate Klein=j(tau) from its definition
            //x/(-x+1)==x+1
            //8x^2/(-x^2+1)==8x^2
            for (int n = 1; n < psN; n++)
            {
                //SortedList<BigInteger, BigInteger> a = new SortedList<BigInteger, BigInteger>();
                //a.Add(n, new BigInteger(n * n * n)); //a=n^3*x^n
                //SortedList<BigInteger, BigInteger> b = new SortedList<BigInteger, BigInteger>();
                //b.Add(0, 1);
                //b.Add(n, -1);
                BigInteger[] a = new BigInteger[n + 1];
                a[0] = new BigInteger(n * n * n); //a=n^3*x^n
                BigInteger[] b = new BigInteger[n + 1];
                b[0] = -1;
                b[n] = 1;
                BigInteger[] t = mulShiftedPolyRing(a, 0, modInversePolyRing(b, divpoly, GF), 0, psN, GF).Item2;
                x = addPolyRing(x, t, GF);
            }
            x = mulPolyRing(x, new BigInteger[] { 240 }, GF);
            x[x.Length - 1] += BigInteger.One;
            x = modexpPolyRing(x, 3, divpoly, GF);
            BigInteger[] y = reducePoly(getEta(psN), 0, psN).Item2;
            y = modexpPolyRing(y, 24, divpoly, GF);
            //R.<x> = PolynomialRing(ZZ)
            //inverse_mod(252*x^2-24*x+1, x^3)
            BigInteger[] klein = reducePoly(mulPolyRing(x, modInversePolyRing(y, divpoly, GF), GF), 0, psN).Item2; //new BigInteger[] { 324, 24, 1}
            //klein = divmodPoly(klein, new BigInteger[] {BigInteger.One, BigInteger.Zero}).Item1; // divide by x
            int kleindiv = 1; //divide by x but since negative powers just store this denominator
            psN *= l;
            divpoly = new BigInteger[psN + 1];
            divpoly[0] = BigInteger.One;

            klein = substPowerPoly(klein, l); // divmodPoly(substPowerPoly(klein, l), divpoly).Item2;
            kleindiv *= l;
            BigInteger[] z = reducePoly(getEta(psN), 0, psN).Item2;
            y = reducePoly(substPowerPoly(z, l), 0, psN).Item2;
            z = reducePoly(mulPolyRing(z, modInversePolyRing(y, divpoly, GF), GF), 0, psN).Item2; //y = 1 / y; z *= y;
            BigInteger[] flt = modexpPolyRing(z, 2 * s, divpoly, GF);
            //BigInteger[] xv = new BigInteger[v + 1];
            //xv[0] = 1;
            //flt = divmodPoly(flt, xv).Item1; // multiply by x^-v
            int fltdiv = v;
            BigInteger w = BigInteger.Pow(l, s);
            y = reducePoly(substPowerPoly(flt, l), 0, psN).Item2;
            int ydiv = fltdiv * l;
            BigInteger[] yinvw = new BigInteger[ydiv + 1];
            yinvw[0] = w;
            BigInteger[] zlt = reducePoly(mulPolyRing(yinvw, modInversePolyRing(y, divpoly, GF), GF), 0, psN).Item2;
            // Calculate Power Sums
            z = new BigInteger[] { 1 };
            BigInteger[] f = new BigInteger[] { 1 };
            int fdiv = 0;
            BigInteger[][] ps = new BigInteger[l + 1 + 1][];
            int[] psdiv = new int[l + 1 + 1];
            ps[0] = new BigInteger[] { l + 1 };
            for (int i = 1; i <= l + 1; i++)
            {
                f = mulPolyRingPow(f, flt, psN, GF);
                fdiv += fltdiv;
                z = reducePoly(mulPolyRing(z, zlt, GF), 0, psN).Item2;
                Tuple<int, BigInteger[]> pswithdiv = phase(f, -fdiv, l, psN);
                pswithdiv = addShiftedPolyRing(pswithdiv.Item2, pswithdiv.Item1, z, 0, psN, GF);
                ps[i] = pswithdiv.Item2;
                psdiv[i] = pswithdiv.Item1;
            }
            BigInteger[][] c = new BigInteger[l + 1 + 1][];
            int[] cdiv = new int[l + 1 + 1];
            c[0] = new BigInteger[] { BigInteger.One };
            for (int i = 1; i <= l + 1; i++)
            {
                c[i] = new BigInteger[] { BigInteger.Zero };
                for (int j = 1; j <= i; j++)
                {
                    Tuple<int, BigInteger[]> res = mulShiftedPolyRing(ps[j], psdiv[j], c[i - j], cdiv[i - j], psN, GF);
                    res = addShiftedPolyRing(c[i], cdiv[i], res.Item2, res.Item1, psN, GF);
                    c[i] = res.Item2;
                    cdiv[i] = res.Item1;
                }
                //c[i] = divmodPoly(mulPolyRing(c[i], new BigInteger[] { -1 }, GF), new BigInteger[] { i }).Item1;
                //c[i] = mulPolyRing(c[i], new BigInteger[] { -1 }, GF).Select((BigInteger val) => val / i).ToArray();
                c[i] = mulPolyRing(c[i], new BigInteger[] { -1 }, GF).Select((BigInteger val) => posRemainder(val * modInverse(i, GF), GF)).ToArray();
            }
            BigInteger[][] jlt = new BigInteger[v + 1][];
            int[] jltdiv = new int[v + 1];
            jlt[0] = new BigInteger[] { BigInteger.One };
            jlt[1] = klein;
            jltdiv[1] = kleindiv;
            for (int i = 2; i <= v; i++)
            {
                Tuple<int, BigInteger[]> res = mulShiftedPolyRing(jlt[i - 1], jltdiv[i - 1], klein, kleindiv, psN, GF);
                jlt[i] = res.Item2;
                jltdiv[i] = res.Item1;
            }
            //x^(l+1) is first term
            List<List<Tuple<BigInteger, int>>> coeffs = new List<List<Tuple<BigInteger, int>>>();
            //Console.Write("X^" + (l + 1));
            coeffs.Add(new List<Tuple<BigInteger, int>>(new Tuple<BigInteger, int>[] { new Tuple<BigInteger, int>(BigInteger.One, 0) }));
            for (int i = 1; i <= l + 1; i++)
            {
                z = c[i];
                int zdiv = cdiv[i];
                BigInteger cf;
                List<Tuple<BigInteger, int>> yvals = new List<Tuple<BigInteger, int>>();
                //Console.Write("+(");
                while (zdiv != 0)
                {
                    int j = zdiv / l;
                    cf = z[z.Length - 1];
                    Tuple<int, BigInteger[]> res = addShiftedPolyRing(z, zdiv, mulPolyRing(jlt[j], new BigInteger[] { -cf }, GF), jltdiv[j], psN, GF);
                    z = res.Item2;
                    zdiv = res.Item1;
                    //Console.Write("+" + cf + "*Y^" + j);
                    yvals.Add(new Tuple<BigInteger, int>(cf, j));
                    //(cf*Y^j;
                }
                cf = z[z.Length - 1];
                //+cf)*X^(l+1-i)
                //Console.Write(" + " + cf + ")*X^" + (l + 1 - i));
                yvals.Add(new Tuple<BigInteger, int>(cf, 0));
                coeffs.Add(yvals);
                if (l <= z.Length - 1 && z[z.Length - 1 - l] != BigInteger.Zero) throw new ArgumentException();
            }
            return coeffs; //coeff x^ y^ 
        }
        static List<List<Tuple<BigInteger, int>>> diffdx(List<List<Tuple<BigInteger, int>>> modPoly)
        {
            List<List<Tuple<BigInteger, int>>> dx = new List<List<Tuple<BigInteger, int>>>();
            for (int i = 0; i < modPoly.Count() - 1; i++)
            { //last coefficient becomes 0
                dx.Add(modPoly[i].Select((Tuple<BigInteger, int> val) => new Tuple<BigInteger, int>(val.Item1 * (modPoly.Count() - 1 - i), val.Item2)).ToList());
            }
            return dx;
        }
        static List<List<Tuple<BigInteger, int>>> diffdy(List<List<Tuple<BigInteger, int>>> modPoly)
        {
            List<List<Tuple<BigInteger, int>>> dy = new List<List<Tuple<BigInteger, int>>>();
            for (int i = 0; i < modPoly.Count(); i++)
            {
                dy.Add(modPoly[i].Where((Tuple<BigInteger, int> val) => val.Item2 != 0).Select((Tuple<BigInteger, int> val) => new Tuple<BigInteger, int>(val.Item1 * val.Item2, val.Item2 - 1)).ToList());
            }
            return dy.SkipWhile((l) => l.Count == 0).ToList();
        }
        static BigInteger evalDiffEq(List<List<Tuple<BigInteger, int>>> diffeq, BigInteger x, BigInteger y, BigInteger GF)
        {
            BigInteger sum = BigInteger.Zero;
            for (int i = 0; i < diffeq.Count(); i++)
            {
                BigInteger cfsum = BigInteger.Zero;
                for (int j = 0; j < diffeq[i].Count(); j++)
                {
                    if (diffeq[i].Count() - 1 - j == 0)
                        cfsum += diffeq[i][j].Item1;
                    else
                        cfsum += posRemainder(diffeq[i][j].Item1 * BigInteger.ModPow(y, diffeq[i].Count() - 1 - j, GF), GF);
                }
                if (diffeq.Count() - 1 - i == 0)
                    sum += cfsum;
                else
                    sum += posRemainder(cfsum * BigInteger.ModPow(x, diffeq.Count() - 1 - i, GF), GF);
            }
            return posRemainder(sum, GF);
        }
        static BigInteger[] getCk(int terms, BigInteger a, BigInteger b, BigInteger GF)
        {
            int k, h;
            BigInteger[] c = new BigInteger[terms + 1];
            if (terms == 0) return c;
            c[1] = posRemainder(-a * modInverse(5, GF), GF);
            if (terms == 1) return c;
            c[2] = posRemainder(-b * modInverse(7, GF), GF);
            for (k = 3; k <= terms; k++)
            {
                c[k] = 0;
                for (h = 1; h <= k - 2; h++) c[k] += c[h] * c[k - 1 - h];
                c[k] *= (new BigInteger(3) * modInverse(new BigInteger((k - 2) * (2 * k + 3)), GF));
                c[k] = posRemainder(c[k], GF);
            }
            return c;
        }
        static Tuple<BigInteger, BigInteger> mulquad(BigInteger p, BigInteger qnr, BigInteger x, BigInteger y, BigInteger a, BigInteger b)
        {
            return new Tuple<BigInteger, BigInteger>(posRemainder(a * x + b * y * qnr, p), posRemainder(a * y + b * x, p));
        }
        static Tuple<BigInteger, BigInteger> powquad(BigInteger p, BigInteger qnr, BigInteger x, BigInteger y, BigInteger e)
        {
            BigInteger k = e;
            BigInteger a = 1;
            BigInteger b = 0;
            if (k == 0) return new Tuple<BigInteger, BigInteger>(a, b);
            for (; ; )
            {
                if ((k & 1) != 0)
                {
                    Tuple<BigInteger, BigInteger> ret = mulquad(p, qnr, x, y, a, b);
                    a = ret.Item1;
                    b = ret.Item2;
                }
                k >>= 1;
                if (k == 0) return new Tuple<BigInteger, BigInteger>(a, b);
                Tuple<BigInteger, BigInteger> retxy = mulquad(p, qnr, x, y, x, y);
                x = retxy.Item1;
                y = retxy.Item2;
            }

        }
        public static BigInteger SchoofElkiesAtkin(int Ea, int Eb, BigInteger GF, RNGCryptoServiceProvider rng, bool useModPolyGF, BigInteger ExpectedBase)
        {
            BigInteger realT = GF + 1 - ExpectedBase;
            BigInteger delta = -16 * (4 * new BigInteger(Ea) * Ea * Ea + 27 * new BigInteger(Eb) * Eb);
            //4A^3+27B^2 == 0 is not allowed or j-invariant with 0 or 1728
            BigInteger j_invariant = posRemainder((-1728 * 4 * 4 * 4 * new BigInteger(Ea) * Ea * Ea) * modInverse(delta, GF), GF);
            BigInteger sqrtGF = Sqrt(16 * GF);
            BigInteger sqrtp4 = sqrtGF + (sqrtGF * sqrtGF < 16 * GF ? 1 : 0); //64-bit square root, can bump this up by one if less than lower bound if that is needed
            //getPrimes(1024);
            BigInteger M = BigInteger.One; int l = 2;
            BigInteger prodS = BigInteger.One;
            BigInteger prodA = BigInteger.One;
            BigInteger[] f = new BigInteger[] { 1, 0, Ea, Eb }; //Eb, Ea, 0, 1
            //modular polynomials are needed first
            //https://github.com/miracl/MIRACL/blob/master/source/curve/mueller.cpp
            List<Tuple<List<BigInteger>, BigInteger>> Ap = new List<Tuple<List<BigInteger>, BigInteger>>();
            //List<Tuple<BigInteger, BigInteger>> Ep = new List<Tuple<BigInteger, BigInteger>>();
            BigInteger t = BigInteger.Zero;
            List<BigInteger[]> divPolys = null;
            //https://github.com/miracl/MIRACL/blob/master/source/curve/sea.cpp
            //while (prodS <= (sqrtp4 >> 24)) { //log2(GF) primes required on average
            while (prodA * prodS <= sqrtp4)
            {
                BigInteger tl = BigInteger.Zero;
                if (l <= 9) tl = getSchoofRemainder(Ea, Eb, GF, rng, l, divPolys, f);
                else
                {
                    List<List<Tuple<BigInteger, int>>> modPoly;
                    if (!useModPolyGF) {
                        modPoly = getModularPoly(l);
                        modPoly = modPoly.Select((val) => val.Select((innerval) => new Tuple<BigInteger, int>(posRemainder(innerval.Item1, GF), innerval.Item2)).ToList()).ToList();
                    } else {
                        modPoly = getModularPolyGF(l, GF);
                    }
                    BigInteger[] modPolyJ = new BigInteger[modPoly.Count()];
                    for (int i = 0; i < modPoly.Count(); i++)
                    {
                        BigInteger sum = BigInteger.Zero;
                        for (int j = 0; j < modPoly[i].Count(); j++)
                        {
                            if (modPoly[i].Count() - 1 - j == 0)
                                sum += modPoly[i][j].Item1;
                            else
                                sum += posRemainder(modPoly[i][j].Item1 * BigInteger.ModPow(j_invariant, modPoly[i].Count() - 1 - j, GF), GF);
                        }
                        modPolyJ[i] = posRemainder(sum, GF);
                    }
                    SortedList<BigInteger, BigInteger> xp = new SortedList<BigInteger, BigInteger>();
                    xp.Add(GF, 1);
                    //remainderPolyRingSparse(xp, divpoly, GF);
                    //divmodPolyRingSparse(xp, divpoly, GF);
                    //BigInteger[] modinv = modInversePolyRing(new BigInteger[] { BigInteger.One, BigInteger.Zero }, divpoly, GF);
                    //divmodPolyRing(mulPolyRing(modinv, new BigInteger[] { BigInteger.One, BigInteger.Zero }, GF), divpoly, GF).Item2;
                    //BigInteger[] xprem = remainderPolyRingSparsePow2(xp, modPolyJ, GF);
                    BigInteger[] xprem = modexpPolyRing(new BigInteger[] { BigInteger.One, BigInteger.Zero }, GF, modPolyJ, GF);
                    BigInteger[] gcdres = gcdPolyRing(addPolyRing(xprem, mulPolyRing(new BigInteger[] { 1, 0 }, new BigInteger[] { -1 }, GF), GF), modPolyJ, GF);
                    if (gcdres.Length - 1 == l + 1)
                    {
                        l = (int)nextPrime(l); continue; //pathological case with degree l + 1
                    }
                    Console.WriteLine((gcdres.Length == 1 ? "Atkin" : "Elkies") + " " + l);
                    if (gcdres.Length - 1 == 0)
                    { //Atkin prime with degree 0
                        //List<BigInteger> T = new List<BigInteger>();
                        BigInteger k = posRemainder(GF, l);
                        BigInteger v = TonelliShanks(rng, k, l);
                        BigInteger lim = 1;
                        BigInteger[][] u = new BigInteger[GetBitSize(l)][];
                        u[0] = xprem;
                        u[1] = substitutePolyRing(u[0], u[0], modPolyJ, GF);
                        BigInteger r;
                        for (r = 2; r <= l + 1; r++)
                        {
                            BigInteger[] C = null;
                            if (posRemainder(l + 1, r) != 0) continue;
                            BigInteger jj = (l + 1) / r;
                            if ((jj & 1) == 0 && (v == 0 && (k % l) != 0)) continue;
                            if ((jj & 1) == 1 && v != 0) continue;
                            BigInteger kk = r; int m = 0;
                            bool first = true;
                            while (true)
                            {
                                if ((kk & 1) != 0)
                                {
                                    if (first) C = u[m];
                                    else C = substitutePolyRing(u[m], C, modPolyJ, GF);
                                    first = false;
                                }
                                kk >>= 1;
                                if (kk == 0) break;
                                m++;
                                if (m > lim)
                                {
                                    u[m] = substitutePolyRing(u[m - 1], u[m - 1], modPolyJ, GF);
                                }
                            }
                            if (C.SequenceEqual(new BigInteger[] { 1, 0 })) break;
                        }
                        BigInteger qnr = 2;
                        while (TonelliShanks(rng, qnr, l) != 0 || (qnr % l) == 0) qnr++;
                        BigInteger ord = l * l - 1;
                        //find generator of F(l^2)
                        BigInteger gx, gy = 1;
                        for (gx = 1; gx < l; gx++)
                        {
                            bool gen = true;
                            for (BigInteger jj = 2; jj < ord >> 1; jj++)
                            {
                                if (posRemainder(ord, jj) != 0) continue;
                                Tuple<BigInteger, BigInteger> ab = powquad(l, qnr, gx, gy, ord / jj);
                                if (ab.Item1 == 1 && ab.Item2 == 0)
                                {
                                    gen = false;
                                    break;
                                }
                            }
                            if (gen) break;
                        }
                        BigInteger candidates = 0;
                        List<BigInteger> T = new List<BigInteger>();
                        BigInteger rphi = 1;
                        for (BigInteger i = 2; i < r; i++) if (BigInteger.GreatestCommonDivisor(i, r) == 1) rphi++;
                        for (BigInteger jj = 1; jj < r; jj++)
                        {
                            if (jj > 1 && BigInteger.GreatestCommonDivisor(jj, r) != 1) continue;
                            Tuple<BigInteger, BigInteger> ab = powquad(l, qnr, gx, gy, jj * ord / r);
                            BigInteger tau = posRemainder((ab.Item1 + 1) * k * (int)modInverse(2, l), l);
                            if (tau == 0)
                            { //this special case means r==2 and we can determine a single candidate easy to use
                                T.Add(tau); //posRemainder(GF + 1, l)
                                break;
                            }
                            else if (TonelliShanks(rng, tau, l) != 0)
                            {
                                tau = TonelliShanks(rng, tau, l);
                                tau = posRemainder(2 * tau, l);
                                T.Add(posRemainder(tau, l));
                                T.Add(posRemainder(-tau, l));
                                if (T.Count() == rphi)
                                { //total will always be rphi at end
                                    break;
                                }
                            }
                        }
                        if (T.Count() != 1)
                        {
                            //can save T for match sort algorithm...
                            Ap.Add(new Tuple<List<BigInteger>, BigInteger>(T, l));
                            prodA *= l;
                            l = (int)nextPrime(l); continue;
                        }
                        else tl = T[0];
                    }
                    else
                    {
                        //mueller 0 200 -o mueller.raw
                        //need to specify with 32 signed 32-bit numbers...
                        //233970423115425145524320034830162017933+1=2 * 13 * 547 * 94819 * 3444919 * 50364659311132962574477
                        //50364659311132962574477+1=2 * 7 * 29 * 89 * 293 * 3761 * 24317 * 52015037
                        //process -f 2*13*547*94819*3444919*(2*7*29*89*293*3761*24317*52015037-1)-1 -i mueller.raw -o test128.pol
                        //sea -95051 11279326 -i test128.pol
                        //Elkies prime
                        BigInteger E4b = posRemainder(-(Ea * modInverse(3, GF)), GF);
                        BigInteger E6b = posRemainder(-(Eb * modInverse(2, GF)), GF);
                        delta = posRemainder((E4b * E4b * E4b - E6b * E6b) * modInverse(1728, GF), GF);
                        BigInteger s = BigInteger.One;
                        for (; ; s++)
                            if (s * (l - 1) % 12 == 0) break;

                        //solve quadratic for root
                        BigInteger g, discrim;
                        if (gcdres.Length - 1 == 1)
                        { //degree == 1
                            //one square root
                            discrim = 0;
                            g = posRemainder(-gcdres[gcdres.Length - 1], GF);
                        }
                        else
                        { //degree == 2
                            //two square roots
                            discrim = 1;
                            g = TonelliShanks(rng, posRemainder(gcdres[1] * gcdres[1] - 4 * gcdres[gcdres.Length - 1], GF), GF);
                            g = posRemainder((-gcdres[1] - g) * modInverse(2, GF), GF);
                        }
                        List<List<Tuple<BigInteger, int>>> dGx = diffdx(modPoly);
                        List<List<Tuple<BigInteger, int>>> dGy = diffdy(modPoly);
                        List<List<Tuple<BigInteger, int>>> dGxx = diffdx(dGx);
                        List<List<Tuple<BigInteger, int>>> dGxy = diffdx(dGy);
                        List<List<Tuple<BigInteger, int>>> dGyy = diffdy(dGy);
                        BigInteger Eg = evalDiffEq(dGx, g, j_invariant, GF);
                        BigInteger Ej = evalDiffEq(dGy, g, j_invariant, GF);
                        BigInteger Exy = evalDiffEq(dGxy, g, j_invariant, GF);
                        BigInteger Dg = posRemainder(g * Eg, GF);
                        BigInteger Dj = posRemainder(j_invariant * Ej, GF);
                        BigInteger atilde, btilde, p1;
                        BigInteger deltal = posRemainder(delta * BigInteger.ModPow(g, 12 / s, GF) * modInverse(BigInteger.ModPow(l, 12, GF), GF), GF);
                        if (Dj == 0)
                        {
                            BigInteger E4bl = E4b * modInverse(l * l, GF);
                            atilde = posRemainder(-3 * BigInteger.ModPow(l, 4, GF) * E4bl, GF);
                            BigInteger jl = BigInteger.ModPow(E4bl, 3, GF) * modInverse(deltal, GF);
                            btilde = posRemainder(2 * BigInteger.ModPow(l, 6, GF) * TonelliShanks(rng, (jl - 1728) * deltal, GF), GF);
                            p1 = 0;
                        }
                        else
                        {
                            BigInteger E2bs = posRemainder((-12 * E6b * Dj) * modInverse(s * E4b * Dg, GF), GF);

                            BigInteger gd = posRemainder(-(s * modInverse(12, GF)) * E2bs * g, GF);
                            BigInteger jd = posRemainder(-E4b * E4b * E6b * modInverse(delta, GF), GF);
                            BigInteger E0b = posRemainder(E6b * modInverse(E4b * E2bs, GF), GF);

                            BigInteger Dgd = posRemainder(gd * Eg + g * (gd * evalDiffEq(dGxx, g, j_invariant, GF) + jd * Exy), GF);
                            BigInteger Djd = posRemainder(jd * Ej + j_invariant * (jd * evalDiffEq(dGyy, g, j_invariant, GF) + gd * Exy), GF);

                            BigInteger E0bd = posRemainder(((-s * Dgd) * modInverse(12, GF) - E0b * Djd) * modInverse(Dj, GF), GF);

                            BigInteger E4bl = posRemainder((E4b - E2bs * (12 * E0bd * modInverse(E0b, GF) + 6 * E4b * E4b * modInverse(E6b, GF) - 4 * E6b * modInverse(E4b, GF)) + E2bs * E2bs) * modInverse(l * l, GF), GF);

                            BigInteger jl = posRemainder(BigInteger.ModPow(E4bl, 3, GF) * modInverse(deltal, GF), GF);
                            BigInteger fs = posRemainder(BigInteger.ModPow(l, s, GF) * modInverse(g, GF), GF); BigInteger fd = posRemainder(s * E2bs * fs * modInverse(12, GF), GF);

                            BigInteger Dgs = evalDiffEq(dGx, fs, jl, GF);
                            BigInteger Djs = evalDiffEq(dGy, fs, jl, GF);

                            BigInteger jld = posRemainder(-fd * Dgs * modInverse(l * Djs, GF), GF);
                            BigInteger E6bl = posRemainder(-E4bl * jld * modInverse(jl, GF), GF);

                            atilde = posRemainder(-3 * BigInteger.ModPow(l, 4, GF) * E4bl, GF);
                            btilde = posRemainder(-2 * BigInteger.ModPow(l, 6, GF) * E6bl, GF);
                            p1 = posRemainder(-l * E2bs * modInverse(2, GF), GF);
                        }
                        int ld = (l - 1) / 2;
                        int ld1 = (l - 3) / 2;
                        BigInteger[] cf = getCk(ld1, Ea, Eb, GF);

                        BigInteger[][] WP = new BigInteger[ld + 1][];
                        WP[0] = new BigInteger[] { BigInteger.Zero };
                        WP[1] = cf.Reverse().Concat(new BigInteger[] { BigInteger.One }).ToArray();
                        for (int v = 2; v <= ld; v++)
                            WP[v] = reducePoly(mulPolyRing(WP[v - 1], WP[1], GF), 0, ld + 1).Item2;
                        //WPv have understood multiplier x^-v
                        BigInteger[] cft = getCk(ld1, atilde, btilde, GF);
                        BigInteger[] Y = Enumerable.Range(1, ld1).Select((k) => posRemainder((l * cf[k] - cft[k]) * modInverse((2 * k + 1) * (2 * k + 2), GF), GF)).Reverse().Concat(new BigInteger[] { BigInteger.Zero, BigInteger.Zero }).ToArray();
                        Y[Y.Length - 2] = posRemainder(Y[Y.Length - 2] - p1, GF);
                        BigInteger RF = BigInteger.One;
                        BigInteger[] H = new BigInteger[] { BigInteger.One }, X = new BigInteger[] { BigInteger.One };
                        for (int r = 1; r <= ld; r++)
                        {
                            X = reducePoly(mulPolyRing(X, Y, GF), 0, ld + 1).Item2;
                            RF *= r;
                            H = addPolyRing(H, mulPolyRing(X, new BigInteger[] { modInverse(RF, GF) }, GF), GF);
                        }
                        //H has understood multiplier x^-d
                        BigInteger ad = 1;
                        BigInteger[] fl = new BigInteger[ld + 1];
                        fl[0] = ad;
                        for (int v = ld - 1; v >= 0; v--)
                        {
                            H = addPolyRing(H, mulPolyRing(WP[v + 1], new BigInteger[] { -ad }, GF), GF);
                            H = H.Take(H.Length - 1).ToArray();
                            ad = H.Length == 0 ? BigInteger.Zero : H.Last();
                            fl[ld - v] = ad;
                        }
                        //GetFactorOfDivisionPolynomialFactor(l, Ea, Eb, GF);
                        xprem = modexpPolyRing(new BigInteger[] { BigInteger.One, BigInteger.Zero }, GF, fl, GF);
                        BigInteger[] yprem = modexpPolyRing(f, (GF - 1) / 2, fl, GF);
                        for (int lambda = 1; lambda <= (l - 1) / 2; lambda++)
                        {
                            BigInteger tau = (lambda + modInverse(lambda, l) * GF) % l;
                            divPolys = getDivPolys(divPolys, lambda * 2, Ea, Eb, f, GF);
                            BigInteger k = (l + tau * tau - (4 * GF) % l) % l;
                            BigInteger sqrroot = TonelliShanks(rng, k, l); //compute Jacobian the long way
                            if ((sqrroot != 0 || (k % l) != 0) && discrim == 0 || sqrroot == 0 && discrim == 1) continue;
                            Tuple<BigInteger[], BigInteger[]> R = scaleECDivPoly(new Tuple<BigInteger[], BigInteger[]>(new BigInteger[] { BigInteger.One, BigInteger.Zero }, new BigInteger[] { BigInteger.One }), lambda, GF, divPolys, fl, f);
                            if (xprem.SequenceEqual(R.Item1))
                            {
                                if (yprem.SequenceEqual(R.Item2))
                                {
                                }
                                else if (yprem.SequenceEqual(mulPolyRing(R.Item2, new BigInteger[] { -1 }, GF)))
                                {
                                    tau = (l - tau) % l;
                                }
                                tl = tau;
                                break;
                            }
                        }
                        //BigInteger lambda = BigInteger.Zero;
                        //t = lambda + lambda / GF;
                        //Ep.Add(new Tuple<BigInteger, BigInteger>(t, l));
                    }
                }
                Console.WriteLine(l + " " + tl + " " + posRemainder(realT, l));
                BigInteger a = prodS * modInverse(prodS, l);
                BigInteger b = l * modInverse(l, prodS);
                prodS *= l;
                t = posRemainder(a * tl + b * t, prodS);
                l = (int)nextPrime(l);
            }
            if (Ap.Count() != 0)
            {
                BigInteger x, y;
                do
                {
                    x = GetRandomBitSize(rng, GetBitSize(GF), GF);
                    y = TonelliShanks(rng, posRemainder(x * x * x + x * Ea + Eb, GF), GF);
                } while (y == 0); //all finite points are also generators if prime order of points
                Tuple<BigInteger, BigInteger> P = new Tuple<BigInteger, BigInteger>(x, y);
                //Tuple<BigInteger, BigInteger> Q = scaleEC(P, GF + 1, Ea, GF);

                List<Tuple<List<BigInteger>, BigInteger>> A1 = new List<Tuple<List<BigInteger>, BigInteger>>(),
                    A2 = new List<Tuple<List<BigInteger>, BigInteger>>();
                int n1 = 1, n2 = 1; //partition into 2 sets
                for (int i = 0; i < Ap.Count; i++)
                {
                    if (n1 <= n2)
                    {
                        A1.Add(Ap[i]);
                        n1 += Ap[i].Item1.Count();
                    }
                    else
                    {
                        A2.Add(Ap[i]);
                        n2 += Ap[i].Item1.Count();
                    }
                }
                List<BigInteger>[] tau = new List<BigInteger>[2] { new List<BigInteger>(), new List<BigInteger>() };
                BigInteger[] m = new BigInteger[2] { 1, 1 };
                for (int ct = 0; ct <= 1; ct++)
                { //generate CRT combinations of both sets
                    List<Tuple<List<BigInteger>, BigInteger>> Acur = ct == 0 ? A1 : A2;
                    BigInteger totalCombs = 1;
                    for (int i = 0; i < Acur.Count(); i++) totalCombs *= Acur[i].Item1.Count();
                    for (BigInteger i = 0; i < totalCombs; i++)
                    {
                        BigInteger tryT = BigInteger.Zero;
                        BigInteger tryProdS = BigInteger.One;
                        int j;
                        BigInteger itmp = i;
                        for (j = 0; j < Acur.Count(); j++)
                        {
                            BigInteger a = tryProdS * modInverse(tryProdS, Acur[j].Item2);
                            BigInteger b = Acur[j].Item2 * modInverse(Acur[j].Item2, tryProdS);
                            tryProdS *= Acur[j].Item2;
                            tryT = (a * Acur[j].Item1[(int)(itmp % Acur[j].Item1.Count())] + b * tryT) % tryProdS;
                            itmp /= Acur[j].Item1.Count();
                        }
                        tau[ct].Add(tryT);
                        if (i == 0) m[ct] = tryProdS;
                    }
                }
                List<BigInteger>[] R = new List<BigInteger>[2] { new List<BigInteger>(), new List<BigInteger>() };
                for (int ct = 0; ct <= 1; ct++)
                {
                    for (int i = 0; i < tau[ct].Count(); i++)
                    {
                        BigInteger r = posRemainder((tau[ct][i] - t) * modInverse(posRemainder(prodS * m[1 - ct], m[ct]), m[ct]), m[ct]);
                        if (ct == 0 && r > (m[ct] >> 1)) r -= m[ct];
                        //if (ct == 1 && r > (m[1] >> 1)) r -= m[1]; //this should not be necessary though since r[0] already scaled
                        R[ct].Add(r);
                        if (ct == 1) R[ct].Add(r - m[ct]); //abs(R[1]) <= m[1] so must try both positive and negative value
                    }
                }
                Tuple<BigInteger, BigInteger> Q = scaleEC(P, GF + 1 - t, Ea, GF);
                Tuple<BigInteger, BigInteger> PMe = scaleEC(P, prodS, Ea, GF);
                Tuple<BigInteger, BigInteger> Pm0 = scaleEC(PMe, m[0], Ea, GF), Pm1 = scaleEC(PMe, m[1], Ea, GF);
                //List<Tuple<BigInteger, BigInteger>> Q1 = new List<Tuple<BigInteger, BigInteger>>();
                SortedList<BigInteger, Tuple<Tuple<BigInteger, BigInteger>, int>> Q1 = new SortedList<BigInteger, Tuple<Tuple<BigInteger, BigInteger>, int>>();
                for (int i = 0; i < R[0].Count(); i++)
                {
                    Tuple<BigInteger, BigInteger> Q1pt = addEC(Q, invertEC(scaleEC(Pm1, R[0][i], Ea, GF), GF), Ea, GF);
                    //Q1.Add(Q1pt);
                    Q1.Add(Q1pt.Item1, new Tuple<Tuple<BigInteger, BigInteger>, int>(Q1pt, i));
                }
                BigInteger r1 = 0, r2 = 0;
                for (int i = 0; i < R[1].Count(); i++)
                {
                    Tuple<BigInteger, BigInteger> Q2 = scaleEC(Pm0, R[1][i], Ea, GF);
                    //if (Q1.Any((val) => val.Item1 == Q2.Item1)) {
                    if (Q1.ContainsKey(Q2.Item1) && Q1[Q2.Item1].Item1.Item2 == Q2.Item2)
                    {
                        //r1 = R[0][Q1.Select((val, idx) => new Tuple<Tuple<BigInteger, BigInteger>, int>(val, idx)).First((val) => val.Item1.Item1 == Q2.Item1).Item2];
                        r1 = R[0][Q1[Q2.Item1].Item2];
                        r2 = R[1][i];
                        break;
                    }
                }
                t = t + prodS * (r1 * m[1] + r2 * m[0]); //(r1 * m[1] + r2 * m[0]) % (m[0] * m[1]) //but no modulo needed and wrong in fact as already calculated exactly including sign
                prodS *= m[0] * m[1];
                /*BigInteger totalCombs = 1; //naive CRT combination method
                for (int i = 0; i < Ap.Count(); i++) totalCombs *= Ap[i].Item1.Count();
                for (BigInteger i = 0; i < totalCombs; i++) {
                    BigInteger tryT = t;
                    BigInteger tryProdS = prodS;
                    int j;
                    BigInteger itmp = i;
                    for (j = 0; j < Ap.Count(); j++) {
                        BigInteger a = tryProdS * modInverse(tryProdS, Ap[j].Item2);
                        BigInteger b = Ap[j].Item2 * modInverse(Ap[j].Item2, tryProdS);
                        tryProdS *= Ap[j].Item2;
                        tryT = (a * Ap[j].Item1[(int)(itmp % Ap[j].Item1.Count())] + b * tryT) % tryProdS;
                        itmp /= Ap[j].Item1.Count();
                    }
                    if (Q.Item1 == scaleEC(P, tryT, Ea, GF).Item1 && Q.Item2 == scaleEC(P, tryT, Ea, GF).Item2) {
                        t = tryT;
                        prodS = tryProdS;
                        break;
                    }
                }*/
            }
            if (prodS <= sqrtp4)
            {
                //sqrtGF = Sqrt(4 * GF);
                BigInteger x, y;
                do
                {
                    x = GetRandomBitSize(rng, GetBitSize(GF), GF);
                    y = TonelliShanks(rng, posRemainder(x * x * x + x * Ea + Eb, GF), GF);
                } while (y == 0); //all finite points are also generators if prime order of points
                Tuple<BigInteger, BigInteger> P = new Tuple<BigInteger, BigInteger>(x, y);
                Tuple<BigInteger, BigInteger> Q = scaleEC(P, GF + 1, Ea, GF);
                //Tuple<BigInteger, BigInteger> Q1 = addEC(Q, scaleEC(new Tuple<BigInteger, BigInteger>(x, y), sqrtGF, Ea, GF), Ea, GF);
                //Q1 == scaleEC(P, realT + sqrtGF, Ea, GF); //here is the discrete log
                //Q == scaleEC(P, realT, Ea, GF);
                //fullt = t % prodS, fullt = t + m * prodS
                BigInteger mval = (realT - t) / prodS;
                //Tuple<BigInteger, BigInteger> Ycalc = addEC(scaleEC(P, t, Ea, GF), scaleEC(P, mval * prodS, Ea, GF), Ea, GF);
                //Q.Item1 == Ycalc.Item1 && Q.Item2 == Ycalc.Item2;
                Tuple<BigInteger, BigInteger> GprimeEC = scaleEC(P, prodS, Ea, GF);
                Tuple<BigInteger, BigInteger> YprimeEC = addEC(Q, invertEC(scaleEC(P, t, Ea, GF), GF), Ea, GF);
                //Tuple<BigInteger, BigInteger> YprimeECcalc = scaleEC(GprimeEC, mval, Ea, GF);
                //YprimeECcalc.Item1 == YprimeEC.Item1 && YprimeECcalc.Item2 == YprimeEC.Item2
                BigInteger Mprime = PollardKangarooEC(0, sqrtp4 / prodS, 13, GprimeEC, Ea, GF, YprimeEC); //(q - 1) / rcum is 43 bits in this case, 26 could also be good
                t = t + Mprime * prodS;
            }
            if (t > Sqrt(4 * GF)) //atkins case has already solved the sign
                t -= prodS;
            return GF + 1 - t;
        }
        static Tuple<BigInteger, BigInteger> cswap(BigInteger a, BigInteger b, bool swap)
        {
            return swap ? new Tuple<BigInteger, BigInteger>(b, a) : new Tuple<BigInteger, BigInteger>(a, b);
        }
        public static BigInteger ladder(BigInteger u, BigInteger k, int Ea, BigInteger p)
        {
            BigInteger u2 = 1, w2 = 0;
            BigInteger u3 = u, w3 = 1;
            for (int i = GetBitSize(p); i >= 0; i--)
            {
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
        public static Tuple<BigInteger, BigInteger> ladder2(Tuple<BigInteger, BigInteger> u, BigInteger k, int Ea, int EaOrig, int Eb, BigInteger p, int conv)
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
        public static Tuple<BigInteger, BigInteger> montgToWS(Tuple<BigInteger, BigInteger> Q, int conv)
        {
            return new Tuple<BigInteger, BigInteger>(Q.Item1 + conv, Q.Item2);
        }
        public static Tuple<BigInteger, BigInteger> montgPtToWS(BigInteger x, int conv, BigInteger Ea, BigInteger GF, System.Security.Cryptography.RNGCryptoServiceProvider rng)
        {
            return new Tuple<BigInteger, BigInteger>(x + conv, TonelliShanks(rng, posRemainder(x * x * x + Ea * x * x + x, GF), GF));
            //TonelliShanks(rng, posRemainder((x + 178) * (x + 178) * (x + 178) + EaOrig * (x + 178) + Eb, GF), GF)
        }
        public static Tuple<BigInteger, BigInteger> WSToMontg(Tuple<BigInteger, BigInteger> Q, int conv)
        {
            return new Tuple<BigInteger, BigInteger>(Q.Item1 - conv, Q.Item2);
        }
        public static Tuple<BigInteger, BigInteger> signECDSA(RNGCryptoServiceProvider rng, BigInteger m, BigInteger d, BigInteger n, Tuple<BigInteger, BigInteger> G, int Ea, BigInteger GF)
        {
            BigInteger k, r, s;
            do
            {
                do
                {
                    do { k = GetNextRandomBig(rng, n); } while (k <= 1);
                    r = scaleEC(G, k, Ea, GF).Item1;
                } while (r.Equals(BigInteger.Zero));
                s = BigInteger.Remainder((m + d * r) * modInverse(k, n), n);
            } while (s.Equals(BigInteger.Zero));
            return new Tuple<BigInteger, BigInteger>(r, s);
        }
        public static bool verifyECDSA(BigInteger m, Tuple<BigInteger, BigInteger> rs, Tuple<BigInteger, BigInteger> Q, BigInteger n, Tuple<BigInteger, BigInteger> G, int Ea, BigInteger GF)
        {
            BigInteger inv = modInverse(rs.Item2, n), u1 = BigInteger.Remainder(m * inv, n), u2 = BigInteger.Remainder(rs.Item1 * inv, n);
            return rs.Item1.Equals(addEC(scaleEC(G, u1, Ea, GF), scaleEC(Q, u2, Ea, GF), Ea, GF).Item1);
        }


        static void testMul()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            System.Diagnostics.Stopwatch s = new System.Diagnostics.Stopwatch();
            /*for (int m = 0; m < 32; m++) {
                BigInteger num = GetRandomBitSize(rng, 65536, BigInteger.One << 65536);
                s.Start();
                for (int n = 0; n < 100000; n++)
                {
                    BigInteger takeNum = num & ((BigInteger.One << (32768 + m)) - 1);
                    //BigInteger highNum = num >> (32768 + m);
                }
                s.Stop();
                Console.WriteLine(s.ElapsedMilliseconds);
                s.Reset();
                s.Start();
                BigInteger A = ((BigInteger.One << (32768 + m)) - 1);
                for (int n = 0; n < 100000; n++) {
                    BigInteger takeNum = num & A;
                    //BigInteger highNum = num >> (32768 + m);
                }
                s.Stop();
                Console.WriteLine(s.ElapsedMilliseconds);
                s.Reset();
                s.Start();
                for (int n = 0; n < 100000; n++) {
                    BigInteger takeNum = takeBitsBigInteger(num, 32768 + m);
                    //BigInteger highNum, takeNum;
                    //(highNum, takeNum) = splitBigInteger(num, 32768 + m);
                }
                s.Stop();
                Console.WriteLine(s.ElapsedMilliseconds);
                s.Reset();
                if ((num & ((BigInteger.One << (32768 + m)) - 1)) != takeBitsBigInteger(num, 32768 + m)) throw new ArgumentException();
                if ((num >> (32768 + m)) != splitBigInteger(num, 32768 + m).Item1) throw new ArgumentException();
            }*/
            /*for (int n = 10; n < 24; n++) {
                BigInteger num = GetRandomBitSize(rng, 1 << n, BigInteger.One << (1 << n));
                //s.Start();
                //int n1 = GetBitSizeSlow(num);
                //s.Stop();
                //Console.WriteLine(n1 + " - " + s.ElapsedMilliseconds);
                //s.Reset();
                s.Start();
                int n2 = GetBitSizeHiSearch(num);
                s.Stop();
                Console.WriteLine(n2 + " - " + s.ElapsedMilliseconds);
                s.Reset();
                s.Start();
                int n3 = GetBitSizeRecurseBinSearch(num);
                s.Stop();
                Console.WriteLine(n3 + " - " + s.ElapsedMilliseconds);
                s.Reset();
                s.Start();
                int n4 = GetBitSizeReflection(num);
                s.Stop();
                Console.WriteLine(n4 + " - " + s.ElapsedMilliseconds);
                s.Reset();
                s.Start();
                int n5 = GetBitSize(num);
                s.Stop();
                Console.WriteLine(n5 + " - " + s.ElapsedMilliseconds);
                s.Reset();
            }*/
            /*for (int i = 0; i < 1 << 16; i++) {
                for (int j = 0; j <= 16; j++) {
                    if (takeBitsBigInteger(i, j) != new BigInteger(i & ((1 << j) - 1))) throw new ArgumentException();
                }
            }*/
            /*for (int n = 10; n < 32; n++) {
                BigInteger a;
                do
                {
                    a = GetRandomBitSize(rng, 1 << 20, BigInteger.One << (1 << 20));
                } while (a < 0);
                BigInteger b;
                do
                {
                    b = GetRandomBitSize(rng, 1 << 20, BigInteger.One << (1 << 20));
                } while (b < 0);
                thresh = 1 << n;
                s.Start();
                BigInteger ck = bigMul(a, b);
                s.Stop();
                Console.WriteLine(n + " - " + s.ElapsedMilliseconds);
                s.Reset();
            }*/
            for (int n = 1 << 21; n < 1 << 24; n += 32768)
            {
                BigInteger a;
                do
                {
                    a = GetRandomBitSize(rng, n, BigInteger.One << n);
                } while (a < 0);
                BigInteger b;
                do
                {
                    b = GetRandomBitSize(rng, n, BigInteger.One << n);
                } while (b < 0);
                /*s.Start();
                BigInteger c = a * b;
                s.Stop();
                Console.WriteLine("BigInteger*:        " + s.ElapsedMilliseconds);
                s.Reset();*/
                s.Start();
                BigInteger ckf = mulKaratsubaFast(a, b, GetBitSize(a), GetBitSize(b));
                s.Stop();
                Console.WriteLine("KaratsubaFast:      " + s.ElapsedMilliseconds);
                s.Reset();
                s.Start();
                BigInteger ck = bigMul(a, b);
                s.Stop();
                Console.WriteLine("BigMul:             " + s.ElapsedMilliseconds);
                s.Reset();
                s.Start();
                BigInteger cs = mulSchonhageStrassen(a, b, GetBitSize(a), GetBitSize(b));
                s.Stop();
                Console.WriteLine("Schonhage-Strassen: " + s.ElapsedMilliseconds);
                s.Reset();
                //if (c != ck) throw new ArgumentException();
                //if (ck != cs) throw new ArgumentException();
                if (ckf != ck) throw new ArgumentException();
            }
        }
    }
}
