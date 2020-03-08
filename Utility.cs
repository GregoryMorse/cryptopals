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
                return new byte[] { 0x80 }
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
                    (b4 & (1 << 25)) != 0 && (b4 & (1 << 26)) != 0 && (b4 & (1 << 28)) != 0 && (b4 & (1 << 18)) == 0 && (b4 & (1 << 29)) == 0 && (b4 & (1 << 25)) == (c4 & (1 << 25));
            }
            public static byte[] WangsAttack(byte[] bytes, bool bMulti, bool bNaito)
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

                if (bMulti)
                {
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
                            if ((a5 & (1 << 18)) != (c4 & (1 << 18)))
                            {
                                x[0] = ((a1 & (1 << 18)) == 0) ? x[0] + (1 << 15) : x[0] - (1 << 15);
                                a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                            }
                            //extra condition to allow correcting c5,29, c5,32
                            if (bNaito)
                            {
                                if ((a5 & (1 << 19)) != (b4 & (1 << 19)))
                                {
                                    x[0] = ((a1 & (1 << 19)) == 0) ? x[0] + (1 << 16) : x[0] - (1 << 16);
                                    a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                                }
                                if ((a5 & (1 << 22)) != (b4 & (1 << 22)))
                                {
                                    x[0] = ((a1 & (1 << 22)) == 0) ? x[0] + (1 << 19) : x[0] - (1 << 19);
                                    a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                                }
                            }
                            if ((a5 & (1 << 25)) == 0)
                            {
                                x[0] = x[0] + (1 << 22);
                                a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                            }
                            if ((a5 & (1 << 26)) != 0)
                            {
                                x[0] = x[0] - (1 << 23);
                                a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                            }
                            if ((a5 & (1 << 28)) == 0)
                            {
                                x[0] = x[0] + (1 << 25);
                                a5 = Round2Operation(a4, b4, c4, d4, x[0], 3);
                            }
                            if ((a5 & ((uint)1 << 31)) == 0)
                            {
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
                            if ((d5 & (1 << 18)) != (a5 & (1 << 18)))
                            {
                                if (bNaito)
                                {
                                    x[1] = (d1 & (1 << 13)) == 0 ? x[1] + (1 << 6) : x[1] - (1 << 6);
                                    d1 = Round1Operation(d0, a1, b0, c0, x[1], 7);
                                    x[4] = Unround1Operation(a1, b1, c1, d1, a2, 3);
                                }
                                else
                                {
                                    x[4] = ((a2 & (1 << 16)) == 0) ? x[4] + (1 << 13) : x[4] - (1 << 13);
                                }
                                d5 = Round2Operation(d4, a5, b4, c4, x[4], 5); //stomps on c5,26 extra condition a2,17=b2,17 if d5,19 not properly modified
                            }
                            if ((d5 & (1 << 25)) != (b4 & (1 << 25)))
                            {
                                x[4] = ((a2 & (1 << 23)) == 0) ? x[4] + (1 << 20) : x[4] - (1 << 20);
                                d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                            }
                            if ((d5 & (1 << 26)) != (b4 & (1 << 26)))
                            {
                                x[4] = ((a2 & (1 << 24)) == 0) ? x[4] + (1 << 21) : x[4] - (1 << 21);
                                d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                            }
                            if ((d5 & (1 << 28)) != (b4 & (1 << 28)))
                            {
                                x[4] = ((a2 & (1 << 26)) == 0) ? x[4] + (1 << 23) : x[4] - (1 << 23);
                                d5 = Round2Operation(d4, a5, b4, c4, x[4], 5);
                            }
                            if (bNaito)
                            {
                                if ((d5 & ((uint)1 << 31)) != (b4 & ((uint)1 << 31)))
                                {
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
                        if ((c5 & (1 << 25)) != (d5 & (1 << 25)))
                        {
                            x[5] = x[5] + (1 << 9);
                            d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                            x[8] = Unround1Operation(a2, b2, c2, d2, a3, 3);
                            c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                        }
                        if ((c5 & (1 << 26)) != (d5 & (1 << 26)))
                        {
                            x[5] = x[5] + (1 << 10);
                            d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                            x[8] = Unround1Operation(a2, b2, c2, d2, a3, 3);
                            c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                        }
                        if (bNaito)
                        {
                            if ((c5 & (1 << 28)) != (d5 & (1 << 28)))
                            {
                                x[14] = x[14] + (1 << 8);
                                c4 = Round1Operation(c3, d4, a4, b3, x[14], 11);
                                c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                            }
                            if ((c5 & (1 << 29)) != (d5 & (1 << 29)))
                            {
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
                        }
                        else
                        {
                            //Naito already has this corrected by prior modifications
                            if ((c5 & (1 << 28)) != (d5 & (1 << 28)))
                            {
                                x[5] = x[5] + (1 << 12);
                                d2 = Round1Operation(d1, a2, b1, c1, x[5], 7);
                                x[8] = Unround1Operation(a2, b2, c2, d2, a3, 3);
                                c5 = Round2Operation(c4, d5, a5, b4, x[8], 9);
                            }
                            if ((c5 & (1 << 31)) != (d5 & (1 << 31)))
                            {
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

                        if (!bNaito)
                        {
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
                    if (bNaito)
                    {
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
                        for (int i = 0; i < (1 << 19); i++)
                        {
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
                            for (int c = 0; c < 19; c++)
                            {
                                if ((i & (1 << c)) != 0)
                                {
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
    }
}
