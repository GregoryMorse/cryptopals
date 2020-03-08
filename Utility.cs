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
            static UInt32 SHA1HashSize = 20;
            public UInt32[] Intermediate_Hash = new UInt32[SHA1HashSize / 4]; /* Message Digest  */
            public UInt32 Length_Low;                        /* Message length in bits      */
            public UInt32 Length_High;                       /* Message length in bits      */
            public int Message_Block_Index;                  /* Index into message block array   */
            public byte[] Message_Block = new byte[64];      /* 512-bit message blocks      */
            public int Computed;                             /* Is the digest computed?         */
            public int Corrupted;                            /* Is the message digest corrupted? */
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
    }
}
