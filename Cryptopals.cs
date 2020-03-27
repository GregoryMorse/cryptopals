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
using static Cryptopals.Utility;
using static Cryptopals.sets;

namespace Cryptopals
{
    public class Crypto
    {
        static public bool Challenge1()
        {
            //SET 1 CHALLENGE 1
            string passResult = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs" +
                                "aWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
            string str = "49276d206b696c6c696e6720796f757220627261696e206c" +
                         "696b65206120706f69736f6e6f7573206d757368726f6f6d";
            return Convert.ToBase64String(HexDecode(str)) == passResult;
        }
        static public bool Challenge2()
        {
            //SET 1 CHALLENGE 2
            string passResult = "746865206b696420646f6e277420706c6179";
            string str1 = "1c0111001f010100061a024b53535009181c";
            string str2 = "686974207468652062756c6c277320657965";
            return HexEncode(FixedXOR(HexDecode(str1), HexDecode(str2))) == passResult;
        }
        static public bool Challenge3()
        {
            //SET 1 CHALLENGE 3
            byte passKey = 88;
            string passString = "Cooking MC's like a pound of bacon"; //Vanilla Ice - Ice Ice Baby
            string str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            byte[] b = HexDecode(str);
            byte key = GetLeastXORCharacterScore(b).First().Item1;
            string res = System.Text.Encoding.ASCII.GetString(
                            FixedXOR(b, Enumerable.Repeat(key, b.Length).ToArray()));
            return key == passKey && res == passString;
        }
        static public bool Challenge4()
        {
            //SET 1 CHALLENGE 4
            int passLine = 170;
            byte passKey = 53;
            string passString = "Now that the party is jumping\n";
            //assume 0 is starting maximum is fine in this scenario regardless
            byte[][] lines = Enumerable.Select(ReadChallengeFile("4.txt"),
                                               s => HexDecode(s)).ToArray();
            Tuple<int, byte, double> maxItem = lines.Select((l, i) => {
                Tuple<byte, double>[] vals = GetLeastXORCharacterScore(lines[i]);
                return new Tuple<int, byte, double>(i, vals.Length == 0 ? (byte)0 : vals.First().Item1, vals.Length == 0 ? 0 : vals.First().Item2); })
                    .OrderByDescending(x => x.Item3).First();
            string res = System.Text.Encoding.ASCII.GetString(
                FixedXOR(lines[maxItem.Item1],
                         Enumerable.Repeat(maxItem.Item2,
                                           lines[maxItem.Item1].Length).ToArray()));
            return maxItem.Item1 == passLine && maxItem.Item2 == passKey && res == passString;
        }
        static public bool Challenge5()
        {
            //SET 1 CHALLENGE 5
            string passResult =
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
                "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
            string str = "Burning 'em, if you ain't quick and nimble\n" +
                "I go crazy when I hear a cymbal";
            string key = "ICE";
            byte[] b = System.Text.Encoding.ASCII.GetBytes(str);
            return HexEncode(FixedXOR(b, XORRepKey(b, System.Text.Encoding.ASCII.GetBytes(key))))
                == passResult;
        }
        static string Challenge6and7pass()
        {
            return //Vanilla Ice - Play That Funky Music
            "I'm back and I'm ringin' the bell \n" +
            "A rockin' on the mike while the fly girls yell \n" +
            "In ecstasy in the back of me \n" +
            "Well that's my DJ Deshay cuttin' all them Z's \n" +
            "Hittin' hard and the girlies goin' crazy \n" +
            "Vanilla's on the mike, man I'm not lazy. \n\n" +
            "I'm lettin' my drug kick in \n" +
            "It controls my mouth and I begin \n" +
            "To just let it flow, let my concepts go \n" +
            "My posse's to the side yellin', Go Vanilla Go! \n\n" +
            "Smooth 'cause that's the way I will be \n" +
            "And if you don't give a damn, then \n" +
            "Why you starin' at me \n" +
            "So get off 'cause I control the stage \n" +
            "There's no dissin' allowed \n" +
            "I'm in my own phase \n" +
            "The girlies sa y they love me and that is ok \n" +
            "And I can dance better than any kid n' play \n\n" +
            "Stage 2 -- Yea the one ya' wanna listen to \n" +
            "It's off my head so let the beat play through \n" +
            "So I can funk it up and make it sound good \n" +
            "1-2-3 Yo -- Knock on some wood \n" +
            "For good luck, I like my rhymes atrocious \n" +
            "Supercalafragilisticexpialidocious \n" +
            "I'm an effect and that you can bet \n" +
            "I can take a fly girl and make her wet. \n\n" +
            "I'm like Samson -- Samson to Delilah \n" +
            "There's no denyin', You can try to hang \n" +
            "But you'll keep tryin' to get my style \n" +
            "Over and over, practice makes perfect \n" +
            "But not if you're a loafer. \n\n" +
            "You'll get nowhere, no place, no time, no girls \n" +
            "Soon -- Oh my God, homebody, you probably eat \n" +
            "Spaghetti with a spoon! Come on and say it! \n\n" +
            "VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n" +
            "Intoxicating so you stagger like a wino \n" +
            "So punks stop trying and girl stop cryin' \n" +
            "Vanilla Ice is sellin' and you people are buyin' \n" +
            "'Cause why the freaks are jockin' like Crazy Glue \n" +
            "Movin' and groovin' trying to sing along \n" +
            "All through the ghetto groovin' this here song \n" +
            "Now you're amazed by the VIP posse. \n\n" +
            "Steppin' so hard like a German Nazi \n" +
            "Startled by the bases hittin' ground \n" +
            "There's no trippin' on mine, I'm just gettin' down \n" +
            "Sparkamatic, I'm hangin' tight like a fanatic \n" +
            "You trapped me once and I thought that \n" +
            "You might have it \n" +
            "So step down and lend me your ear \n" +
            "'89 in my time! You, '90 is my year. \n\n" +
            "You're weakenin' fast, YO! and I can tell it \n" +
            "Your body's gettin' hot, so, so I can smell it \n" +
            "So don't be mad and don't be sad \n" +
            "'Cause the lyrics belong to ICE, You can call me Dad \n" +
            "You're pitchin' a fit, so step back and endure \n" +
            "Let the witch doctor, Ice, do the dance to cure \n" +
            "So come up close and don't be square \n" +
            "You wanna battle me -- Anytime, anywhere \n\n" +
            "You thought that I was weak, Boy, you're dead wrong \n" +
            "So come on, everybody and sing this song \n\n" +
            "Say -- Play that funky music Say, go white boy, go white boy go \n" +
            "play that funky music Go white boy, go white boy, go \n" +
            "Lay down and boogie and play that funky music till you die. \n\n" +
            "Play that funky music Come on, Come on, let me hear \n" +
            "Play that funky music white boy you say it, say it \n" +
            "Play that funky music A little louder now \n" +
            "Play that funky music, white boy Come on, Come on, Come on \n" +
            "Play that funky music \n";
        }
        static public bool Challenge6()
        {
            //SET 1 CHALLENGE 6
            int passKeyLen = 29;
            byte[] passKey = System.Text.Encoding.ASCII.GetBytes("Terminator X: Bring the noise");
            string passResult = Challenge6and7pass();
            if (HammingDistance(System.Text.Encoding.ASCII.GetBytes("this is a test"),
                                System.Text.Encoding.ASCII.GetBytes("wokka wokka!!!")) != 37)
                return false;
            byte[] b = Enumerable.Select(ReadChallengeFile("6.txt"),
                                         s => Convert.FromBase64String(s))
                .SelectMany(d => d).ToArray();
            int keyLen; byte[] key;
            (keyLen, key) = breakRepXorKey(2, 40, b);
            return keyLen == passKeyLen && key.SequenceEqual(passKey) &&
                System.Text.Encoding.ASCII.GetString(FixedXOR(b, XORRepKey(b, key))) == passResult;
        }
        static public bool Challenge7()
        {
            //SET 1 CHALLENGE 7
            string passResult = Challenge6and7pass() + "\x04\x04\x04\x04";
            byte[] b = ReadChallengeFile("7.txt").Select(s =>
                Convert.FromBase64String(s)).SelectMany(d => d).ToArray();
            byte[] o = decrypt_ecb(System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), b);
            return System.Text.Encoding.ASCII.GetString(o) == passResult;
        }
        static public bool Challenge8()
        {
            //SET 1 CHALLENGE 8
            string[] passResult = {"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4f" +
                "d5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb57" +
                "08649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d465" +
                "97949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd283" +
                "97a93eab8d6aecd566489154789a6b0308649af70dc06f4f" +
                "d5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0" +
                "ab51b29933f2c123c58386b06fba186a"};
            byte[][] lines = ReadChallengeFile("8.txt").Select(s => HexDecode(s)).ToArray();
            List<byte[]> ecbLines = new List<byte[]>();
            foreach (byte[] l in lines)
            {
                if (is_ecb_mode(l))
                {
                    ecbLines.Add(l);
                }
            }
            return ecbLines.Select((x) => HexEncode(x)).SequenceEqual(passResult);
        }

        static public bool Challenge9()
        {
            //SET 2 CHALLENGE 9
            return System.Text.Encoding.ASCII.GetString(PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), 20)) == "YELLOW SUBMARINE\x04\x04\x04\x04";
        }
        static public bool Challenge10()
        {
            //SET 2 CHALLENGE 10
            byte[] passResult = PKCS7Pad(System.Text.Encoding.ASCII.GetBytes(Challenge6and7pass()), 16);
            byte[] b = ReadChallengeFile("10.txt").Select(s => Convert.FromBase64String(s)).SelectMany(d => d).ToArray();
            byte[] o = decrypt_cbc(Enumerable.Repeat((byte)0, 16).ToArray(), System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), b);
            //proved encryption is back to input
            if (!b.SequenceEqual(encrypt_cbc(Enumerable.Repeat((byte)0, 16).ToArray(), System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), o))) return false;
            return o.SequenceEqual(passResult);
        }
        static private ValueTuple<bool, byte[]> encryption_oracle(byte[] input)
        {
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            byte[] first = new byte[5 + GetNextRandom(rnd, 6)];
            byte[] last = new byte[5 + GetNextRandom(rnd, 6)];
            byte[] data = PKCS7Pad(Enumerable.Concat(first, input).Concat(last).ToArray(), 16);
            if (GetNextRandom(rnd, 2) == 1)
            {
                return (true, encrypt_ecb(key, data));
            }
            else
            {
                byte[] iv = new byte[16];
                rnd.GetBytes(iv);
                return (false, encrypt_cbc(iv, key, data));
            }
        }
        static public bool Challenge11()
        {
            //SET 2 CHALLENGE 11
            byte[] b = ReadChallengeFile("10.txt").Select(s => Convert.FromBase64String(s)).SelectMany(d => d).ToArray();
            byte[] o = decrypt_cbc(Enumerable.Repeat((byte)0, 16).ToArray(), System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), b);
            //important note: if the plain text does not have a repeated 16-byte block starting
            //between offsets 0 to 4 and 10 to 16 inclusive then this will not be a useful detector
            //since 5+5=10 and (10+10)%16=4 
            for (int i = 0; i < 1024; i++) {
                (bool oracle_ecb, byte[] res) = encryption_oracle(o);
                if (oracle_ecb != is_ecb_mode(res)) return false;
            }
            return true;
        }
        static private byte[] encryption_oracle_with_key(ValueTuple<byte[], byte[]> key_data, byte[] input)
        {
            return encrypt_ecb(key_data.Item1, PKCS7Pad(Enumerable.Concat(input, key_data.Item2).ToArray(), 16));
        }
        static public bool Challenge12()
        {
            //SET 2 CHALLENGE 12
            string passResult = "Rollin' in my 5.0\n" + //Vanilla Ice - Ice Ice Baby
                "With my rag-top down so my hair can blow\n" +
                "The girlies on standby waving just to say hi\n" +
                "Did you stop? No, I just drove by\n";
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            byte[] b = Convert.FromBase64String(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" + 
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                "YnkK");

            int startlen = encryption_oracle_with_key((key, b), new byte[] { }).Length;
            int ct = 1; //when output size increases, difference will be one block
            while (startlen == encryption_oracle_with_key((key, b), Enumerable.Repeat<byte>(0, ct).ToArray()).Length)
            {
                ct++;
            }
            int blocksize = encryption_oracle_with_key((key, b), Enumerable.Repeat<byte>(0, ct).ToArray()).Length - startlen;
            if (blocksize != 16) return false;
            //only 2 identical blocks needed since we are at the start of string now
            if (!is_ecb_mode(encryption_oracle_with_key((key, b), Enumerable.Repeat<byte>(0, 32).ToArray()))) return false;
            int len = startlen - ct;
            byte[] output = new byte[len];
            for (int i = 0; i < len; i++)
            {
                int start = ((1 + i) / blocksize) * blocksize;
                byte[] prefix = Enumerable.Repeat<byte>(0, blocksize - (1 + i) % blocksize).ToArray();
                byte[] sample = encryption_oracle_with_key((key, b), prefix).Skip(start).Take(blocksize).ToArray();
                Dictionary<byte[], byte> dict = new Dictionary<byte[], byte>(new ByteArrayComparer());
                //maintaining a dictionary is not really of any special benefit in this scenario
                for (ct = 0; ct < 256; ct++)
                { //alphanumeric and whitespace would be a shortcut
                    byte[] ciph = encryption_oracle_with_key((key, b), prefix.Concat(output.Take(i)).Concat(new byte[] { (byte)ct }).ToArray()).Skip(start).Take(blocksize).ToArray();
                    dict.Add(ciph, (byte)ct);
                }
                output[i] = (byte)dict[sample]; //no collision and key found is asserted or will crash
            }
            return System.Text.Encoding.ASCII.GetString(output) == passResult;
        }
        static private Dictionary<string, object> parsecookie(string input)
        {
            Dictionary<string, object> dict = new Dictionary<string, object>();
            foreach (string kv in input.Split('&'))
            {
                string[] kvs = kv.Split('=');
                if (kvs.Length != 2) return new Dictionary<string, object>();
                string val = kvs[1].Trim();
                if (val.All(x => Char.IsDigit(x))) dict[kvs[0]] = int.Parse(val);
                else dict[kvs[0]] = val;
            }
            return dict;
        }
        static private string profile_for(string name)
        {
            name = name.Replace("&", "%" + ((byte)'&').ToString("X2")).Replace("=", "%" + ((byte)'=').ToString("X2"));
            Dictionary<string, Tuple<int, string>> profileDict = new Dictionary<string, Tuple<int, string>>();
            profileDict.Add("foo@bar.com", new Tuple<int, string>(10, "user"));
            if (!profileDict.ContainsKey(name)) profileDict.Add(name, new Tuple<int, string>(10, "user"));
            Dictionary<string, object> profile = new Dictionary<string, object>();
            profile.Add("email", name);
            profile.Add("uid", profileDict[name].Item1);
            profile.Add("role", profileDict[name].Item2);
            string[] encodeOrder = new string[] { "email", "uid", "role" };
            string encode = string.Empty;
            bool bFirst = true;
            foreach (string s in encodeOrder) {
                if (!bFirst) encode += "&";
                else bFirst = false;
                encode += s + "=" + profile[s];
            }
            return encode;
        }
        static private byte[] profile_for_enc(byte[] key, string name)
        {
            return encrypt_ecb(key, PKCS7Pad(Encoding.ASCII.GetBytes(profile_for(name)), 16));
        }
        static private Dictionary<string, object> profile_for_dec(byte[] key, byte[] data)
        {
            byte[] stripped;
            try {
                stripped = PKCS7Strip(decrypt_ecb(key, data));
            } catch (ArgumentException) { return new Dictionary<string, object>(); }
            return parsecookie(System.Text.Encoding.ASCII.GetString(stripped));
        }
        static public bool Challenge13()
        {
            //SET 2 CHALLENGE 13
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            Dictionary<string, object> d = parsecookie("foo=bar&baz=qux&zap=zazzle");
            Dictionary<string, object> testDict = new Dictionary<string, object>();
            testDict.Add("foo", "bar"); testDict.Add("baz", "qux"); testDict.Add("zap", "zazzle");
            if (!d.SequenceEqual(testDict)) return false;
            if (profile_for("foo@bar.com") != "email=foo@bar.com&uid=10&role=user") return false;
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            byte[] b = profile_for_enc(key, "foo@bar.com");
            testDict.Clear(); testDict.Add("email", "foo@bar.com"); testDict.Add("uid", 10); testDict.Add("role", "user");
            if (!profile_for_dec(key, b).SequenceEqual(testDict)) return false;
            byte[] adminBytes = PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("admin"), 16);
            //profile_for encrypted variation is the only one allowed to be used so must iterate through spacing of 16*16 combinations until admin achieved
            //int adjust = (profile_for("foo@bar.com").IndexOf("&role=") + "&role=".Length & 15) - "email=".Length;
            //byte[] fixEncode = profile_for_enc(key, System.Text.Encoding.ASCII.GetString(Enumerable.Repeat<byte>(0x20, 16 - "email=".Length).ToArray()) + System.Text.Encoding.ASCII.GetString(adminBytes) + "foo@bar.com" + System.Text.Encoding.ASCII.GetString(Enumerable.Repeat<byte>(0x20, 16 - adjust).ToArray()));
            testDict["role"] = "admin";
            //if we cannot exploit due to trim occurring, and it checks email address validity on decoding, then 16 emails would be needed to exploit this and additional loop to try them
            //if we cannot exploit invalid emails on encoding as it is checked, then 256 email addresses need to be added including ones with PKCS7 encoding in them
            //if not sure about 2nd block being the right one, would need to try all middle blocks
            for (int i = 0; i < 16; i++) {
                for (int j = 0; j < 16; j++) {
                    byte[] fixEncode = profile_for_enc(key, System.Text.Encoding.ASCII.GetString(Enumerable.Repeat<byte>(0x20, i).ToArray()) + System.Text.Encoding.ASCII.GetString(adminBytes) + "foo@bar.com" + System.Text.Encoding.ASCII.GetString(Enumerable.Repeat<byte>(0x20, j).ToArray()));
                    byte[] modEncode = fixEncode.Take(16).Concat(fixEncode.Skip(32).Take(fixEncode.Length - 48).Concat(fixEncode.Skip(16).Take(16))).ToArray();
                    if (profile_for_dec(key, modEncode).SequenceEqual(testDict)) return true;
                }
            }
            return false;
        }
        static private byte[] encryption_oracle_with_key(ValueTuple<byte[], byte[]> key_data, byte[] prefix, byte[] input)
        {
            return encryption_oracle_with_key(key_data, Enumerable.Concat(prefix, input).ToArray());
        }
        static public bool Challenge14()
        {
            //SET 2 CHALLENGE 14
            string passResult = "Rollin' in my 5.0\n" + //Vanilla Ice - Ice Ice Baby
                "With my rag-top down so my hair can blow\n" +
                "The girlies on standby waving just to say hi\n" +
                "Did you stop? No, I just drove by\n";
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            int randCount;
            do { randCount = GetNextRandom(rnd, 32); } while (randCount == 0);
            byte[] r = new byte[randCount];
            rnd.GetBytes(r);
            byte[] b = Convert.FromBase64String(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                "YnkK");

            int startlen = encryption_oracle_with_key((key, b), r, new byte[] { }).Length;
            int ct = 1; //when output size increases, difference will be one block
            while (startlen == encryption_oracle_with_key((key, b), r, Enumerable.Repeat<byte>(0, ct).ToArray()).Length)
            {
                ct++;
            }
            int blocksize = encryption_oracle_with_key((key, b), r, Enumerable.Repeat<byte>(0, ct).ToArray()).Length - startlen;
            if (blocksize != 16) return false;
            //need 3 (or in keysize cases 2) identical blocks makes at least 2 aligned blocks when randomly prefixed
            byte[] output = encryption_oracle_with_key((key, b), r, Enumerable.Repeat<byte>(0, blocksize * 3).ToArray());
            if (!is_ecb_mode(output)) return false;
            int startblock = 0; //determine startblock by finding first 2 duplicates
            while (!output.Skip(startblock * blocksize).Take(blocksize).SequenceEqual(
                                                output.Skip((startblock + 1) * blocksize).Take(blocksize)))
            {
                startblock++;
            }
            int startinblock = 0; //determine where in the block it was started by scanning increasing controlled data in prior block
            while (!output.Skip((startblock - 1) * blocksize).Take(blocksize).SequenceEqual(
                                                encryption_oracle_with_key((key, b), r, Enumerable.Repeat<byte>(0, startinblock).ToArray()).Skip((startblock - 1) * blocksize).Take(blocksize)))
            {
                startinblock++;
            }
            if (startinblock != 0 && startinblock % blocksize != 0) {
                startblock--; startinblock = 16 - startinblock;
            }
            int len = startlen - ct - startblock * blocksize - startinblock;
            output = new byte[len];
            for (int i = 0; i < len; i++)
            {
                int start = (startblock + (1 + i + startinblock) / blocksize) * blocksize;
                byte[] prefix = Enumerable.Repeat<byte>(0, blocksize - (1 + i + startinblock) % blocksize).ToArray();
                byte[] sample = encryption_oracle_with_key((key, b), r, prefix).Skip(start).Take(blocksize).ToArray();
                Dictionary<byte[], byte> dict = new Dictionary<byte[], byte>(new ByteArrayComparer());
                //maintaining a dictionary is not really of any special benefit in this scenario
                for (ct = 0; ct < 256; ct++)
                { //alphanumeric and whitespace would be a shortcut
                    dict.Add(encryption_oracle_with_key((key, b), r, prefix.Concat(output.Take(i)).Concat(new byte[] { (byte)ct }).ToArray()).Skip(start).Take(blocksize).ToArray(), (byte)ct);
                }
                output[i] = (byte)dict[sample]; //no collision and key found is asserted or will crash
            }
            return System.Text.Encoding.ASCII.GetString(output) == passResult;
        }
        static public bool Challenge15()
        {
            //SET 2 CHALLENGE 15
            if (Encoding.ASCII.GetString(PKCS7Strip(Encoding.ASCII.GetBytes("ICE ICE BABY\x04\x04\x04\x04"))) != "ICE ICE BABY") return false;
            try
            {
                PKCS7Strip(Encoding.ASCII.GetBytes("ICE ICE BABY\x05\x05\x05\x05"));
                return false;
            }
            catch {}
            try
            {
                PKCS7Strip(Encoding.ASCII.GetBytes("ICE ICE BABY\x01\x02\x03\x04"));
                return false;
            }
            catch
            {
            }
            return true;
        }
        static private byte[] encryption_oracle_with_key_cbc(byte[] iv, byte[] key, byte[] prefix, string input, byte[] extra)
        {
            input = input.Replace(";", "%" + ((byte)';').ToString("X2")).Replace("=", "%" + ((byte)'=').ToString("X2"));
            return encrypt_cbc(iv, key, PKCS7Pad(Enumerable.Concat(Enumerable.Concat(prefix, System.Text.Encoding.ASCII.GetBytes(input)), extra).ToArray(), 16));
        }
        static public bool Challenge16()
        {
            //SET 2 CHALLENGE 16
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            byte[] iv = new byte[16];
            string o = System.Text.Encoding.ASCII.GetString(Enumerable.Repeat<byte>(0x20, 64).ToArray());
            rnd.GetBytes(iv);
            byte[] b = encryption_oracle_with_key_cbc(iv, key, Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata="), o, Encoding.ASCII.GetBytes(";comment2=%20like%20a%20pound%20of%20bacon"));
            if (Encoding.ASCII.GetString(PKCS7Strip(decrypt_cbc(iv, key, b))).Contains(";admin=true;")) return false;
            //first send a block with all 0's to let us determine the output of the next stage
            //output = decrypt_cbc(iv, key, Enumerable.Concat(Enumerable.Concat(b.Take(32), Enumerable.Repeat((byte)0, 16)), b.Skip(48)).ToArray());
            //Console.WriteLine(Encoding.ASCII.GetString(decrypt_cbc(iv, key, Enumerable.Concat(Enumerable.Concat(b.Take(32), FixedXOR(output.Skip(48).Take(16).ToArray(), Encoding.ASCII.GetBytes(";admin=true;    "))), b.Skip(48)).ToArray())).Contains(";admin=true;"));
            return Encoding.ASCII.GetString(PKCS7Strip(decrypt_cbc(iv, key, Enumerable.Concat(Enumerable.Concat(b.Take(32), FixedXOR(System.Text.Encoding.ASCII.GetBytes(o.ToCharArray(), 16, 16), FixedXOR(b.Skip(32).Take(16).ToArray(), Encoding.ASCII.GetBytes(";admin=true;    ")))), b.Skip(48)).ToArray()))).Contains(";admin=true;");
        }
        static public bool Challenge17()
        {
            //SET 3 CHALLENGE 17
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] b;
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            int ct;
            byte[] output;
            int startinblock;
            int startblock;
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
            if (Encoding.ASCII.GetString(PKCS7Strip(output)) != rndstrs[ct]) return false;
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
                        /*try //try-catch too slow at least with debugger displaying exceptions
                        {
                            b[(startblock - 1) * 16 + startinblock] ^= (byte)(i ^ (16 - startinblock));
                            PKCS7Strip(decrypt_cbc(iv, key, b.Take((startblock + 1) * 16).ToArray()));
                            data[startinblock] = (byte)i;
                            b[(startblock - 1) * 16 + startinblock] ^= (byte)(i ^ (16 - startinblock));
                            break;
                        }
                        catch (ArgumentException) { b[(startblock - 1) * 16 + startinblock] ^= (byte)(i ^ (16 - startinblock)); }*/
                        b[(startblock - 1) * 16 + startinblock] ^= (byte)(i ^ (16 - startinblock));
                        if (PKCS7Check(decrypt_cbc(iv, key, b.Take((startblock + 1) * 16).ToArray()))) {
                            b[(startblock - 1) * 16 + startinblock] ^= (byte)(i ^ (16 - startinblock));
                            data[startinblock] = (byte)i;
                            break;
                        }
                        b[(startblock - 1) * 16 + startinblock] ^= (byte)(i ^ (16 - startinblock));
                    }
                    for (int j = 15; j > startinblock; j--) { b[(startblock - 1) * 16 + j] ^= (byte)(data[j] ^ (16 - startinblock)); }
                }
                Array.Copy(data, 0, b, startblock * 16, 16);
            }
            return Encoding.ASCII.GetString(PKCS7Strip(b.Skip(16).ToArray())) == rndstrs[ct];
        }
        static public bool Challenge18()
        {
            //SET 3 CHALLENGE 18
            string passResult = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";
            string str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
            byte[] key = System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            if (System.Text.Encoding.ASCII.GetString(crypt_ctr(0, key, Convert.FromBase64String(str))) != passResult) return false;
            //test encrypt-decrypt returns same result
            return str == Convert.ToBase64String(crypt_ctr(0, key, crypt_ctr(0, key, Convert.FromBase64String(str))));
        }
        static public bool Challenge19()
        {
            //SET 3 CHALLENGE 19
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            GetLeastXORBiTrigramScoreProto GetLeastXORBiTrigramScore = GetLeastXORBiTrigramScoreGen(
                new Dictionary<string, double> { ["turn"] = double.PositiveInfinity, ["urn,"] = double.PositiveInfinity });
            byte[] key = new byte[16]; 
            rnd.GetBytes(key); //Easter, 1916, a poem by W. B. Yeats
            string[] rndstrs = new string[] {"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
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
            string[] passResult = rndstrs.Select(str => System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(str))).ToArray();
            byte[][] lines = rndstrs.Select((str) => crypt_ctr(0, key, Convert.FromBase64String(str))).ToArray();
            int m = lines.Max((bts) => bts.Length);
            byte[] b = new byte[m]; //maximum length of keystream to try to decode
            for (int i = 0; i < b.Length; i++)
            {
                byte[] analysis = lines.Where((bts) => bts.Length > i).Select((bts) => bts[i]).ToArray();
                Tuple<byte, double>[] vals = GetLeastXORCharacterScore(analysis);
                Tuple<byte, double> val = vals.First();
                if (i == 0 && val.Item2 == vals[1].Item2) {
                    //prefer upper case when lower case assumed to win in tie
                    if (FixedXOR(analysis, Enumerable.Repeat<byte>(vals[1].Item1, analysis.Length).ToArray()).Where(x => char.IsUpper((char)x)).Count() >
                        FixedXOR(analysis, Enumerable.Repeat<byte>(val.Item1, analysis.Length).ToArray()).Where(x => char.IsUpper((char)x)).Count())
                        val = vals[1];
                }
                if (i > 3 && (analysis.Length <= 13 || val.Item2 <= 80))
                {
                    val = BigramHandler(GetLeastXORBiTrigramScore, val, lines, i, b, analysis);
                }
                b[i] = val.Item1;
            }
            for (int i = 0; i < lines.Length; i++) {
                if (System.Text.Encoding.ASCII.GetString(FixedXOR(lines[i], b.Take(lines[i].Length).ToArray())) != passResult[i]) {
                    Console.WriteLine(passResult[i]);
                    Console.WriteLine(System.Text.Encoding.ASCII.GetString(FixedXOR(lines[i], b.Take(lines[i].Length).ToArray())));
                }
            }
            return Enumerable.Range(0, lines.Length).All(i => System.Text.Encoding.ASCII.GetString(FixedXOR(lines[i], b.Take(lines[i].Length).ToArray())) == passResult[i]);
        }
        static public bool Challenge20()
        {
            //SET 3 CHALLENGE 20
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            GetLeastXORBiTrigramScoreProto GetLeastXORBiTrigramScore = GetLeastXORBiTrigramScoreGen(new Dictionary<string, double>
            { [" who"] = double.PositiveInfinity,  ["he m"] = double.PositiveInfinity,
                [" sce"] = double.PositiveInfinity, ["nery"] = double.PositiveInfinity
            });
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            byte[][] passResult = ReadChallengeFile("20.txt").Select((s) => Convert.FromBase64String(s)).ToArray();
            //for (int i = 0; i < passResult.Length; i++) Console.WriteLine(System.Text.Encoding.ASCII.GetString(passResult[i]));
            byte[][] lines = passResult.Select(s => crypt_ctr(0, key, s)).ToArray();
            int m = lines.Max(l => l.Length);
            byte[] b = new byte[m];
            int mn = lines.Min(l => l.Length);
            int keyLen; byte[] firstBytes;
            (keyLen, firstBytes) = breakRepXorKey(2, m, lines.Select(s => s.Take(mn).ToArray()).SelectMany(x => x).ToArray());
            if (keyLen != mn) return false;
            Array.Copy(firstBytes, 0, b, 0, mn);
            for (int i = mn; i < m; i++) {
                //maximum length of keystream to try to decode, but could take minimum as problem states to reduce logic
                byte[] analysis = lines.Where((bts) => bts.Length > i).Select((bts) => bts[i]).ToArray();
                Tuple<byte, double>[] vals = GetLeastXORCharacterScore(analysis);
                Tuple<byte, double> val = vals.First();
                if (i > 3 && (analysis.Length <= 13 || val.Item2 <= 80)) {
                    val = BigramHandler(GetLeastXORBiTrigramScore, val, lines, i, b, analysis);
                }
                b[i] = val.Item1;
            }
            for (int i = 0; i < lines.Length; i++) {
                if (System.Text.Encoding.ASCII.GetString(FixedXOR(lines[i], b.Take(lines[i].Length).ToArray())) != System.Text.Encoding.ASCII.GetString(passResult[i])) {
                    Console.WriteLine(System.Text.Encoding.ASCII.GetString(passResult[i]));
                    Console.WriteLine(System.Text.Encoding.ASCII.GetString(FixedXOR(lines[i], b.Take(lines[i].Length).ToArray())));
                }
            }
            return Enumerable.Range(0, lines.Length).All(i => System.Text.Encoding.ASCII.GetString(FixedXOR(lines[i], b.Take(lines[i].Length).ToArray())) == System.Text.Encoding.ASCII.GetString(passResult[i]));
        }
        static public bool Challenge21()
        {
            //SET 3 CHALLENGE 21
            MersenneTwister mt = new MersenneTwister();
            mt.Initialize(0);
            return mt.Extract() == 2357136044;
        }
        static public bool Challenge22()
        {
            //SET 3 CHALLENGE 22
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            MersenneTwister mt = new MersenneTwister();
            uint time = (uint)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            mt.Initialize(time);
            uint delay1 = time + 40 + (uint)GetNextRandom(rnd, 961); //simulate the delay only
            uint firstop = mt.Extract();
            while (true)
            {
                mt.Initialize(delay1);
                if (mt.Extract() == firstop) break;
                delay1--;
            }
            return time == delay1;
        }
        static public bool Challenge23()
        {
            //SET 3 CHALLENGE 23
            MersenneTwister mt = new MersenneTwister();
            mt.Initialize(0);
            uint[] vals = new uint[624];
            int ct;
            for (ct = 0; ct < 624; ct++) { vals[ct] = mt.Extract(); }
            MersenneTwister mtsplice = new MersenneTwister();
            mtsplice.Initialize(0);
            for (ct = 0; ct < 624; ct++) { vals[ct] = MersenneTwister.Unextract(vals[ct]); }
            mtsplice.Splice(vals);
            mt.Initialize(0);
            for (ct = 0; ct < 624; ct++) { if (mtsplice.Extract() != mt.Extract()) break; }
            return ct == 624;
        }
        static private byte[] MTCipher(ushort seed, byte[] input)
        {
            MersenneTwister mt = new MersenneTwister();
            mt.Initialize((uint)seed);
            return FixedXOR(Enumerable.Range(0, (input.Length >> 2) + (input.Length % 4 == 0 ? 0 : 1)).Select((i) => BitConverter.GetBytes(mt.Extract())).SelectMany((d) => d).Take(input.Length).ToArray(), input);
        }
        static public bool Challenge24()
        {
            //SET 3 CHALLENGE 24
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] b;
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            byte[] output;
            MersenneTwister mt = new MersenneTwister();
            b = new byte[GetNextRandom(rnd, 256)];
            rnd.GetBytes(b);
            b = Enumerable.Concat(b, Enumerable.Repeat((byte)'A', 14)).ToArray();
            uint firstop = (uint)(GetNextRandom(rnd, ushort.MaxValue)), time;
            output = MTCipher((ushort)firstop, b);
            for (time = 0; time <= ushort.MaxValue; time++) {
                mt.Initialize(time);
                if (new ByteArrayComparer().Equals(Enumerable.Repeat((byte)'A', 14).ToArray(), FixedXOR(Enumerable.Range(0, (output.Length >> 2) + (output.Length % 4 == 0 ? 0 : 1)).Select((i) => BitConverter.GetBytes(mt.Extract())).SelectMany((d) => d).Skip(output.Length - 14).Take(14).ToArray(), output.Skip(output.Length - 14).ToArray()))) break;
            }
            if (firstop != time) return false;
            time = (uint)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            mt.Initialize(time); //no difference really from challenge 22...
            firstop = mt.Extract();
            uint delay1 = time + 40 + (uint)GetNextRandom(rnd, 961);
            while (true)
            {
                mt.Initialize(delay1);
                if (mt.Extract() == firstop) break;
                delay1--;
            }
            return time == delay1;
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
        static byte[] edit(byte[] input, byte[] key, int offset, byte[] plaintext)
        {
            byte[] o = crypt_ctr(0, key, input);
            plaintext.CopyTo(o, offset);
            return crypt_ctr(0, key, o);
        }
        static public bool Challenge25()
        {
            //SET 4 CHALLENGE 25
            string passResult = Challenge6and7pass() + "\x04\x04\x04\x04";
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            byte[] b = ReadChallengeFile("25.txt").Select(s => Convert.FromBase64String(s)).SelectMany(d => d).ToArray();
            byte[] o = decrypt_ecb(System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE"), b);
            b = crypt_ctr(0, key, o);
            byte[] editValue = new byte[b.Length];
            rnd.GetBytes(editValue); //XOR plaintext which in simple 0 case with Enumerable.Repeat((byte)0, b.Length).ToArray() does not require an extra XOR
            return System.Text.Encoding.ASCII.GetString(FixedXOR(FixedXOR(edit(b, key, 0, editValue), b), editValue)) == passResult;
        }
        static private byte[] encryption_oracle_with_key_ctr(ulong nonce, byte[] key, byte[] prefix, string input, byte[] extra)
        {
            input = input.Replace(";", "%" + ((byte)';').ToString("X2")).Replace("=", "%" + ((byte)'=').ToString("X2"));
            return crypt_ctr(nonce, key, PKCS7Pad(Enumerable.Concat(Enumerable.Concat(prefix, System.Text.Encoding.ASCII.GetBytes(input)), extra).ToArray(), 16));
        }
        static public bool Challenge26()
        {
            //SET 4 CHALLENGE 26
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            string o = Encoding.ASCII.GetString(Enumerable.Repeat<byte>(32, 32).ToArray());
            byte[] b = encryption_oracle_with_key_ctr(0, key, Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata="), o, Encoding.ASCII.GetBytes(";comment2=%20like%20a%20pound%20of%20bacon"));
            if (Encoding.ASCII.GetString(crypt_ctr(0, key, b)).Contains(";admin=true;")) return false;
            return Encoding.ASCII.GetString(crypt_ctr(0, key, Enumerable.Concat(Enumerable.Concat(b.Take(32), FixedXOR(Encoding.ASCII.GetBytes(o.Take(16).ToArray()), FixedXOR(b.Skip(32).Take(16).ToArray(), Encoding.ASCII.GetBytes(";admin=true;    ")))), b.Skip(48)).ToArray())).Contains(";admin=true;");
        }
        static public bool Challenge27()
        {
            //SET 4 CHALLENGE 27
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];
            rnd.GetBytes(key);
            byte[] b = encryption_oracle_with_key_cbc(key, key, Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata="), Encoding.ASCII.GetString(Enumerable.Repeat<byte>(32, 32).ToArray()), Encoding.ASCII.GetBytes(";comment2=%20like%20a%20pound%20of%20bacon"));
            byte[] o = decrypt_cbc(key, key, b.Take(16).Concat(Enumerable.Repeat((byte)0, 16).Concat(b.Take(16))).ToArray());
            return key.SequenceEqual(FixedXOR(o.Take(16).ToArray(), o.Skip(32).Take(16).ToArray()));
        }
        static public bool Challenge28()
        {
            //SET 4 CHALLENGE 28
            RandomNumberGenerator rnd = RandomNumberGenerator.Create();
            byte[] key = new byte[16];
            SHA1Context sc = new SHA1Context();
            SHA1_Algo.SHA1Reset(sc);
            key = System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            byte[] b = System.Text.Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
            SHA1_Algo.SHA1Input(sc, key.Concat(b).ToArray());
            byte[] o = new Byte[SHA1_Algo.SHA1HashSize];
            SHA1_Algo.SHA1Result(sc, o);
            return HexEncode(o) == "08cb9f974e3141954f5b09a648fac55f20427d57";
        }
        static public bool Challenge29()
        {
            //SET 4 CHALLENGE 29
            byte[] key = System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            byte[] o = new byte[SHA1_Algo.SHA1HashSize];
            byte[] b = System.Text.Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
            SHA1Context sc = new SHA1Context();
            SHA1_Algo.SHA1Reset(sc);
            SHA1_Algo.SHA1Input(sc, key.Concat(b).ToArray());
            SHA1_Algo.SHA1Result(sc, o);
            byte[] pad = SHA1_Algo.SHA1Pad(key.Concat(b).ToArray());
            int blocks = pad.Length / 64;
            SHA1_Algo.SHA1ResetFromHashLen(sc, o, blocks);
            byte[] extra = System.Text.Encoding.ASCII.GetBytes(";admin=true");
            SHA1_Algo.SHA1Input(sc, extra);
            byte[] md = new byte[SHA1_Algo.SHA1HashSize];
            SHA1_Algo.SHA1Result(sc, md);
            SHA1_Algo.SHA1Reset(sc);
            //blocks of 64 immediately processed
            //last block >= 56 = [block + 0x80 + 0x00 .. 0x00] [0x00 .. 0x00 64-bit-bitlen-big-endian]
            //last block < 56 = [block + 0x80 + 0x00 .. 0x00 64-bit-bitlen-big-endian]
            SHA1_Algo.SHA1Input(sc, pad.Concat(extra).ToArray());
            SHA1_Algo.SHA1Result(sc, o);
            return o.SequenceEqual(md);
        }
        static public bool Challenge30()
        {
            //SET 4 CHALLENGE 30
            //padding nearly identical to SHA1
            byte[] key = System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            byte[] b = System.Text.Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
            byte[] extra = System.Text.Encoding.ASCII.GetBytes(";admin=true");
            MD4 hash = new MD4();
            byte[] o = hash.ComputeHash(key.Concat(b).ToArray());
            byte[] pad = MD4.MD4Pad(key.Concat(b).ToArray());
            hash.InitFromHashLen(o, pad.Length / 64);
            byte[] md = hash.ComputeHash(extra);
            o = hash.ComputeHash(pad.Concat(extra).ToArray());
            Console.WriteLine(HexEncode(md) + " " + HexEncode(o));
            return o.SequenceEqual(md);
        }
        static public bool Challenge31()
        {
            //SET 4 CHALLENGE 31
            //46b4ec586117154dacd49d664e5d63fdc88efb51
            byte[] key = breakurlkey(50, 1);
            openurl("http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51", 0); //initialize/precompile
            Console.WriteLine("4.31 Recovered key: " + HexEncode(key));
            Console.WriteLine("HMAC-SHA1 in URL from key: foo and text: bar" + HexEncode(hmac(System.Text.Encoding.ASCII.GetBytes("foo"), System.Text.Encoding.ASCII.GetBytes("bar"))));
            return false;
        }
        static public bool Challenge32()
        {
            //SET 4 CHALLENGE 32
            byte[] key = breakurlkey(5, 5);
            Console.WriteLine("4.32 Recovered key: " + HexEncode(key));
            return false;
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
        static public bool Challenge33()
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
            return false;
        }
        static public bool Challenge34()
        {
            //SET 5 CHALLENGE 34
            DHClient Alice = new DHClient();
            DHClient Bob = new DHClient();
            Console.WriteLine("5.34 Message exchange successful: " + Alice.SendDH(null, Bob));
            ManInTheMiddle Chuck = new ManInTheMiddle();
            Console.WriteLine("Message exchange injection and snooping successful: " + Alice.SendDH(Chuck, Bob));
            return false;
        }
        static public bool Challenge35()
        {
            //SET 5 CHALLENGE 35
            //when g=1 or g=p-1, and we set A=1 then the secret will always be 1
            //when g=p, we set A=p and the secret will always be 0 similar to the previous break
            //if not setting A, the protocol will abort because the initiator has s=A or s=1, but the receiver has s=A^b so cannot decrypt the first message
            //at best by setting s=A or s=1, the first message of initiator can be decrypted before the abort occurs
            DHClient Alice = new DHClient();
            DHClient Bob = new DHClient();
            ManInTheMiddle Chuck = new ManInTheMiddle();
            Chuck.attackver = 1;
            Console.WriteLine("5.35 With g=1 injection and snooping successful: " + Alice.SendParameter(Chuck, Bob));
            Chuck.attackver = 2;
            Console.WriteLine("With g=p injection and snooping successful: " + Alice.SendParameter(Chuck, Bob));
            Chuck.attackver = 3; //8 tries to prove that it works in the other 25% of cases
            Console.WriteLine("With g=p-1 injection and snooping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snooping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snooping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snooping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snooping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snooping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snooping successful: " + Alice.SendParameter(Chuck, Bob));
            Console.WriteLine("With g=p-1 injection and snooping successful: " + Alice.SendParameter(Chuck, Bob));
            return false;
        }
        static public bool Challenge36()
        {
            //SET 5 CHALLENGE 36
            DHClient Alice = new DHClient();
            DHClient Bob = new DHClient();
            Console.WriteLine("5.36 Secure Remote Password DH succeeds: " + Alice.SendEmailDH(null, Bob));
            return false;
        }
        static public bool Challenge37()
        {
            //SET 5 CHALLENGE 37
            BigInteger _p = BigInteger.Parse("00" + "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
            DHClient Alice = new DHClient();
            DHClient Bob = new DHClient();
            Console.WriteLine("5.37 SRP with 0 public exponent succeeds: " + Alice.SendEmailDHBreakKey(Bob, 0)); //p, p^2, ..., p^n
            Console.WriteLine("n succeeds: " + Alice.SendEmailDHBreakKey(Bob, _p));
            Console.WriteLine("n^2 succeeds: " + Alice.SendEmailDHBreakKey(Bob, BigInteger.ModPow(_p, 2, _p)));
            return false;
        }
        static public bool Challenge38()
        {
            //SET 5 CHALLENGE 38
            DHClient Alice = new DHClient();
            DHClient Bob = new DHClient();
            ManInTheMiddle Chuck = new ManInTheMiddle();
            Console.WriteLine("5.38 Simplified SRP succeeds: " + Alice.SendEmailDH(null, Bob, true));
            Console.WriteLine("With MITM dictionary attack salt=0, u=1, b=1, B=g finds password: " + Alice.SendEmailDH(Chuck, Bob, true));
            return false;
        }
        static public bool Challenge39()
        {
            //SET 5 CHALLENGE 39
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            BigInteger _p, _q;
            BigInteger et;
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
            BigInteger n = _p * _q;
            BigInteger d = modInverse(3, et);
            BigInteger m = 42;
            BigInteger c = BigInteger.ModPow(m, 3, n);
            Console.WriteLine("5.39 RSA decrypts to 42: " + (42 == BigInteger.ModPow(c, d, n)));
            return false;
        }
        static public bool Challenge40()
        {
            //SET 5 CHALLENGE 40
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            BigInteger _p, _q, et, m = 42;
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
            BigInteger n = _p * _q;
            BigInteger c = BigInteger.ModPow(m, 3, n);
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
            BigInteger n1 = _p * _q;
            BigInteger c1 = BigInteger.ModPow(m, 3, n1);
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
            BigInteger n2 = _p * _q;
            BigInteger c2 = BigInteger.ModPow(m, 3, n2);
            BigInteger result = BigInteger.Remainder(c * n1 * n2 * modInverse(n1 * n2, n) + c1 * n * n2 * modInverse(n * n2, n1) + c2 * n * n1 * modInverse(n * n1, n2), n * n1 * n2);
            Console.WriteLine("5.40 Integer cube root result: " + icbrt2(result));
            return false;
        }

        static BigInteger GetPivotRandom(RandomNumberGenerator rng, int BitSize)
        {
            byte[] r = new byte[(BitSize >> 3) + 1];
            rng.GetBytes(r);
            r[r.Length - 1] &= (byte)((1 << (BitSize % 8)) - 1); //make sure it wont be interpreted as negative in little-endian order
            r[r.Length - 1 - (BitSize % 8 == 0 ? 1 : 0)] |= (byte)(1 << ((BitSize - 1) % 8)); //always set bitsize-th bit
            return new BigInteger(r);
        }
        static byte[] PadToSize(byte[] arr, int size)
        {
            return (arr.Length >= size ? arr.Skip(arr.Length - size).ToArray() : Enumerable.Repeat((byte)0, size - arr.Length).Concat(arr).ToArray());
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
        static public bool Challenge41()
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
            return false;
        }
        static public bool Challenge42()
        {
            //SET 6 CHALLENGE 42
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
            BigInteger m = BytesToBigInt(new byte[] { 0 }.Concat(ASN1_PKCS1_SHA1.Concat(hf.ComputeHash(ptext))).ToArray());
            // PKCS#1 00 01 FF ... FF 00
            m = BigInteger.ModPow(BytesToBigInt(new byte[] { 0, 1 }.Concat(Enumerable.Repeat((byte)0xFF, 384 - 2 - 36)).ToArray()) * BigInteger.Pow(2, 288) + m, d, n); //legitimate signature
            BigInteger signature = BigInteger.ModPow(m, 3, n); // = BigInteger.Pow(m, 3);
            sig = PadToSize(BigIntToBytes(signature), 384);
            if (sig[0] == 0 && sig[1] == 1)
            {
                int i;
                for (i = 2; i < sig.Length; i++)
                {
                    if (sig[i] != 0xFF) break;
                }
                if (sig[i] == 0 && new ByteArrayComparer().Equals(ASN1_PKCS1_SHA1, sig.Skip(i + 1).Take(15).ToArray()))
                {
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
            if (sig[0] == 0 && sig[1] == 1)
            {
                int i;
                for (i = 2; i < sig.Length; i++)
                {
                    if (sig[i] != 0xFF) break;
                }
                //i == 384 - 36 check would avoid the break...
                if (sig[i] == 0 && new ByteArrayComparer().Equals(ASN1_PKCS1_SHA1, sig.Skip(i + 1).Take(15).ToArray()))
                {
                    Console.WriteLine(new ByteArrayComparer().Equals(sig.Skip(i + 16).Take(20).ToArray(), hf.ComputeHash(ptext)));
                }
            }
            return false;
        }
        static public bool Challenge43()
        {
            //SET 6 CHALLENGE 43
            SHA1 hf = SHA1.Create();
            BigInteger _p, _q;
            _p = BigInteger.Parse("00" + "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", System.Globalization.NumberStyles.HexNumber);
            _q = BigInteger.Parse("00" + "f4f47f05794b256174bba6e9b396a7707e563c5b", System.Globalization.NumberStyles.HexNumber);
            BigInteger g = BigInteger.Parse("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", System.Globalization.NumberStyles.HexNumber);
            BigInteger y = BigInteger.Parse("00" + "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", System.Globalization.NumberStyles.HexNumber);
            byte[] b = System.Text.Encoding.ASCII.GetBytes("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n");
            Console.WriteLine(new ByteArrayComparer().Equals(hf.ComputeHash(b), HexDecode("d2d0714f014a9784047eaeccf956520045c45265")));
            BigInteger r = BigInteger.Parse("548099063082341131477253921760299949438196259240");
            BigInteger s = BigInteger.Parse("857042759984254168557880549501802188789837994940");
            BigInteger realx = BigInteger.Parse("0954edd5e0afe5542a4adf012611a91912a3ec16", System.Globalization.NumberStyles.HexNumber);
            BigInteger x;
            BigInteger mhsh = BytesToBigInt(hf.ComputeHash(b));
            BigInteger rinv = modInverse(r, _q);
            for (int _k = 16574; _k <= 1 << 16; _k++)
            {
                x = posRemainder((s * _k - mhsh) * rinv, _q);
                //x = 499e6554da7afd18096df79f123e6bd17328fb15 k=16575
                if (BigInteger.ModPow(g, x, _p) == y)
                {
                    Console.WriteLine("Found x: " + HexEncode(BigIntToBytes(x)) + " k: " + _k.ToString());
                    if (BytesToBigInt(hf.ComputeHash(System.Text.Encoding.ASCII.GetBytes(HexEncode(BigIntToBytes(x))))) == realx)
                    {
                        Console.WriteLine("Matches hash");
                    }
                    if (r == BigInteger.Remainder(BigInteger.ModPow(g, _k, _p), _q) && s == BigInteger.Remainder(modInverse(_k, _q) * (BytesToBigInt(hf.ComputeHash(b)) + x * r), _q))
                    {
                        Console.WriteLine("Matches r and s");
                    }
                    break;
                }
            }
            return false;
        }
        static public bool Challenge44()
        {
            //SET 6 CHALLENGE 44
            SHA1 hf = SHA1.Create();
            BigInteger _p, _q;
            _p = BigInteger.Parse("00" + "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", System.Globalization.NumberStyles.HexNumber);
            _q = BigInteger.Parse("00" + "f4f47f05794b256174bba6e9b396a7707e563c5b", System.Globalization.NumberStyles.HexNumber);
            BigInteger g = BigInteger.Parse("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", System.Globalization.NumberStyles.HexNumber);
            BigInteger y = BigInteger.Parse("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", System.Globalization.NumberStyles.HexNumber);
            BigInteger realx = BigInteger.Parse("00" + "ca8f6f7c66fa362d40760d135b763eb8527d3d52", System.Globalization.NumberStyles.HexNumber);
            string[] strs = System.IO.File.ReadAllLines("../../44.txt");
            BigInteger k;
            for (int i = 0; i < strs.Length; i += 4)
            { //(n^2+n)/2 possibilities to try
                for (int j = i + 4; j < strs.Length; j += 4)
                {
                    k = posRemainder(posRemainder(BigInteger.Parse("00" + strs[i + 3].Remove(0, 3), System.Globalization.NumberStyles.HexNumber) - BigInteger.Parse("00" + strs[j + 3].Remove(0, 3), System.Globalization.NumberStyles.HexNumber), _q) *
                        modInverse(posRemainder(BigInteger.Parse(strs[i + 1].Remove(0, 3)) - BigInteger.Parse(strs[j + 1].Remove(0, 3)), _q), _q), _q);
                    BigInteger x = posRemainder((BigInteger.Parse(strs[j + 1].Remove(0, 3)) * k - BytesToBigInt(hf.ComputeHash(System.Text.Encoding.ASCII.GetBytes(strs[j].Remove(0, 5))))) * modInverse(BigInteger.Parse(strs[j + 2].Remove(0, 3)), _q), _q);
                    if (BigInteger.ModPow(g, x, _p) == y)
                    {
                        Console.WriteLine("Found x: " + HexEncode(BigIntToBytes(x)) + " k: " + HexEncode(BigIntToBytes(k)) + " entries: " + (i / 4).ToString() + ", " + (j / 4).ToString());
                        if (BytesToBigInt(hf.ComputeHash(System.Text.Encoding.ASCII.GetBytes(HexEncode(BigIntToBytes(x))))) == realx)
                        {
                            Console.WriteLine("Matches hash");
                        }
                    }
                }
            }
            return false;
        }
        static public bool Challenge45()
        {
            //SET 6 CHALLENGE 45
            SHA1 hf = SHA1.Create();
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] b = System.Text.Encoding.ASCII.GetBytes("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n");
            BigInteger _p, _q;
            _p = BigInteger.Parse("00" + "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", System.Globalization.NumberStyles.HexNumber);
            _q = BigInteger.Parse("00" + "f4f47f05794b256174bba6e9b396a7707e563c5b", System.Globalization.NumberStyles.HexNumber);
            BigInteger g, k, y, x, r, s;
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
            return false;
        }
        static public bool Challenge46()
        {
            //SET 6 CHALLENGE 46
            BigInteger _p, _q, et, n, d, m, c;
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
            BigInteger cprime = c;
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
            return false;
        }
        static public bool Challenge47()
        {
            //SET 6 CHALLENGE 47
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            BigInteger _p, _q, et, n, d, c;
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

            byte[] b = System.Text.Encoding.ASCII.GetBytes("kick it, CC");
            byte[] pad = new byte[GetBitSize(n) / 8 - b.Length - 1 - 2];
            rng.GetBytes(pad);
            c = BigInteger.ModPow(BytesToBigInt(new byte[] { 0, 2 }.Concat(pad).Concat(new byte[] { 0 }).Concat(b).ToArray()), 3, n);
            BigInteger result = BleichenBacherPaddingOracle(rng, n, 3, d, c);
            Console.WriteLine("Result: " + HexEncode(BigIntToBytes(result)) + " matches: " + (result == BigInteger.ModPow(c, d, n)));
            return false;
        }
        static public bool Challenge48()
        {
            //SET 6 CHALLENGE 48
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            BigInteger _p, _q, et, n, d, c, result;
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
            
            byte[] b = System.Text.Encoding.ASCII.GetBytes("kick it, CC");
            byte[] pad = new byte[GetBitSize(n) / 8 - b.Length - 1 - 2];
            rng.GetBytes(pad);
            c = BigInteger.ModPow(BytesToBigInt(new byte[] { 0, 2 }.Concat(pad).Concat(new byte[] { 0 }).Concat(b).ToArray()), 3, n);
            result = BleichenBacherPaddingOracle(rng, n, 3, d, c);
            Console.WriteLine("Result: " + HexEncode(BigIntToBytes(result)) + " matches: " + (result == BigInteger.ModPow(c, d, n)));
            return false;
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
        static public bool Challenge49()
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
            return false;
        }
        static public bool Challenge50()
        {
            //SET 7 CHALLENGE 50
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] iv = new byte[16];
            rng.GetBytes(iv);
            byte[] key = System.Text.Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            //16 encrypted bytes before the cbcmac xored with the plaintext are the ones needed to correctly forge this
            byte[] cbcmac = encrypt_cbc(iv, key, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("alert('MZA who was that?');\n"), 16)).Skip(16 * (("alert('MZA who was that?');\n".Length - 1) / 16)).Take(16).ToArray();
            Console.WriteLine("7.50 Verify CBC-MAC expected value: " + (new ByteArrayComparer().Equals(cbcmac, HexDecode("296b8d7cb78a243dda4d0a61d33bbdd1"))));
            cbcmac = encrypt_cbc(iv, key, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("alert('MZA who was that?');\n"), 16)).Skip(16 * (("alert('MZA who was that?');\n".Length - 1) / 16) - 16).Take(16).ToArray();
            string str = "alert('Ayo, the Wu is back!');//                ";
            //     0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF;
            //binary 0 and new line should be only characters we need to watch out for if we use a comment structure
            //one approach is to do length extension and append original message but commented out - not general for multiline so could also return or play other javascript abort game
            //yet better since we have key and hence decryption oracle access, other approach is to decrypt the padding xored with desired output
            //the spirit of this exercise is to show that hash functions are one way and symmetric encryption is not
            byte[] attackmessage = System.Text.Encoding.ASCII.GetBytes(str).Concat(FixedXOR(encrypt_cbc(iv, key, System.Text.Encoding.ASCII.GetBytes(str)).Skip(16 * ((str.Length - 1) / 16)).ToArray(), decrypt_cbc(iv, key, FixedXOR(Enumerable.Repeat((byte)16, 16).ToArray(), FixedXOR(cbcmac, PKCS7Pad(System.Text.Encoding.ASCII.GetBytes("alert('MZA who was that?');\n"), 16).Skip(16 * (("alert('MZA who was that?');\n".Length - 1) / 16)).Take(16).ToArray()))))).ToArray();
            Console.WriteLine("Forged javascript: \"" + System.Text.Encoding.ASCII.GetString(attackmessage) + "\" same CBC-MAC: " + new ByteArrayComparer().Equals(encrypt_cbc(iv, key, PKCS7Pad(attackmessage, 16)).Skip(16 * ((PKCS7Pad(attackmessage, 16).Length - 1) / 16)).ToArray(), HexDecode("296b8d7cb78a243dda4d0a61d33bbdd1")));
            //Extra Credit: Write JavaScript code that downloads your file, checks its CBC-MAC, and inserts it into the DOM iff it matches the expected hash.
            return false;
        }
        static public bool Challenge51()
        {
            //SET 7 CHALLENGE 51
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            List<string> Candidates = new List<String>(); //queue
            //base 64 character set
            Candidates.Add("sessionid=");
            int baselen = CompressionLengthOracle(Candidates[0], false);
            string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            do
            {
                for (int i = 0; i < charset.Length; i++)
                {
                    //it will eventually grow up to one byte reasonably with a short session key and though could get more sophisticated with when that happens, no need in this case
                    if (CompressionLengthOracle(Candidates[0] + charset[i], false) <= baselen + 1)
                    {
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
            do
            {
                for (int i = 0; i < charset.Length; i++)
                {
                    //it will eventually grow up to one byte reasonably with a short session key and though could get more sophisticated with when that happens, no need in this case
                    if (CompressionLengthOracle(Candidates[0] + charset[i], true) <= baselen + 1)
                    {
                        Candidates.Add(Candidates[0] + charset[i]);
                    }
                    //could consider equal sign positions for extra efficiency as they are only at the end
                    //if % 3 = 1 consider '='
                    //if % 3 = 2 && [-1] == '=' consider '='
                }
                if (Candidates.Count == 1)
                {
                    Candidates[0] = Candidates[0].Remove(0, 1);
                    for (int i = 0; i < charset.Length; i++)
                    {
                        for (int j = 0; j < charset.Length; j++)
                        {
                            if (j == i && j == charset.Length - 1) break; if (j == i) j++;
                            if (CompressionLengthOracle(Candidates[0] + charset[i] + charset[j], true) <= baselen + 1)
                            {
                                Candidates.Add(Candidates[0] + charset[i] + charset[j]);
                            }
                        }
                    }
                    if (Candidates.Count == 1) break;
                }
                Candidates.RemoveAt(0);
            } while (true);
            Console.WriteLine("Recovered plaintext from compression oracle with padding: " + Candidates[0] + " " + System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(Candidates[0].Substring(Candidates[0].IndexOf("sessionid=") + "sessionid=".Length))));
            return false;
        }
        static public bool Challenge52()
        {
            //SET 7 CHALLENGE 52
            byte[][] cols = fcollision(6); //2^6=64 collisions
            int c;
            byte[] h = MD(cols[0], 16);
            for (c = 1; c < cols.Length; c++)
            {
                if (!(new ByteArrayComparer().Equals(h, MD(cols[c], 16)))) break;
            }
            Console.WriteLine("7.52 Number of collisions generated: " + cols.Length.ToString() + " all verified: " + (c == cols.Length));
            int n;
            Dictionary<byte[], int> map;
            h = MD(new byte[] { 0, 0 }, 20);
            //50% chance after 2^10 but it could theoretically go to any length even past 2^20 depending on how evenly distributed the hash function is...since AES is good, unlikely concern
            for (n = 10; true; n++)
            {
                cols = fcollision(n);
                h = cols[0];
                map = new Dictionary<byte[], int>(new ByteArrayComparer());
                for (c = 0; c < cols.Length; c++)
                {
                    byte[] newh = MD(cols[c], 20);
                    if (map.ContainsKey(newh))
                    {
                        Console.WriteLine("Colliding values and their f||g hash output: " + HexEncode(cols[c]) + ": " + HexEncode(MD(cols[c], 16)) + HexEncode(newh) + " " + HexEncode(cols[map[newh]]) + ": " + HexEncode(MD(cols[map[newh]], 16)) + HexEncode(newh));
                        break;
                    }
                    else
                    {
                        map.Add(newh, c);
                    }
                }
                if (c != cols.Length) break;
            }
            Console.WriteLine("Number of collisions in f to find collision in g as a power of 2: " + n);
            return false;
        }
        static public bool Challenge53()
        {
            //SET 7 CHALLENGE 53
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] kblock = new byte[16 * 8]; //any message length between k and k+2^k-1 is possible...e.g. 2-5, 3-10, 4-19, 5-36
            rng.GetBytes(kblock);
            byte[][][] expmsg = kcollisions(3); //find k s.t.: k << 3 > ((kblock.Length + 15) / 16)
            Dictionary<byte[], int> map = new Dictionary<byte[], int>(new ByteArrayComparer());
            for (int i = 0; i < kblock.Length / 16; i++)
            {
                byte[] newh = MD(kblock.Take(i * 16).ToArray(), 16);
                if (map.ContainsKey(newh)) map[newh] = i; //use last index on this rare coincidence to make this deterministic
                else map.Add(newh, i);
            }
            BigInteger bridge;
            byte[] inith = MD(expmsg.Reverse().SelectMany((b) => b[0].Concat(Enumerable.Repeat((byte)0, 16)).Take(16).ToArray()).ToArray(), 16);
            int blocknum;
            for (bridge = 0; true; bridge++)
            {
                if (map.ContainsKey(PrehMD(bridge == 0 ? new byte[] { 0 } : BigIntToBytes(bridge).ToArray(), 16, inith)))
                {
                    blocknum = map[PrehMD(bridge == 0 ? new byte[] { 0 } : BigIntToBytes(bridge).ToArray(), 16, inith)];
                    if (blocknum > expmsg.Length) break;
                }
            }
            //already have 1, so 2+4+8+...
            byte[] forgery = new byte[kblock.Length];
            for (int i = expmsg.Length - 1; i >= 0; i--)
            {
                Array.Copy(expmsg[i][((blocknum - 1 - expmsg.Length) & (1 << i)) != 0 ? 1 : 0].Concat(Enumerable.Repeat((byte)0, 16)).Take((((blocknum - 1 - expmsg.Length) & (1 << i)) != 0 ? (1 << i) : 0) * 16 + 16).ToArray(), 0, forgery, (((blocknum - 1 - expmsg.Length) & ((1 << expmsg.Length) - (1 << (i + 1)))) + (expmsg.Length - 1 - i)) * 16, (((blocknum - 1 - expmsg.Length) & (1 << i)) != 0 ? (1 << i) : 0) * 16 + 16);
            }
            Array.Copy(BigIntToBytes(bridge).Concat(Enumerable.Repeat((byte)0, 16)).Take(16).ToArray(), 0, forgery, (blocknum - 1) * 16, 16);
            Array.Copy(kblock, blocknum * 16, forgery, blocknum * 16, kblock.Length - blocknum * 16);
            Console.WriteLine("Forgery hash is identical: " + (new ByteArrayComparer().Equals(MD(kblock, 16), MD(forgery, 16))));
            return false;
        }
        static public bool Challenge54()
        {
            //SET 7 CHALLENGE 54
            byte[][] cols = ktreecollisions(8);
            string str = String.Empty;
            for (int i = 0; i < 2430; i++)
            { //simple formula as a substitute for the actual results
                str += i.ToString() + ": " + (i % 9) + "-" + ((i + 1) % 9) + "\n";
            }
            byte[] forgery = System.Text.Encoding.ASCII.GetBytes(str);
            if ((forgery.Length % 16) != 0) forgery = forgery.Concat(Enumerable.Repeat((byte)0, 16 - (forgery.Length % 16))).ToArray();
            byte[] inith = MD(forgery, 16);
            Dictionary<byte[], int> map = new Dictionary<byte[], int>(new ByteArrayComparer());
            for (int i = 0; i < (1 << 8); i++)
            {
                map[cols[i]] = i;
            }
            BigInteger bridge;
            for (bridge = 0; true; bridge++)
            {
                if (map.ContainsKey(PrehMD(bridge == 0 ? new byte[] { 0 } : BigIntToBytes(bridge).ToArray(), 16, inith))) break;
            }
            forgery = forgery.Concat(bridge == 0 ? new byte[] { 0 } : BigIntToBytes(bridge)).ToArray();
            if ((forgery.Length % 16) != 0) forgery = forgery.Concat(Enumerable.Repeat((byte)0, 16 - (forgery.Length % 16))).ToArray();
            int blocknum = (1 << 8);
            int c = map[PrehMD(bridge == 0 ? new byte[] { 0 } : BigIntToBytes(bridge).ToArray(), 16, inith)];
            for (int i = 7; i >= 0; i--)
            {
                forgery = forgery.Concat(cols[blocknum + c]).ToArray();
                if ((forgery.Length % 16) != 0) forgery = forgery.Concat(Enumerable.Repeat((byte)0, 16 - (forgery.Length % 16))).ToArray();
                blocknum += (1 << (i + 1));
                c >>= 1;
            }
            Console.WriteLine("Forged prediction hash is identical to prior prediction hash: " + (new ByteArrayComparer().Equals(cols[cols.Length - 1], MD(forgery, 16))));
            return false;
        }
        static public bool Challenge55()
        {
            //SET 7 CHALLENGE 55
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] m1 = (new uint[] { 0x4d7a9c83, 0x56cb927a, 0xb9d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f, 0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8, 0x45dd8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9 }).SelectMany((d) => BitConverter.GetBytes(d)).ToArray();
            byte[] m1prime = (new uint[] { 0x4d7a9c83, 0xd6cb927a, 0x29d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f, 0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8, 0x45dc8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9 }).SelectMany((d) => BitConverter.GetBytes(d)).ToArray();
            byte[] m2 = (new uint[] { 0x4d7a9c83, 0x56cb927a, 0xb9d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f, 0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8, 0x45dd8e31, 0x97e31fe5, 0xf713c240, 0xa7b8cf69 }).SelectMany((d) => BitConverter.GetBytes(d)).ToArray();
            byte[] m2prime = (new uint[] { 0x4d7a9c83, 0xd6cb927a, 0x29d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f, 0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8, 0x45dc8e31, 0x97e31fe5, 0xf713c240, 0xa7b8cf69 }).SelectMany((d) => BitConverter.GetBytes(d)).ToArray();
            byte[] h1 = (new uint[] { 0x5f5c1a0d, 0x71b36046, 0x1b5435da, 0x9b0d807a }).SelectMany((d) => BitConverter.GetBytes(d)).ToArray();
            byte[] hstar1 = (new uint[] { 0x4d7e6a1d, 0xefa93d2d, 0xde05b45d, 0x864c429b }).SelectMany((d) => BitConverter.GetBytes(d)).ToArray();
            byte[] h2 = (new uint[] { 0xe0f76122, 0xc429c56c, 0xebb5e256, 0xb809793 }).SelectMany((d) => BitConverter.GetBytes(d)).ToArray();
            byte[] hstar2 = (new uint[] { 0xc6f3b3fe, 0x1f4833e0, 0x697340fb, 0x214fb9ea }).SelectMany((d) => BitConverter.GetBytes(d)).ToArray();
            MD4 md4 = new MD4();
            md4._dontPad = true; //unpadded little-endian
            //without multi-step modification, the probability is 2^-25
            if (!MD4.ApplyWangDifferential(m1).SequenceEqual(m1prime)) return false;
            if (!md4.ComputeHash(m1).SequenceEqual(md4.ComputeHash(m1prime))) return false;
            if (!md4.ComputeHash(m1).SequenceEqual(h1)) return false;
            if (!MD4.ApplyWangDifferential(m2).SequenceEqual(m2prime)) return false;
            if (!md4.ComputeHash(m2).SequenceEqual(md4.ComputeHash(m2prime))) return false;
            if (!md4.ComputeHash(m2).SequenceEqual(h2)) return false;
            md4._dontPad = false;
            md4._bigEndian = true;
            if (!md4.ComputeHash(m1).SequenceEqual(hstar1)) return false; //padded big-endian
            if (!md4.ComputeHash(m1prime).SequenceEqual(hstar1)) return false;
            if (!md4.ComputeHash(m2).SequenceEqual(hstar2)) return false;
            if (!md4.ComputeHash(m2prime).SequenceEqual(hstar2)) return false;
            byte[] mRandom = BigInteger.Parse("24ce9d37de4dfca0a3b88fc39c9f9e5c92ee86ada2c9e8b088f3a020c5368a690e503cc80c2368f978ff57bf21a1762ad018afb8daa431e9308bf382806a18a1", System.Globalization.NumberStyles.HexNumber).ToByteArray().Reverse().ToArray();
            mRandom = Enumerable.Range(0, mRandom.Length >> 2).Select(i => mRandom.Skip(i * 4).Take(4).Reverse().ToArray()).SelectMany(x => x).ToArray();
            byte[] m1Naito = BigInteger.Parse("368b9d377e2dfc60b5b88fcb0c8fbe5601a6662d9ecc3929aa35aabf887f929f2740a2c8c8c12039bbb401bdc1983331e45e1f61c150d565ee27d04af1dfec4c", System.Globalization.NumberStyles.HexNumber).ToByteArray().Reverse().ToArray();
            m1Naito = Enumerable.Range(0, m1Naito.Length >> 2).Select(i => m1Naito.Skip(i * 4).Take(4).Reverse().ToArray()).SelectMany(x => x).ToArray();
            byte[] m1primeNaito = BigInteger.Parse("368b9d37fe2dfc6025b88fcb0c8fbe5601a6662d9ecc3929aa35aabf887f929f2740a2c8c8c12039bbb401bdc1983331e45d1f61c150d565ee27d04af1dfec4c", System.Globalization.NumberStyles.HexNumber).ToByteArray().Reverse().ToArray();
            m1primeNaito = Enumerable.Range(0, m1primeNaito.Length >> 2).Select(i => m1primeNaito.Skip(i * 4).Take(4).Reverse().ToArray()).SelectMany(x => x).ToArray();
            byte[] hNaito = BigInteger.Parse(new string("26a280327c3068532de33b679d022e59".Reverse().ToArray()), System.Globalization.NumberStyles.HexNumber).ToByteArray();
            hNaito = Enumerable.Range(0, hNaito.Length >> 2).Select(i => hNaito.Skip(i * 4).Take(4).Reverse().ToArray()).SelectMany(x => x).ToArray();
            if (!MD4.ApplyWangDifferential(m1Naito).SequenceEqual(m1primeNaito)) return false;
            md4._dontPad = true;
            if (!md4.ComputeHash(m1Naito).SequenceEqual(hNaito)) return false;
            //Console.WriteLine(HexEncode(MD4.WangsAttack(mRandom, true, true)));
            byte[] forgery;
            byte[] key = new byte[64];
            int n, total = 0;
            md4._bigEndian = false;
            for (int i = 0; i < 50000; i++) {
                n = 0;
                byte[] check;
                do {
                    n++;
                    rng.GetBytes(key);
                    byte[] save = key;
                    check = MD4.WangsAttack(key, true, false);
                    if (check != null) key = check;
                    forgery = (check != null) ? MD4.ApplyWangDifferential(key) : null;
                    if (check != null && !(md4.ComputeHash(key).SequenceEqual(md4.ComputeHash(forgery)))) {
                        throw new ArgumentException();
                    }
                } while (check == null || !(md4.ComputeHash(key).SequenceEqual(md4.ComputeHash(forgery))));
                //correct algorithm will have n == 2^2 = 4 up to n == 2^6 = 64 average tries
                //Naito exactly computed this as 1/(3/4*7/8*1/2*(1/2)^2*(1/2)^2) which yields 48.76 average tries, but he did not consider Wang's m[14] and m[15] round 3 search strategy
                //therefore truly this should be 1/(3/4*7/8*1/2*(1/2)^2) which yields 12.19 average tries
                //since we search out the missing conditions, and the 7/8 seems to be 1 and the Naito has no explanation
                //if only one round of Wang's attack probability matches 1/(3/4*1/2*1/16)=42.6666
                //1/(1/(1-1/8)-1)=7 is expected number of rounds if probability 1/8 per round...
                //1/(3/4*1/2)*7=18.666
                //Console.WriteLine("Wang et al. paper attack: " + n + " tries " + HexEncode(key) + " " + HexEncode(forgery) + " -> " + HexEncode(md4.ComputeHash(key)));
                total += n;
            }
            Console.WriteLine("Wang et al. paper attack: " + total + " tries to find 50000 collisions with probability " + ((double)total / 50000));
            total = 0;
            for (int i = 0; i < 5000; i++)
            {
                n = 0;
                do
                {
                    n++;
                    rng.GetBytes(key);
                    key = MD4.WangsAttack(key, true, true);
                    forgery = MD4.ApplyWangDifferential(key);
                    if (!(md4.ComputeHash(key).SequenceEqual(md4.ComputeHash(forgery)))) {
                        throw new ArgumentException();
                    }
                } while (!(md4.ComputeHash(key).SequenceEqual(md4.ComputeHash(forgery))));
                //correct algorithm will have n == 1 almost always precisely 1-(1-1/4)^(2^19)=per Wolfram Alpha 1.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000...
                //Console.WriteLine("Naito et al. improvement: " + n + " tries " + HexEncode(key) + " " + HexEncode(forgery) + " -> " + HexEncode(md4.ComputeHash(key)));
                total += n;
            }
            Console.WriteLine("Naito et al. improvement: " + total + " tries to find 5000 collisions with probability " + ((double)total / 5000));
            return total == 5000;
        }
        static public bool Challenge56()
        {
            //SET 7 CHALLENGE 56
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] forgery = Convert.FromBase64String("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F");
            byte[] key = new byte[64];
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
                for (int i = 0; i < 1 << 25; i++)
                {
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
                    if (15 - len + forgery.Length >= 32)
                    {
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
            return false;
        }
        static Tuple<BigInteger, BigInteger> signECDSAbiased(RNGCryptoServiceProvider rng, BigInteger m, BigInteger d, BigInteger n, Tuple<BigInteger, BigInteger> G, int Ea, BigInteger GF)
        {
            BigInteger k, r, s;
            do
            {
                do
                {
                    do { k = GetNextRandomBig(rng, n); } while (k <= 1);
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
            return c.SkipWhile((BigInteger cr) => cr == BigInteger.Zero).ToArray(); ;
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
            return p.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray();
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
            return new Tuple<BigInteger[], BigInteger[]>(q.SkipWhile((BigInteger c) => c == BigInteger.Zero).ToArray(), r);
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
            BigInteger[] c = gcdGFE2k(f, fprime.SkipWhile((BigInteger cr) => cr == BigInteger.Zero).ToArray()), w = divmodGFE2k(f, c).Item1;
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
        static public bool Challenge57()
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
            for (int i = 2; i < 1 << 16; i++)
            {
                BigInteger Rem = new BigInteger(), Quot = BigInteger.DivRem(j, i, out Rem);
                if (Rem == BigInteger.Zero)
                {
                    rs.Add(i);
                    do
                    {
                        j = Quot;
                        Quot = BigInteger.DivRem(j, i, out Rem); //reduce powers of factors:
                        //(Friendly tip: maybe avoid any repeated factors. They only complicate things.)
                    } while (Rem == BigInteger.Zero);
                }
            }
            do { x = GetNextRandomBig(rng, q); } while (x <= 1); //Bob's secret key
            //Console.WriteLine("Secret key generated: " + HexEncode(x.ToByteArray()));
            do
            {
                BigInteger h;
                do
                {
                    //random number between 1..p
                    BigInteger rand;
                    do { rand = GetNextRandomBig(rng, p); } while (rand <= 1);
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
            } while (rcum <= q);
            //Chinese Remainder Theorem - arbitrary size by interpolation
            //K = b1 (mod h1), K = b_n (mod r_n)
            for (int i = 0; i < curr; i++)
            {
                BigInteger curcum = rcum / rs[i];
                RecX += bs[i] * curcum * modInverse(curcum, rs[i]);
            }
            //Console.WriteLine("8.57 Secret key recovered: " + HexEncode(posRemainder(RecX, rcum).ToByteArray()));
            return posRemainder(RecX, rcum) == x;
        }
        static public bool Challenge58()
        {
            //SET 8 CHALLENGE 58
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] m = System.Text.Encoding.ASCII.GetBytes("crazy flamboyant for the rap enjoyment");
            BigInteger x;
            BigInteger p = BigInteger.Parse("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623");
            BigInteger q = BigInteger.Parse("335062023296420808191071248367701059461");
            BigInteger j = (p - 1) / q; //34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
            BigInteger g = BigInteger.Parse("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357");
            BigInteger y = BigInteger.Parse("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119");
            /*for (int i = 0; i < 1 << 20; i++) { //small enough to brute force, AC3CD
                if (y == BigInteger.ModPow(g, i, p)) {
                    Console.WriteLine("Brute force secret key from public: " + i.ToString("X")); break;
                }
            }*/
            //[0, 2^20], y=g^x mod p
            BigInteger yPass = 705485;
            BigInteger yRes = PollardKangaroo(0, 1 << 20, 7, g, p, y);
            if (yPass != yRes) return false;
            //Console.WriteLine("Pollard Kangaroo secret key from public: " + HexEncode(yRes.ToByteArray().Reverse().ToArray()));
            y = BigInteger.Parse("9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733");
            //[0, 2^40], 53b89e66e4
            yPass = 359579674340;
            yRes = PollardKangaroo(0, (ulong)1 << 40, 23, g, p, y);
            if (yPass != yRes) return false;
            //Console.WriteLine("Pollard Kangaroo secret key from public: " + HexEncode(yRes.ToByteArray().Reverse().ToArray()));
            do { x = GetNextRandomBig(rng, q); } while (x <= 1); //Bob's secret key
            y = BigInteger.ModPow(g, x, p);
            //Console.WriteLine("Secret key generated: " + HexEncode(x.ToByteArray()));
            List<int> rs = new List<int>();
            for (int i = 2; i < 1 << 16; i++)
            {
                BigInteger Rem = new BigInteger(), Quot = BigInteger.DivRem(j, i, out Rem);
                if (Rem == BigInteger.Zero)
                {
                    rs.Add(i);
                    do
                    {
                        j = Quot;
                        Quot = BigInteger.DivRem(j, i, out Rem); //reduce powers of factors:
                        //(Friendly tip: maybe avoid any repeated factors. They only complicate things.)
                    } while (Rem == BigInteger.Zero);
                }
            }
            int curr = 0;
            BigInteger rcum = 1;
            List<int> bs = new List<int>();
            do
            {
                BigInteger h;
                do
                {
                    //random number between 1..p
                    BigInteger rand;
                    do { rand = GetNextRandomBig(rng, p); } while (rand <= 1);
                    h = BigInteger.ModPow(rand, (p - 1) / rs[curr], p); //There is no x such that h = g^x mod p
                } while (h == 1);
                BigInteger K = BigInteger.ModPow(h, x, p);
                byte[] t = hmac(K.ToByteArray(), m);
                BigInteger testK;
                for (int i = 0; i < rs[curr]; i++)
                {
                    testK = BigInteger.ModPow(h, i, p);
                    if (t.SequenceEqual(hmac(testK.ToByteArray(), m)))
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
            BigInteger RecX = BigInteger.Zero;
            for (int i = 0; i < curr; i++)
            {
                BigInteger curcum = rcum / rs[i];
                RecX += bs[i] * curcum * modInverse(curcum, rs[i]);
            }
            RecX = BigInteger.Remainder(RecX, rcum);
            //Console.WriteLine("CRT recovered: " + HexEncode(RecX.ToByteArray()));
            //[0, (q-1)/r]
            //x = n mod r, x = n + m * r therefore transform
            //y = g^x=g^(n+m*r)=g^n*g^(m*r)
            //y' = y * g^(-n)=g^(m*r), g'=g^r, y'=(g')^m
            BigInteger Gprime = BigInteger.ModPow(g, rcum, p);
            BigInteger Yprime = BigInteger.Remainder(y * modInverse(BigInteger.ModPow(g, RecX, p), p), p);
            BigInteger Mprime = PollardKangaroo(0, (p - 1) / rcum, 23, Gprime, p, Yprime); //(p - 1) / rcum is 40 bits in this case, 23 could also be good
            BigInteger res = BigInteger.Remainder(RecX + Mprime * rcum, p - 1);
            //Console.WriteLine("8.58 Secret key recovered: " + HexEncode(res.ToByteArray()));
            return res == x;
        }
        static public bool Challenge59()
        {
            //SET 8 CHALLENGE 59
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] m = System.Text.Encoding.ASCII.GetBytes("crazy flamboyant for the rap enjoyment");
            int Ea = -95051, Eb = 11279326;
            BigInteger Gx = 182, Gy = BigInteger.Parse("85518893674295321206118380980485522083"),
                GF = BigInteger.Parse("233970423115425145524320034830162017933"), BPOrd = BigInteger.Parse("29246302889428143187362802287225875743"), Ord = BPOrd * 2 * 2 * 2;
            //BPOrd*(Gx, Gy) = (0, 1)
            //factor Ord - then test all factors for BPOrd according to point multiplication equal to the infinite point (0, 1)
            //scaleEC(new Tuple<BigInteger, BigInteger>(Gx, Gy), BPOrd, Ea, GF).Equals(new Tuple<BigInteger, BigInteger>(0, 1));
            //if (Ord != SchoofElkiesAtkin(Ea, Eb, GF, rng, true, Ord)) return false;
            //if (Ord != SchoofElkiesAtkin(Ea, Eb, GF, rng, false, Ord)) return false;
            //if (Ord != Schoof(Ea, Eb, GF, rng, Ord)) return false;
            int[] PickGys = new int[] { Eb, 210, 504, 727 };
            Tuple<BigInteger, BigInteger> G = new Tuple<BigInteger, BigInteger>(Gx, Gy);
            //http://magma.maths.usyd.edu.au/calc/
            //E: y^2+a_1xy+a_3y=x^3+a_2x^2+a_4x+a_6 over GF(p)
            //K:=GF(233970423115425145524320034830162017933);
            //g:= Generator(K);
            //E:= EllipticCurve([0, 0, 0, -95051 * g, 727 * g]);
            //#E;
            BigInteger[] Ords = new BigInteger[] { Ord, BigInteger.Parse("233970423115425145550826547352470124412"), //2^2 * 3 * 11 * 23 * 31 * 89 * 4999 * 28411 * 45361 * 109138087 * 39726369581
                BigInteger.Parse("233970423115425145544350131142039591210"), //2 * 5 * 7 * 11 * 61 * 12157 * 34693 * 11810604523200031240395593
                BigInteger.Parse("233970423115425145545378039958152057148") }; //2^2 * 7 * 23 * 37 * 67 * 607 * 1979 * 13327 * 13799 * 663413139201923717
            //if (Ords[1] != SchoofElkiesAtkin(Ea, PickGys[1], GF, rng, true, Ords[1])) return false;
            //if (Ords[1] != SchoofElkiesAtkin(Ea, PickGys[1], GF, rng, false, Ords[1])) return false;
            //if (Ords[1] != Schoof(Ea, PickGys[1], GF, rng, Ords[1])) return false;
            if (Ords[2] != SchoofElkiesAtkin(Ea, PickGys[2], GF, rng, true, Ords[2])) return false;
            if (Ords[2] != SchoofElkiesAtkin(Ea, PickGys[2], GF, rng, false, Ords[2])) return false;
            if (Ords[2] != Schoof(Ea, PickGys[2], GF, rng, Ords[2])) return false;
            if (Ords[3] != SchoofElkiesAtkin(Ea, PickGys[3], GF, rng, true, Ords[3])) return false;
            if (Ords[3] != SchoofElkiesAtkin(Ea, PickGys[3], GF, rng, false, Ords[3])) return false;
            if (Ords[3] != Schoof(Ea, PickGys[3], GF, rng, Ords[3])) return false;
            //Ords[0] /= 2; //The correct way to find generators of required order is to use the order of the largest cyclic subgroup of an elliptic curve.
            BigInteger ASecret;
            do { ASecret = GetNextRandomBig(rng, BPOrd); } while (ASecret <= 1);
            Tuple<BigInteger, BigInteger> APub = scaleEC(G, ASecret, Ea, GF);
            BigInteger BSecret;
            do { BSecret = GetNextRandomBig(rng, BPOrd); } while (BSecret <= 1);
            Tuple<BigInteger, BigInteger> BPub = scaleEC(G, BSecret, Ea, GF);
            Tuple<BigInteger, BigInteger> AShared = scaleEC(BPub, ASecret, Ea, GF);
            Tuple<BigInteger, BigInteger> BShared = scaleEC(APub, BSecret, Ea, GF);
            Console.WriteLine("Base point and order correct: " + (scaleEC(G, BPOrd, Ea, GF).Equals(new Tuple<BigInteger, BigInteger>(0, 1))));
            Console.WriteLine("Shared Secrets Identical: " + (AShared.Item1 == BShared.Item1));

            //Pohlig-Hellman algorithm for discrete logarithms
            List<int> rs = new List<int>();
            List<int> rsidx = new List<int>();
            rs.Add(8);
            rsidx.Add(0);
            for (int prms = 1; prms < 4; prms++)
            {
                BigInteger p = Ords[prms];
                for (int i = 2; i < 1 << 16; i++)
                {
                    BigInteger Rem = new BigInteger(), Quot = BigInteger.DivRem(p, i, out Rem);
                    if (Rem == BigInteger.Zero)
                    {
                        if (i != 2 && !rs.Contains(i))
                        {//2^3 as a factor uses original curve, up to 31 result not found
                            rs.Add(i);
                            rsidx.Add(prms);
                        }
                        do
                        {
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
            List<int> bs = new List<int>();
            BigInteger rcum = 1, x;
            int curr = 0;
            do { x = GetNextRandomBig(rng, BPOrd); } while (x <= 1); //Bob's secret key
            Console.WriteLine("Secret key generated: " + x);
            do
            {
                BigInteger hx, hy;
                Tuple<BigInteger, BigInteger> h;
                do
                {
                    //random point with between x value between 1..Ord
                    do { hx = GetNextRandomBig(rng, Ords[rsidx[curr]]); } while (hx <= 1);
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
                for (i = 0; i < rs[curr]; i++)
                {
                    testK = scaleEC(h, i, Ea, GF);
                    if (new ByteArrayComparer().Equals(t, hmac(testK.Item1.ToByteArray(), m)))
                    {
                        break;
                    }
                }
                if (i == rs[curr] || i == 0)
                {
                    //Console.WriteLine(rs[curr]);
                    rs.RemoveAt(curr);
                    rsidx.RemoveAt(curr);
                }
                else
                {
                    //k*u = -k*u, resulting in a combinatorial explosion of potential CRT outputs. 
                    //i or rs[curr] - i
                    //Console.WriteLine(rs[curr] + " " + (rs[curr] - i) + " " + i + " " + BigInteger.Remainder(x, rs[curr]));
                    bs.Add(i); //i or rs[curr] - i, only know i^2
                    rcum *= rs[curr];
                    curr++;
                }
            } while (rcum <= BPOrd);
            BigInteger RecX = BigInteger.Zero;
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
                    do { hx = GetNextRandomBig(rng, BPOrd); } while (hx <= 1);
                    hy = TonelliShanks(rng, posRemainder(hx * hx * hx + Ea * hx + Eb, GF), GF);
                } while (hy == BigInteger.Zero);
                h = new Tuple<BigInteger, BigInteger>(hx, hy);
                Tuple<BigInteger, BigInteger> finK = scaleEC(h, x, Ea, GF);
                byte[] t = hmac(finK.Item1.ToByteArray(), m);
                for (int r = 0; r < 1 << curr; r++)
                {
                    RecX = BigInteger.Zero;
                    for (int i = 0; i < curr; i++)
                    {
                        BigInteger curcum = rcum / rs[i];
                        RecX += ((r & (1 << i)) != 0 ? bs[i] : rs[i] - bs[i]) * curcum * modInverse(curcum, rs[i]);
                    }
                    RecX = BigInteger.Remainder(RecX, rcum);
                    Tuple<BigInteger, BigInteger> testK = scaleEC(h, RecX, Ea, GF);
                    if (new ByteArrayComparer().Equals(t, hmac(testK.Item1.ToByteArray(), m)))
                    {
                        break;
                    }
                }
            }
            Console.WriteLine("8.59 Secret key recovered: " + RecX);
            return false;
        }
        static public bool Challenge60()
        {
            //SET 8 CHALLENGE 60
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] m = System.Text.Encoding.ASCII.GetBytes("crazy flamboyant for the rap enjoyment");
            BigInteger Gx = 182, Gy = BigInteger.Parse("85518893674295321206118380980485522083"), GF = BigInteger.Parse("233970423115425145524320034830162017933"),
                BPOrd = BigInteger.Parse("29246302889428143187362802287225875743"), Ord = BPOrd * 2 * 2 * 2;
            Tuple<BigInteger, BigInteger> G = new Tuple<BigInteger, BigInteger>(Gx, Gy);
            int EaOrig = -95051, Ea = 534, Eb = 11279326; Gx = Gx - 178;
            Console.WriteLine("Base point and order correct: " + ladder(Gx, BPOrd, Ea, GF) + " " + (ladder(Gx, BPOrd, Ea, GF) == BigInteger.Zero));
            BigInteger Pt = BigInteger.Parse("76600469441198017145391791613091732004");
            Console.WriteLine(ladder(Pt, 11, Ea, GF)); //0 or infinite
            Console.WriteLine(TonelliShanks(rng, posRemainder(Pt * Pt * Pt + Ea * Pt * Pt + Pt, GF), GF)); //0 meaning non-existent
            BigInteger TwistOrd = 2 * GF + 2 - Ord;
            List<int> rs = new List<int>();
            BigInteger p = TwistOrd; //Montgomery curve order are always divisible by 4
            for (int i = 2; i < 1 << 24; i++)
            {
                BigInteger Rem = new BigInteger(), Quot = BigInteger.DivRem(p, i, out Rem);
                if (Rem == BigInteger.Zero)
                {
                    rs.Add(i);
                    do
                    {
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
            List<int> bs = new List<int>();
            BigInteger rcum = 1, x;
            int curr = 0;
            do { x = GetNextRandomBig(rng, BPOrd); } while (x <= 1); //Bob's secret key
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
                    do { u = GetNextRandomBig(rng, GF); } while (u <= 1);
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
                if (i == rs[curr] || i == 0)
                {
                    //Console.WriteLine(rs[curr]);
                    rs.RemoveAt(curr);
                }
                else
                {
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
            BigInteger RecX;
            for (int r = 0; r < 1 << curr; r++)
            {
                RecX = BigInteger.Zero;
                for (int i = 0; i < curr; i++)
                {
                    BigInteger curcum = rcum / rs[i];
                    RecX += ((r & (1 << i)) != 0 ? bs[i] : rs[i] - bs[i]) * curcum * modInverse(curcum, rs[i]);
                }
                RecX = BigInteger.Remainder(RecX, rcum);
                recxs.Add(RecX);
            }
            do
            {
                BigInteger u, hy; //keep querying until narrowed down to only a positive/negative pair
                do
                {
                    //random point with between x value between 1..Ord
                    do { u = GetNextRandomBig(rng, GF); } while (u <= 1);
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
            Tuple<BigInteger, BigInteger> Yorig = scaleEC(G, x, EaOrig, GF);
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
            BigInteger Mprime = PollardKangarooECmontg(0, TwistOrd / rcum, 23, GprimeEC, EaOrig, Ea, Eb, GF, YprimeEC, 178); //(q - 1) / rcum is 43 bits in this case, 26 could also be good
            if (Mprime.Equals(BigInteger.Zero))
            {
                RecX = rcum - RecX;
                //YprimeEC = addEC(Y, invertEC(scaleEC(G, RecX, EaOrig, GF), GF), EaOrig, GF);
                YprimeEC = addEC(montgToWS(Y, 178), invertEC(montgToWS(ladder2(new Tuple<BigInteger, BigInteger>(Gx, Gy), RecX, Ea, EaOrig, Eb, GF, 178), 178), GF), EaOrig, GF);
                Console.WriteLine(YprimeEC + " " + scaleEC(GprimeEC, ((x - RecX) / rcum), EaOrig, GF));
                Mprime = PollardKangarooECmontg(0, TwistOrd / rcum, 23, GprimeEC, EaOrig, Ea, Eb, GF, YprimeEC, 178); //(q - 1) / rcum is 43 bits in this case, 26 could also be good
            }
            Console.WriteLine("8.60 Secret key recovered: " + (RecX + Mprime * rcum) + " " + HexEncode((RecX + Mprime * rcum).ToByteArray()));
            return false;
        }
        static public bool Challenge61()
        {
            //SET 8 CHALLENGE 61
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] m = System.Text.Encoding.ASCII.GetBytes("crazy flamboyant for the rap enjoyment");
            int EaOrig = -95051;
            BigInteger Gx = 182, Gy = BigInteger.Parse("85518893674295321206118380980485522083"), 
                GF = BigInteger.Parse("233970423115425145524320034830162017933"), BPOrd = BigInteger.Parse("29246302889428143187362802287225875743");
            Tuple<BigInteger, BigInteger> G = new Tuple<BigInteger, BigInteger>(Gx, Gy);
            BigInteger d;
            SHA1 hf = SHA1.Create();
            do { d = GetNextRandomBig(rng, BPOrd); } while (d <= 1);
            Tuple<BigInteger, BigInteger> Q = scaleEC(G, d, EaOrig, GF);
            BigInteger hm = BytesToBigInt(hf.ComputeHash(m));
            Tuple<BigInteger, BigInteger> res = signECDSA(rng, hm, d, BPOrd, G, EaOrig, GF);
            //now generate a fake signer public key Q'
            BigInteger inv = modInverse(res.Item2, BPOrd), u1 = BigInteger.Remainder(hm * inv, BPOrd), u2 = BigInteger.Remainder(res.Item1 * inv, BPOrd);
            BigInteger dprime;
            do { dprime = GetNextRandomBig(rng, BPOrd); } while (dprime <= 1);
            BigInteger tmp = u1 + u2 * dprime;
            Tuple<BigInteger, BigInteger> GprimeEC = scaleEC(addEC(scaleEC(G, u1, EaOrig, GF), scaleEC(Q, u2, EaOrig, GF), EaOrig, GF), modInverse(tmp, BPOrd), EaOrig, GF);
            Tuple<BigInteger, BigInteger> Qprime = scaleEC(GprimeEC, dprime, EaOrig, GF);
            Console.WriteLine("Q and Q' verify: " + verifyECDSA(hm, res, Q, BPOrd, G, EaOrig, GF) + " " + verifyECDSA(hm, res, Qprime, BPOrd, GprimeEC, EaOrig, GF));
            //RSA
            //sign: s=pad(m)^d mod N
            BigInteger _p;
            BigInteger _q;
            BigInteger et;
            do
            {
                do
                {
                    _p = GetPivotRandom(rng, 128);
                } while (!IsProbablePrime(_p, 64));
                _p = BigInteger.Parse("252919978488117916147778994275562072491");
                do
                {
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
                for (; i < rsq.Count; i++)
                {
                    if (BigInteger.ModPow(s, (pprime - 1) / rsq[i], pprime).Equals(BigInteger.One)) break;
                }
                if (i == rsq.Count) break;
            } while (true);
            List<int> rs = rsq.ConvertAll((BigInteger X) => (int)X); rsq.Clear();
            do
            {
                do
                {
                    qprime = GetPivotRandom(rng, 128);
                    if (pprime * qprime <= n) continue;
                } while (!IsProbablePrime(qprime, 64));
                qprime = BigInteger.Parse("266237645118740561410025069955757680311");
                int i = 0;
                for (; i < rs.Count; i++)
                {
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
            List<int>bs = new List<int>(); BigInteger rcum = 1;
            BigInteger nprime = pprime * qprime, npp = qprime - 1, npq = pprime - 1, ep = BigInteger.Zero, eq = BigInteger.Zero;
            //Pohlig-Hellman s^e=pad(m) mod n, s^ep=pad(m) mod p, s^eq=pad(m) mod q
            for (int curr = 0; curr < rs.Count; curr++)
            {
                BigInteger gprime = BigInteger.ModPow(s, (pprime - 1) / rs[curr], pprime);
                BigInteger hprime = BigInteger.ModPow(hm, (pprime - 1) / rs[curr], pprime);
                for (int i = 0; i < rs[curr]; i++)
                {
                    if (BigInteger.ModPow(gprime, i, pprime).Equals(hprime))
                    {
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
            for (int curr = 0; curr < rs.Count; curr++)
            {
                BigInteger gprime = BigInteger.ModPow(s, (qprime - 1) / rs[curr], qprime);
                BigInteger hprime = BigInteger.ModPow(hm, (qprime - 1) / rs[curr], qprime);
                for (int i = 0; i < rs[curr]; i++)
                {
                    if (BigInteger.ModPow(gprime, i, qprime).Equals(hprime))
                    {
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
            Console.WriteLine("eprime for ep and eq: " + BigInteger.Remainder(eprime, pprime - 1).Equals(ep) + " " + BigInteger.Remainder(eprime, qprime - 1).Equals(eq));
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
            return false;
        }
        static public bool Challenge62()
        {
            //SET 8 CHALLENGE 62
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            SHA1 hf = SHA1.Create();
            byte[] m = System.Text.Encoding.ASCII.GetBytes("crazy flamboyant for the rap enjoyment");
            int EaOrig = -95051;
            BigInteger Gx = 182, Gy = BigInteger.Parse("85518893674295321206118380980485522083"), 
                GF = BigInteger.Parse("233970423115425145524320034830162017933"), BPOrd = BigInteger.Parse("29246302889428143187362802287225875743");
            Tuple<BigInteger, BigInteger> G = new Tuple<BigInteger, BigInteger>(Gx, Gy);
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
            BigInteger d;
            do { d = GetNextRandomBig(rng, BPOrd); } while (d <= 1);
            Tuple<BigInteger, BigInteger> Q = scaleEC(G, d, EaOrig, GF);
            BigInteger hm = BytesToBigInt(hf.ComputeHash(m));
            List<List<Tuple<BigInteger, BigInteger>>> Basis = new List<List<Tuple<BigInteger, BigInteger>>>();
            const int trials = 20; //20 is possible per problem guidance
            for (int i = 0; i < trials; i++)
            {
                Basis.Add(Enumerable.Repeat(new Tuple<BigInteger, BigInteger>(0, 1), i).Concat(new List<Tuple<BigInteger, BigInteger>> { new Tuple<BigInteger, BigInteger>(BPOrd, 1) }).Concat(Enumerable.Repeat(new Tuple<BigInteger, BigInteger>(0, 1), trials + 2 - 1 - i)).ToList());
            }
            List<Tuple<BigInteger, BigInteger>> bt = new List<Tuple<BigInteger, BigInteger>>();
            List<Tuple<BigInteger, BigInteger>> bu = new List<Tuple<BigInteger, BigInteger>>();
            for (int i = 0; i < trials; i++)
            {
                Tuple<BigInteger, BigInteger> res = signECDSAbiased(rng, hm, d, BPOrd, G, EaOrig, GF);
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
            BigInteger dprime = BigInteger.Zero;
            for (int i = 0; i < trials + 2; i++)
            {
                if (Basis[i][trials + 1].Equals(cu))
                {
                    //reducFrac(-Basis[i][trials].Item1 * (1 << 8), Basis[i][trials].Item2).Item1 == 1
                    dprime = posRemainder(reducFrac(new Tuple<BigInteger, BigInteger>(-Basis[i][trials].Item1 * (1 << 8), Basis[i][trials].Item2)).Item1, BPOrd);
                    break;
                }
            }
            Console.WriteLine("8.62 d recovered: " + (d == dprime));
            return false;
        }
        static public bool Challenge63()
        {
            //SET 8 CHALLENGE 63
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] m = System.Text.Encoding.ASCII.GetBytes("crazy flamboyant for the rap enjoyment");
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
            for (int ctr = 0; ctr < padAuthData.Length; ctr += 16)
            { //zero pad to block align
                coeff[ctr / 16] = addGF2(new BigInteger(padAuthData.Skip((int)ctr).Take(Math.Min(padAuthData.Length - (int)ctr, 16)).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()),
                    new BigInteger(padAuthDataRev.Skip((int)ctr).Take(Math.Min(padAuthDataRev.Length - (int)ctr, 16)).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()));
            }
            for (int ctr = 0; ctr < cyphData.Length; ctr += 16)
            { //zero pad to block align
                coeff[padAuthData.Length / 16 + ctr / 16] = addGF2(new BigInteger(cyphData.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()),
                    new BigInteger(cyphData2.Skip((int)ctr).Take(16).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()));
            }
            coeff[coeff.Length - 2] = addGF2(new BigInteger(BitConverter.GetBytes((ulong)authData.Length * 8).Reverse().Concat(BitConverter.GetBytes((ulong)cyphData.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()),
                new BigInteger(BitConverter.GetBytes((ulong)authData.Length * 8).Reverse().Concat(BitConverter.GetBytes((ulong)cyphData2.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()));
            coeff[coeff.Length - 1] = addGF2(tag, tag2);
            String str = String.Empty;
            BigInteger Sum = BigInteger.Zero;
            BigInteger hkey = new BigInteger(encrypt_ecb(key, Enumerable.Repeat((byte)0, 16).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()); //authentication key
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
            BigInteger[] monic = mulGFE2k(coeff, new BigInteger[] { multiplier });
            //BigInteger [] reslt = divmodGFE2k(monic, new BigInteger[] { BigInteger.One, BigInteger.Parse("74290645703835062417165689337537425287"), BigInteger.Parse("35413549109971219848440623448364065564"), BigInteger.Parse("79510262696675812766390810347978617508") }).Item1;
            //BigInteger[] monic = addGFE2k(monTup.Item1, mulGFE2k(new BigInteger[] { coeff[0] }, monTup.Item2));
            List<BigInteger[]> sqrF = sqrFree(monic);
            Tuple<BigInteger[], int>[] ddfRes = sqrF.SelectMany((sq) => ddf(sq)).ToArray();
            List<BigInteger> keyPosbl = new List<BigInteger>();
            for (int i = 0; i < ddfRes.Length; i++)
            {
                if (ddfRes[i].Item2 == 1)
                { //a degree one factor will be the key
                    BigInteger[][] edfRes = edf(rng, ddfRes[i].Item1, ddfRes[i].Item2);
                    for (int l = 0; l < edfRes.Length; l++)
                    {
                        keyPosbl.Add(edfRes[l].Last());
                    }
                }
            }

            if (keyPosbl.Count != 1)
            {
                byte[] cyphDataOth = crypt_gcm(nonce, key, Enumerable.Repeat((byte)0, cyphData2.Length).ToArray());
                BigInteger tagOth = calc_gcm_tag(nonce, key, cyphDataOth, authData.Reverse().ToArray());
                //make forgery, query oracle for validity
                //forgery must have same length cypher text and authentication data or cannot be made with authentication key and must reverse AES key which is not possible
                for (int i = 0; i < keyPosbl.Count; i++)
                {
                    BigInteger stag = calc_gcm_s(nonce, keyPosbl[i], cyphData, authData, tag);
                    //try a forgery making sure the cypher data and authentication are the same length, the only way to forge
                    BigInteger trytag = calc_gcm_s(nonce, keyPosbl[i], cyphDataOth, authData, stag);
                    if (trytag == tagOth)
                    { //oracle function
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
                for (int i = 0; i < ddfRes.Length; i++)
                {
                    if (ddfRes[i].Item2 == 1)
                    { //a degree one factor will be the key
                        BigInteger[][] edfRes = edf(rng, ddfRes[i].Item1, ddfRes[i].Item2);
                        for (int l = 0; l < edfRes.Length; l++)
                        {
                            if (keyPosbl.Contains(edfRes[l].Last()))
                            {
                                Console.WriteLine("Authentication Key found by 3rd same nonce message: " + edfRes[l].Last());
                                break;
                            }
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("Authentication Key found: " + keyPosbl[0]);
            }
            Console.WriteLine("8.63");
            return false;
        }
        static public bool Challenge64()
        {
            //SET 8 CHALLENGE 64
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            BigInteger M = BigInteger.Parse("0100000000000000000000000000000087", System.Globalization.NumberStyles.HexNumber); //00E1000000000000000000000000000000 00E100000000000000000000000000000080 0100000000000000000000000000000087
            byte[] key = new byte[16];
            rng.GetBytes(key);
            byte[] nonce = new byte[12]; // || 0^31 || 1
            rng.GetBytes(nonce);
            nonce = new byte[] { 0x51, 0x75, 0x3c, 0x65, 0x80, 0xc2, 0x72, 0x6f, 0x20, 0x71, 0x84, 0x14 };
            key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

            //https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf
            //messages of 2^17 blocks which are 128 bits each
            int nSize = 17; //too slow for now with 17 ~ 7 minutes for crypt_gcm and calc_gcm_tag, probably need GCM MAC library
            byte[] m = new byte[16 * (1 << nSize)];
            rng.GetBytes(m);

            Tuple<byte[], BigInteger> cyphtag = crypt_gcm_fastlib(nonce, key, m, new byte[] { });
            byte[] cyphDataVerify = cyphtag.Item1;
            byte[] cyphData = cyphtag.Item1;
            BigInteger tag = cyphtag.Item2 & 0xFFFFFFFF; //32-bit MAC
            //tag = calc_gcm_tag_fastlib(M, nonce, key, cyphData) & 0xFFFFFFFF; //32-bit MAC;
            //tag = calc_gcm_tag_fastlib(M, nonce, key, cyphData) & 0xFFFFFFFF; //32-bit MAC;

            //cyphData = crypt_gcm(nonce, key, m);
            //tag = calc_gcm_tag(nonce, key, cyphData, new byte[] { }) & 0xFFFFFFFF; //32-bit MAC
            //tgComp = tag.ToByteArray().Select((byte b) => ReverseBitsWith4Operations(b)).ToArray();

            BigInteger hkey = new BigInteger(encrypt_ecb(key, Enumerable.Repeat((byte)0, 16).ToArray()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray()); //authentication key
            Console.WriteLine("Secret key: " + hkey);
            bool[,] Ms = new bool[128, 128];
            bool[][,] Msis = new bool[nSize][,];
            bool[,] Ad = new bool[128, 128];
            //can 0 out (n*128) / (ncols(X)) per operation, start with 16+1 non-zero row
            bool[,] T = null;
            bool[,] NT, Km = null, Xm = null;
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
                for (int c = 1; c < nSize + 1; c++)
                {
                    int ctr = 16 * ((1 << c) - 1);
                    //Console.WriteLine(c);
                    for (int flip = 0; flip < 128; flip++)
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
                        //bool[,] Mdit = calcAd(nSize, cyphDataTest, M, Msis).Item1;
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
                while (true)
                {
                    totalTries++;
                    bool[,] testBits = new bool[numcols, 1]; //new bool[solutionBits.GetLength(0), solutionBits.GetLength(1)]; //(bool[,])solutionBits.Clone();
                    rng.GetBytes(rnd);
                    for (int ci = 0; ci < numrows; ci++)
                    {
                        if ((rnd[ci] & 1) != 0)
                        { //odd byte means inclusion
                            for (int col = 0; col < numcols; col++)
                            {
                                testBits[col, 0] ^= NT[ci, col];
                            }
                        }
                    }
                    byte[] cyphDataTest = cyphData.ToArray(); //make copy
                    for (int bit = 0; bit < numcols; bit++)
                    {
                        if (testBits[bit, 0])
                        {
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
                    if (tag == tagtest)
                    {
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
                foreach (int i in AdRows)
                {
                    for (int col = 0; col < Ad.GetLength(1); col++)
                    {
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
            Console.WriteLine("8.64"); return false;
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
        static public bool Challenge65()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] m = System.Text.Encoding.ASCII.GetBytes("crazy flamboyant for the rap enjoyment");
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
                if (padLengthMode)
                {
                    bool[,] solveT = new bool[T.GetLength(0), T.GetLength(1) + 1];
                    for (int row = 0; row < T.GetLength(0); row++)
                    {
                        for (int col = 0; col < T.GetLength(1); col++)
                        {
                            solveT[row, col] = T[row, col];
                        }
                    }
                    BigInteger dit = new BigInteger(BitConverter.GetBytes((ulong)0).Reverse().Concat(BitConverter.GetBytes((ulong)cyphData.Length * 8).Reverse()).Select((byte b) => ReverseBitsWith4Operations(b)).Concat(new byte[] { 0 }).ToArray());
                    for (int i = 0; i < 128; i++)
                    {
                        BigInteger cnst = modmulGF2k(dit, BigInteger.One << i, M);
                        for (int row = 0; row < 128; row++)
                        {
                            Adt[row, i] = (cnst & (BigInteger.One << row)) != 0;
                        }
                    }
                    AdtX = (Xm != null) ? matmul(Adt, Xm) : Adt;
                    for (int row = 0; row < numrows; row++)
                    {
                        for (int col = 0; col < numcols; col++)
                        {
                            solveT[col + row * numcols, solveT.GetLength(1) - 1] = (AdtX[row, col] != AdnX[0][row, col]);
                        }
                    }
                    solveT = gaussianElim(solveT);
                    int ct = 0;
                    //last column is now the solution
                    for (int row = 0; row < solveT.GetLength(0); row++)
                    {
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
                    if (numrows <= 16)
                    { //exhaustive search before toggling mode and moving on to non-length padding mode
                        if (padLengthMode && totalTries == (1 << numrows))
                        {
                            padLengthMode = !padLengthMode;
                            totalTries = -1;
                            break;
                        }
                        for (int ci = 0; ci < numrows; ci++)
                        {
                            if (((1 << ci) & totalTries) != 0)
                            { //totalTries bits indicate combinations
                                for (int col = 0; col < numcols; col++)
                                {
                                    testBits[col, 0] ^= NT[ci, col];
                                }
                            }
                        }
                    }
                    else
                    {
                        rng.GetBytes(rnd);
                        for (int ci = 0; ci < numrows; ci++)
                        {
                            if ((rnd[ci] & 1) != 0)
                            { //odd byte means inclusion
                                for (int col = 0; col < numcols; col++)
                                {
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
                        if (padLengthMode)
                        {
                            for (int ci = 0; ci < Adt.GetLength(0); ci++)
                            {
                                for (int col = 0; col < Adt.GetLength(1); col++)
                                {
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
                for (int i = 0; i < 128; i++)
                {
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
                foreach (int i in AdRows)
                {
                    for (int col = 0; col < Ad.GetLength(1); col++)
                    {
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
            return false;
        }
        static public bool Challenge66()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            //start with code from #59, addEC/scaleEC to inject fault
            int EaOrig = -95051, Ea = EaOrig, Eb = 11279326;
            BigInteger Gx = 182, Gy = BigInteger.Parse("85518893674295321206118380980485522083"),
                GF = BigInteger.Parse("233970423115425145524320034830162017933"), BPOrd = BigInteger.Parse("29246302889428143187362802287225875743"), Ord = BPOrd * 2 * 2 * 2;
            Tuple<BigInteger, BigInteger> G = new Tuple<BigInteger, BigInteger>(Gx, Gy);
            int count = GetBitSize(BPOrd);
            BigInteger ASecret;
            do { ASecret = GetNextRandomBig(rng, BPOrd); } while (ASecret <= 1 || GetBitSize(ASecret) != count);
            Tuple<BigInteger, BigInteger> APub = scaleEC(G, ASecret, Ea, GF);
            BigInteger BSecret;
            do { BSecret = GetNextRandomBig(rng, BPOrd); } while (BSecret <= 1 || GetBitSize(BSecret) != count);
            Tuple<BigInteger, BigInteger> BPub = scaleECdecrease(G, BSecret, Ea, GF);
            //BPub.Item1 == scaleEC(G, BSecret, Ea, GF).Item1 && BPub.Item2 == scaleEC(G, BSecret, Ea, GF).Item2;
            Tuple<BigInteger, BigInteger> AShared = scaleECdecrease(BPub, ASecret, Ea, GF);
            Tuple<BigInteger, BigInteger> BShared = scaleECdecrease(APub, BSecret, Ea, GF);
            Console.WriteLine("Base point and order correct: " + (scaleECdecrease(G, BPOrd, Ea, GF).Equals(new Tuple<BigInteger, BigInteger>(0, 1))));
            Console.WriteLine("Shared Secrets Identical: " + (AShared.Item1 == BShared.Item1));

            BigInteger d = BSecret;
            //do { d = GetNextRandomBig(rng, BPOrd); } while (d <= 1 || GetBitSize(d) != count); //Bob's secret key
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
                        do { hx = GetNextRandomBig(rng, Ord); } while (hx <= 1);
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
                            do { hx = GetNextRandomBig(rng, Ord); } while (hx <= 1);
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
            return false;
        }
    }
}