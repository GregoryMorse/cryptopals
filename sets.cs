using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using static Cryptopals.Crypto;
using static Cryptopals.Utility;

namespace Cryptopals
{
    class sets
    {
        static public string[] ReadChallengeFile(string fileName)
        {
            return System.IO.File.ReadAllLines("../../" + fileName);
        }
        static public void RunSet(int setNum, Tuple<Func<bool>, int>[] curSet)
        {
            bool bPassAll = true;
            foreach (dynamic s in curSet)
            {
                bool bRes = s.Item1();
                if (!bRes) bPassAll = false;
                Console.WriteLine((bRes ? "Passed" : "Failed") + " challenge " + setNum.ToString() + "." + s.Item2.ToString());
            }
            if (bPassAll) Console.WriteLine("All challenges passed in set " + setNum.ToString());
        }
        static Tuple<Func<bool>, int>[] Set1 = {
            new Tuple<Func<bool>, int>(Challenge1, 1),
            new Tuple<Func<bool>, int>(Challenge2, 2),
            new Tuple<Func<bool>, int>(Challenge3, 3),
            new Tuple<Func<bool>, int>(Challenge4, 4),
            new Tuple<Func<bool>, int>(Challenge5, 5),
            new Tuple<Func<bool>, int>(Challenge6, 6),
            new Tuple<Func<bool>, int>(Challenge7, 7),
            new Tuple<Func<bool>, int>(Challenge8, 8)};
        static Tuple<Func<bool>, int>[] Set2 = {
            new Tuple<Func<bool>, int>(Challenge9, 9),
            new Tuple<Func<bool>, int>(Challenge10, 10),
            new Tuple<Func<bool>, int>(Challenge11, 11),
            new Tuple<Func<bool>, int>(Challenge12, 12),
            new Tuple<Func<bool>, int>(Challenge13, 13),
            new Tuple<Func<bool>, int>(Challenge14, 14),
            new Tuple<Func<bool>, int>(Challenge15, 15),
            new Tuple<Func<bool>, int>(Challenge16, 16)
        };
        static Tuple<Func<bool>, int>[] Set3 = {
            new Tuple<Func<bool>, int>(Challenge17, 17),
            new Tuple<Func<bool>, int>(Challenge18, 18),
            new Tuple<Func<bool>, int>(Challenge19, 19),
            new Tuple<Func<bool>, int>(Challenge20, 20),
            new Tuple<Func<bool>, int>(Challenge21, 21),
            new Tuple<Func<bool>, int>(Challenge22, 22),
            new Tuple<Func<bool>, int>(Challenge23, 23),
            new Tuple<Func<bool>, int>(Challenge24, 24)
        };
        static Tuple<Func<bool>, int>[] Set4 = {
            new Tuple<Func<bool>, int>(Challenge25, 25),
            new Tuple<Func<bool>, int>(Challenge26, 26),
            new Tuple<Func<bool>, int>(Challenge27, 27),
            new Tuple<Func<bool>, int>(Challenge28, 28),
            new Tuple<Func<bool>, int>(Challenge29, 29),
            new Tuple<Func<bool>, int>(Challenge30, 30),
            new Tuple<Func<bool>, int>(Challenge31, 31),
            new Tuple<Func<bool>, int>(Challenge32, 32)
        };
        static Tuple<Func<bool>, int>[] Set5 = {
            new Tuple<Func<bool>, int>(Challenge33, 33),
            new Tuple<Func<bool>, int>(Challenge34, 34),
            new Tuple<Func<bool>, int>(Challenge35, 35),
            new Tuple<Func<bool>, int>(Challenge36, 36),
            new Tuple<Func<bool>, int>(Challenge37, 37),
            new Tuple<Func<bool>, int>(Challenge38, 38),
            new Tuple<Func<bool>, int>(Challenge39, 39),
            new Tuple<Func<bool>, int>(Challenge40, 40)
        };
        static Tuple<Func<bool>, int>[] Set6 = {
            new Tuple<Func<bool>, int>(Challenge41, 41),
            new Tuple<Func<bool>, int>(Challenge42, 42),
            new Tuple<Func<bool>, int>(Challenge43, 43),
            new Tuple<Func<bool>, int>(Challenge44, 44),
            new Tuple<Func<bool>, int>(Challenge45, 45),
            new Tuple<Func<bool>, int>(Challenge46, 46),
            new Tuple<Func<bool>, int>(Challenge47, 47),
            new Tuple<Func<bool>, int>(Challenge48, 48)
        };
        static Tuple<Func<bool>, int>[] Set7 = {
            new Tuple<Func<bool>, int>(Challenge49, 49),
            new Tuple<Func<bool>, int>(Challenge50, 50),
            new Tuple<Func<bool>, int>(Challenge51, 51),
            new Tuple<Func<bool>, int>(Challenge52, 52),
            new Tuple<Func<bool>, int>(Challenge53, 53),
            new Tuple<Func<bool>, int>(Challenge54, 54),
            new Tuple<Func<bool>, int>(Challenge55, 55),
            new Tuple<Func<bool>, int>(Challenge56, 56)
        };
        static Tuple<Func<bool>, int>[] Set8 = {
            new Tuple<Func<bool>, int>(Challenge57, 57),
            new Tuple<Func<bool>, int>(Challenge58, 58),
            new Tuple<Func<bool>, int>(Challenge59, 59),
            new Tuple<Func<bool>, int>(Challenge60, 60),
            new Tuple<Func<bool>, int>(Challenge61, 61),
            new Tuple<Func<bool>, int>(Challenge62, 62),
            new Tuple<Func<bool>, int>(Challenge63, 63),
            new Tuple<Func<bool>, int>(Challenge64, 64)
        };
        static Tuple<Func<bool>, int>[] Set9 = {
            new Tuple<Func<bool>, int>(Challenge65, 65),
            new Tuple<Func<bool>, int>(Challenge66, 66),
        };
        static void Main(string[] args)
        {
            //testMul();
            //RunSet(1, Set1);
            //RunSet(2, Set2);
            //RunSet(3, Set3);
            //RunSet(4, Set4);
            //RunSet(5, Set5);
            //RunSet(6, Set6);
            //RunSet(7, Set7);
            //RunSet(8, Set8);
            RunSet(9, Set9);
            Console.ReadKey();
        }
    }
}
