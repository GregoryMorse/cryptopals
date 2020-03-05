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
        static void Main(string[] args)
        {
            //testMul();
            //RunSet(1, Set1);
            RunSet(2, Set2);
            //Set2();
            //Set3();
            //Set4();
            //Set5();
            //Set6();
            //Set7();
            //Set8();
            //Set9();

            Console.ReadKey();
        }
    }
}
