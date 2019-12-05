using System;
using System.Collections.Generic;

namespace EncryptionLibrary {
    class Program {
        static void Main(string[] args) {
            bool quit = false;
            while (!quit)
            {
                Console.WriteLine("Encryption test. 1 : Encrypt, 2 : Decrypt");
                string s = Console.ReadLine();
                EncryptionWrapper enc = new EncryptionWrapper("enctest.txt");

                if ("1" == s)
                {
                    string a = Console.ReadLine();
                    List<string> strings = new List<string>();
                    while (a.Length > 1)
                    {
                        strings.Add(a);
                        a = Console.ReadLine();
                    }

                    enc.encryptToFile(strings);
                }
                else if ("2" == s)
                {
                    enc.decryptFromFile();
                }
                else if ("q" == s)
                    quit = true;
            }
            Console.WriteLine("Test end.");
        }
    }
}
