using System;
using System.Collections.Generic;

namespace EncryptionLibrary {
    class Program {
        static void Main(string[] args) {
            bool quit = false;
            byte[] key;
            string salt;
            byte[] hash;

            var enc = new EncryptionManager("enctest.txt");
            Console.WriteLine("Enter a pass:");
                string pass = Console.ReadLine();
                (key, salt, hash) = enc.preparePassword(pass);
            while ( !quit ) {

                Console.WriteLine("Encryption test. 1 : Encrypt, 2 : Decrypt, 3 : Hash, 4: change pass, q : quit");
                string s = Console.ReadLine();

                if ( "1" == s ) {
                    string a = Console.ReadLine();
                    List<string> strings = new List<string>();
                    while ( a.Length > 1 ) {
                        strings.Add(a);
                        a = Console.ReadLine();
                    }

                    if (key != null && salt != null && hash != null)
                        enc.encryptToFile(strings, key, salt, hash);
                }
                else if ( "2" == s ) {
                    if (key != null) {
                        var payload = enc.decryptFromFile(pass, key);
                        Console.WriteLine("Payload:");
                        if ( payload == EncryptionManager.VERIFICATION_ERROR )
                            Console.WriteLine("Verification error.");
                        foreach ( var p in payload )
                            Console.WriteLine(p);
                    }
                }
                else if ( "3" == s ) {
                    pass = Console.ReadLine();
                    (key, salt, hash) = enc.preparePassword(pass);
                }
                else if ( "4" == s) {
                    pass = Console.ReadLine();
                }
                else if ( "q" == s )
                    quit = true;
            }
            Console.WriteLine("Test end.");
        }
    }
}
