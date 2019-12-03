using System;
using System.Collections.Generic;

namespace EncryptionLibrary {
    class Program {
        static void Main(string[] args) {
            Console.WriteLine("Encryption test. 1 : Encrypt, 2 : Decrypt");
            string s = Console.ReadLine();
            if ( "1" == s ) {
                string a;
                List<string> strings = new List<string>();
                do {
                    a = Console.ReadLine();
                    strings.Add(a);
                } while ( a.Length > 1 );
                EncryptionWrapper.testEncrypt(strings);
            }
            else if ( "2" == s ) {
                EncryptionWrapper.testDecrypt();
            }
            Console.WriteLine("Test end.");
        }
    }
}
