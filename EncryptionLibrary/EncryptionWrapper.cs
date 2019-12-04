using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace EncryptionLibrary {
    class EncryptionWrapper {

        public static List<string> DECRYPTION_ERROR = new List<string>();

        private string path = "enctest.txt";

        private byte[] initialisationVector;
        private byte[] key;

        public EncryptionWrapper(string path) {
            this.path = path;
            key = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
        }

        public void encryptToFile(List<string> payload) {
            // payload validation

            using (Aes aes = Aes.Create() ) {
                aes.Key = key;
                aes.GenerateIV();
                Console.WriteLine("Key {0}", aes.Key);
                Console.Write("IV :");
                foreach (int i in Encoding.UTF8.GetString(aes.IV).ToCharArray() ) {
                    Console.Write(i);
                }
                Console.WriteLine();
                Console.WriteLine("IV {0}", Encoding.UTF8.GetString(aes.IV));
                using (FileStream file = File.OpenWrite(path) ) {
                    using (StreamWriter writer = new StreamWriter(file)) {
                        writer.WriteLine(Encoding.UTF8.GetString(aes.IV));
                    }

                    ICryptoTransform alg = aes.CreateEncryptor(aes.Key, aes.IV);
                    using ( CryptoStream crypto = new CryptoStream(file, alg, CryptoStreamMode.Write) ) {
                        using ( StreamWriter writer = new StreamWriter(crypto) ) {
                            writer.WriteLine("verification");
                            foreach ( string s in payload ) {
                                writer.WriteLine("{0} ", s);
                            }
                        }
                    }
                }
            }
            Console.WriteLine("Encryption complete.");
        }

        public string decryptFromFile() {
            if ( key == null )
                return null;

            List<string> plainText = new List<string>();
            using ( Aes aes = Aes.Create() ) {
                aes.Key = key;
                Console.WriteLine("Key {0}", aes.Key);
                Console.WriteLine("IV {0}", aes.IV);
                using ( FileStream file = File.OpenRead(path) ) {
                    using ( StreamReader reader = new StreamReader(file) ) {
                        string iv = reader.ReadLine();
                        aes.Key = Encoding.UTF8.GetBytes(iv);
                        Console.WriteLine("IV string: {0}", iv);
                        Console.WriteLine("IV bytes: {0}", aes.IV);
                    }

                    ICryptoTransform alg = aes.CreateEncryptor(aes.Key, aes.IV);
                    using ( CryptoStream crypto = new CryptoStream(file, alg, CryptoStreamMode.Read) ) {
                        using ( StreamReader reader = new StreamReader(crypto) ) {
                            if (reader.ReadLine().CompareTo("verification") != 0)
                                return "Verification failed.";

                            while ( !reader.EndOfStream ) {
                                string s = reader.ReadLine();
                                Console.WriteLine(s);
                                plainText.Add( s );
                            }
                        }
                    }
                }
            }
            return plainText[0] ?? "Nothing there.";
        }
    }
}
