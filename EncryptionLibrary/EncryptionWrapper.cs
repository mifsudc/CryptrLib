using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace EncryptionLibrary {
    class EncryptionWrapper {

        public static List<string> DECRYPTION_ERROR = new List<string>();

        private string path = "enctest.txt";

        private byte[] IV;
        private byte[] key;

        public EncryptionWrapper(string path) {
            this.path = path;
            key = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            //IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            IV = new byte[] { 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            Console.WriteLine("IV byte array len: {0}", IV.Length);
        }

        public void encryptToFile(List<string> payload) {
            using ( Aes aes = Aes.Create() ) {
                //aes.GenerateIV();
                aes.Key = key;
                aes.IV = IV;
                aes.Padding = PaddingMode.Zeros;

                Console.WriteLine("WRITING");
                using ( FileStream file = File.OpenWrite(path) ) {
                    Console.WriteLine("Outgoing IV:");
                    for ( int i = 0; i < 16; i++ ) {
                        Console.Write("{0} ", (char)IV[i]);
                        file.WriteByte(IV[i]);
                    }
                    Console.WriteLine();

                    ICryptoTransform alg = aes.CreateEncryptor(aes.Key, aes.IV);
                    using ( CryptoStream crypto = new CryptoStream(file, alg, CryptoStreamMode.Write) ) {
                        using ( StreamWriter writer = new StreamWriter(crypto) ) {
                            writer.WriteLine("verification");
                            //foreach ( string s in payload ) {
                            //    writer.WriteLine("{0} ", s);
                            //}
                        }
                    }
                }
                Console.WriteLine("Encryption complete.");

                Console.WriteLine("READING");
                using ( FileStream file = File.OpenRead(path) ) {
                    Console.WriteLine("offset {0}", file.Position);
                    Console.WriteLine("Incoming IV:");
                    for ( int i = 0; i < 16; i++ ) {
                        int c = file.ReadByte();
                        Console.Write((char)c);
                    }
                    Console.WriteLine("offset {0}", file.Position);
                    Console.WriteLine();
                    ICryptoTransform alg = aes.CreateDecryptor(aes.Key, aes.IV);
                    using ( CryptoStream crypto = new CryptoStream(file, alg, CryptoStreamMode.Read) ) {
                        Console.WriteLine("offset {0}", file.Position);
                        using ( StreamReader reader = new StreamReader(crypto) ) {
                            Console.WriteLine("offset {0}", file.Position);
                            Console.WriteLine(reader.ReadLine());
                        }
                        Console.WriteLine("Done");
                    }
                }
            }
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
