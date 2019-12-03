using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace EncryptionLibrary {
    class EncryptionWrapper {

        private string path = "enctest.txt";

        private byte[] initialisationVector;
        private byte[] key;

        public EncryptionWrapper(string path) {
            this.path = path;
        }

        public void testDecrypt() {
            if ( !File.Exists(path) )
                return;

            FileStream fs = File.OpenRead(path);
            RijndaelManaged rm = new RijndaelManaged();

            byte[] key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            byte[] iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            CryptoStream cs = new CryptoStream(fs, rm.CreateDecryptor(key, iv), CryptoStreamMode.Read);
            StreamReader sr = new StreamReader(cs);

            while ( !sr.EndOfStream ) {
                Console.WriteLine( sr.ReadLine() );
            }
            Console.WriteLine("End of file.");

            sr.Close();
            cs.Close();
            fs.Close();
            rm.Dispose();
        }

        public void encryptToFile(List<string> payload) {
            // payload validation

            using (Aes aes = Aes.Create() ) {
                Console.WriteLine("Key {0}", aes.Key);
                Console.WriteLine("IV {0}", aes.IV);
                using (FileStream file = File.OpenWrite(path) ) {
                    using (StreamWriter writer = new StreamWriter(file)) {
                        writer.WriteLine(aes.IV);
                    }

                    ICryptoTransform alg = aes.CreateEncryptor(aes.Key, aes.IV);
                    using ( CryptoStream crypto = new CryptoStream(file, alg, CryptoStreamMode.Write) ) {
                        using ( StreamWriter writer = new StreamWriter(crypto) ) {
                            writer.WriteLine("verification");
                            foreach ( string s in payload ) {
                                writer.WriteLine(s);
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

            using ( Aes aes = Aes.Create() ) {
                Console.WriteLine("Key {0}", aes.Key);
                Console.WriteLine("IV {0}", aes.IV);
                using ( FileStream file = File.OpenWrite(path) ) {
                    using ( StreamWriter writer = new StreamWriter(file) ) {
                        writer.WriteLine(aes.IV);
                    }

                    List<String>
                    ICryptoTransform alg = aes.CreateEncryptor(aes.Key, aes.IV);
                    using ( CryptoStream crypto = new CryptoStream(file, alg, CryptoStreamMode.Write) ) {
                        using ( StreamWriter writer = new StreamWriter(crypto) ) {
                            writer.WriteLine("verification");
                            foreach ( string s in payload ) {
                                writer.WriteLine(s);
                            }
                        }
                    }
                }
            }
            return null;
        }

        public void testEncrypt(List<string> payload) {

            FileStream fs = File.OpenWrite(path);
            RijndaelManaged rm = new RijndaelManaged();

            byte[] key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            byte[] iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            CryptoStream cs = new CryptoStream(fs, rm.CreateEncryptor(key, iv), CryptoStreamMode.Write);
            StreamWriter sw = new StreamWriter(cs);

            foreach (string s in payload) {
                sw.WriteLine(s);
            }
            Console.WriteLine("Successfully encrypted to file");

            sw.Close();
            cs.Close();
            fs.Close();
            rm.Dispose();
        }
    }
}
