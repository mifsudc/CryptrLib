using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using DevOne.Security.Cryptography.BCrypt; 

namespace EncryptionLibrary {

    static class EncryptionWrapper {
        public static (byte[], string, byte[]) preparePassword(string pass) {
            string salt = BCryptHelper.GenerateSalt();
            string bHash = BCryptHelper.HashPassword(pass, salt);

            byte[] intermediary = new byte[31];
            for (int i = 0; i < 31; i++ )
                intermediary[i] = Convert.ToByte( bHash[i+29] );

            byte[] shaHash;
            using ( var sha = SHA256.Create() )
                shaHash = sha.ComputeHash(Encoding.UTF8.GetBytes(bHash));
   
            return (shaHash, salt, intermediary);
        }


        public static void encryptToFile(string path, List<string> payload, byte[] key, string salt, byte[] hash) {
            using ( var aes = Aes.Create() ) {
                // Set up aes encryptor
                aes.Key = key;
                aes.Padding = PaddingMode.Zeros;

                using ( var file = new FileStream(path, FileMode.Truncate, FileAccess.Write) ) {
                    // Prepend salt
                    for ( int i = 0; i < 29; i++ )
                        file.WriteByte(Convert.ToByte(salt[i]));

                    // Prepend IV
                    aes.GenerateIV();
                    for ( int i = 0; i < 16; i++ )
                        file.WriteByte(aes.IV[i]);

                    ICryptoTransform alg = aes.CreateEncryptor(aes.Key, aes.IV);
                    using ( var crypto = new CryptoStream(file, alg, CryptoStreamMode.Write) ) {
                        // Prepend encoded verification hash
                        for ( int i = 0; i < 31; i++ )
                            crypto.WriteByte(hash[i]);

                        // Write encoded payload
                        using ( var writer = new StreamWriter(crypto) ) {
                            foreach ( string s in payload )
                                writer.WriteLine(s);
                            writer.Flush();
                        }
                    }
                }
            }
        }


        public static List<string> decryptFromFile(string path, string pass, byte[] key) {
            var payload = new List<string>();

            using ( var aes = Aes.Create() ) {
                // Setup aes decryptor
                aes.Key = key;
                aes.Padding = PaddingMode.Zeros;

                using ( FileStream file = File.OpenRead(path) ) {
                    // Read salt
                    string salt = string.Empty;
                    for ( int i = 0; i < 29; i++ )
                        salt += Convert.ToChar(file.ReadByte());

                    // Read iv
                    byte[] iv = new byte[16];
                    for ( int i = 0; i < 16; i++ )
                        iv[i] = Convert.ToByte(file.ReadByte());
                    aes.IV = iv;

                    ICryptoTransform alg = aes.CreateDecryptor(aes.Key, aes.IV);
                    using ( var crypto = new CryptoStream(file, alg, CryptoStreamMode.Read) ) {
                        // Read encoded verification hash
                        var hash = new byte[31];
                        for ( int i = 0; i < 31; i++ )
                            hash[i] = Convert.ToByte(crypto.ReadByte());

                        string hashed = salt + Encoding.UTF8.GetString(hash);
                        if ( BCryptHelper.CheckPassword(pass, hashed) ) {
                            using ( var reader = new StreamReader(crypto) ) {
                                // Read encoded payload
                                payload.Add(reader.ReadLine());
                                while ( !reader.EndOfStream )
                                    payload.Add(reader.ReadLine());
                            }
                        }
                        else throw new Exception("Verification Error.");
                    }
                }
            }
            return payload;
        }


    }
}
