using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ShieldyCSharpExample
{
    internal static class ShieldyApi
    {
        private static class Utils
        {
            public const string DllFilePath = "lib/native.dll";
            private const string DllFilePathUpdate = "lib/native.update";
            public static string AppSalt;
            public static bool Initialized;
            public static bool DebugMode = true;


            public static string Xor(string val, string key)
            {
                var result = new StringBuilder();
                for (int i = 0; i < val.Length; i++)
                {
                    result.Append((char)(val[i] ^ key[i % key.Length]));
                }

                return result.ToString();
            }

            public static string Xor(string val, List<byte> key)
            {
                var result = new StringBuilder();
                for (int i = 0; i < val.Length; i++)
                {
                    result.Append((char)(val[i] ^ key[i % key.Count]));
                }

                return result.ToString();
            }

            public static List<byte> Xor(List<byte> toEncrypt, string xorKey)
            {
                for (int i = 0; i < toEncrypt.Count; i++)
                {
                    toEncrypt[i] = (byte)(toEncrypt[i] ^ xorKey[i % xorKey.Length]);
                }

                return toEncrypt;
            }

            private static void PerformUpdate()
            {
                if (File.Exists(DllFilePathUpdate))
                {
                    File.Delete(DllFilePath);
                    File.Move(DllFilePathUpdate, DllFilePath);
                }
            }

            private static bool CompareBytearrays(ICollection<byte> a, IList<byte> b)
            {
                if (a.Count != b.Count)
                    return false;
                int i = 0;
                foreach (byte c in a)
                {
                    if (c != b[i])
                        return false;
                    i++;
                }

                return true;
            }

            private static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509Key)
            {
                // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
                byte[] seqOid =
                    { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
                byte[] seq;
                // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
                MemoryStream mem = new MemoryStream(x509Key);
                BinaryReader binr = new BinaryReader(mem); //wrap Memory Stream with BinaryReader for easy reading

                try
                {
                    var twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte(); //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16(); //advance 2 bytes
                    else
                        return null;

                    seq = binr.ReadBytes(15); //read the Sequence OID
                    if (!CompareBytearrays(seq, seqOid)) //make sure Sequence for OID is correct
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes ==
                        0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                        binr.ReadByte(); //advance 1 byte
                    else if (twobytes == 0x8203)
                        binr.ReadInt16(); //advance 2 bytes
                    else
                        return null;

                    var bt = binr.ReadByte();
                    if (bt != 0x00) //expect null byte next
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte(); //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16(); //advance 2 bytes
                    else
                        return null;

                    twobytes = binr.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                        lowbyte = binr.ReadByte(); // read next bytes which is bytes in modulus
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binr.ReadByte(); //advance 2 bytes
                        lowbyte = binr.ReadByte();
                    }
                    else
                        return null;

                    byte[] modint =
                        { lowbyte, highbyte, 0x00, 0x00 }; //reverse byte order since asn.1 key uses big endian order
                    int modsize = BitConverter.ToInt32(modint, 0);

                    byte firstbyte = binr.ReadByte();
                    binr.BaseStream.Seek(-1, SeekOrigin.Current);

                    if (firstbyte == 0x00)
                    {
                        //if first byte (highest order) of modulus is zero, don't include it
                        binr.ReadByte(); //skip this null byte
                        modsize -= 1; //reduce modulus buffer size by 1
                    }

                    byte[] modulus = binr.ReadBytes(modsize); //read the modulus bytes

                    if (binr.ReadByte() != 0x02) //expect an Integer for the exponent data
                        return null;
                    int expbytes =
                        (int)binr
                            .ReadByte(); // should only need one byte for actual exponent data (for all useful values)
                    byte[] exponent = binr.ReadBytes(expbytes);

                    // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                    RSAParameters RSAKeyInfo = new RSAParameters();
                    RSAKeyInfo.Modulus = modulus;
                    RSAKeyInfo.Exponent = exponent;
                    RSA.ImportParameters(RSAKeyInfo);
                    return RSA;
                }
                catch (Exception)
                {
                    return null;
                }

                finally
                {
                    binr.Close();
                }
            }

            public static bool Verify()
            {
                PerformUpdate();
                byte[] buff = File.ReadAllBytes(DllFilePath);

                //get last 256 bytes
                var last256 = new byte[256];
                for (var i = 0; i < 256; i++)
                {
                    last256[i] = buff[buff.Length - 256 + i];
                }

                //get buff without last 256 bytes
                byte[] buffWithoutLast256 = new byte[buff.Length - 256];
                for (int i = 0; i < buffWithoutLast256.Length; i++)
                {
                    buffWithoutLast256[i] = buff[i];
                }

                //get md5 of buff without last 256 bytes
                var md5 = MD5.Create().ComputeHash(buffWithoutLast256);
                //print md5

                RSACryptoServiceProvider rsa = DecodeX509PublicKey(Convert.FromBase64String(
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgb7m2HrJ7M6aiC9VzIOizWZ/XlB0eXSC56W6/ql5pUUjd0rEst6NgN1WuNlgjIjgqaRCIT2cJsX8yekjNSxwCogGcGTKm50i9ueh8SdwXtqIRMe4MHBuGbhimLlzDXhFGCfl8HIl2KpnyzBuIDqmuwNqJFdADXprHLiv066M6P9WKp8S4oIb0Y0s8k7aif7B/4bxHNe6ukI2uvVmAM0hEfq5g1pm2jvvAU9xytv2yWuYQ6u+0SzWkRAlP0MDKV9WsE/AKo9wID+Iod0u9U8tEj6HkiUhQ0V/q0BKjSWGOEUyujVoacVgswLOQU6nVdnntJEoZ9Jf8mOnbyLc6xTDTwIDAQAB"));

                //verify
                if (!rsa.VerifyData(md5, CryptoConfig.MapNameToOID("SHA256"), last256))
                {
                    Console.WriteLine("Verification failed");
                    Environment.Exit(0);
                    return false;
                }

                return true;
            }
        }

        private static class Bindings
        {
            [DllImport(Utils.DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_Initialize(string licenseKey, string appSecret);

            [DllImport(Utils.DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_GetVariable(string variableName, out IntPtr buf, out int size);

            [DllImport(Utils.DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_GetUserProperty(string fileName, out IntPtr buf, out int size);

            [DllImport(Utils.DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_DownloadFile(string secret, out IntPtr fileBuf, out int fileSize);

            [DllImport(Utils.DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_DeobfString(string obfB64, int rounds, out IntPtr buf, out int size);

            [DllImport(Utils.DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_Log(string text);

            [DllImport(Utils.DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_LoginLicenseKey(string licenseKey);

            [DllImport(Utils.DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_LoginUserPass(string username, string password);

            [DllImport(Utils.DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SC_GetLastError();

            [DllImport(Utils.DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_FreeMemory(out IntPtr buf);
        }

        public static bool Initialize(string appGuid, string version, string appSalt)
        {
            Utils.AppSalt = appSalt;

            if (!Utils.Verify()) return false;
            return Bindings.SC_Initialize(appGuid, version);
        }

        public static bool Login(string username, string password)
        {
            if (!Bindings.SC_LoginUserPass(username, password)) return false;
            Utils.Initialized = true;
            return true;
        }

        public static bool Login(string licenseKey)
        {
            if (!Bindings.SC_LoginLicenseKey(licenseKey)) return false;
            Utils.Initialized = true;
            return true;
        }

        public static int GetLastError()
        {
            return Bindings.SC_GetLastError();
        }

        public static string GetVariable(string name)
        {
            IntPtr buf;
            int size;
            bool result = Bindings.SC_GetVariable(name, out buf, out size);
            if (result)
            {
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                var resultVariable = Encoding.UTF8.GetString(data);

                if (!Bindings.SC_FreeMemory(out buf) && Utils.DebugMode)
                {
                    Console.WriteLine("Failed to free memory in GetVariable function for variable: " + name);
                }

                return Utils.Xor(resultVariable, Utils.AppSalt);
            }

            if (Utils.DebugMode) Console.WriteLine("Failed to get variable: " + name);
            return "";
        }

        public static string GetUserProperty(string propertyName)
        {
            IntPtr buf;
            int size;
            bool result = Bindings.SC_GetUserProperty(propertyName, out buf, out size);
            if (result)
            {
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                var resultVariable = Encoding.UTF8.GetString(data);

                if (!Bindings.SC_FreeMemory(out buf) && Utils.DebugMode)
                {
                    Console.WriteLine("Failed to free memory in GetUserProperty function for user property: " +
                                      propertyName);
                }

                return Utils.Xor(resultVariable, Utils.AppSalt);
            }

            if (Utils.DebugMode) Console.WriteLine("Failed to get user property: " + propertyName);
            return "";
        }

        public static string DeobfuscateString(string base64, int rounds)
        {
            IntPtr buf;
            int size;
            bool result = Bindings.SC_DeobfString(base64, rounds, out buf, out size);
            if (result)
            {
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                var resultVariable = Encoding.UTF8.GetString(data);

                if (!Bindings.SC_FreeMemory(out buf) && Utils.DebugMode)
                {
                    Console.WriteLine("Failed to free memory in DeobfuscateString function for str: " + base64 +
                                      " and rounds: " + rounds);
                }

                return Utils.Xor(resultVariable, Utils.AppSalt);
            }

            if (Utils.DebugMode) Console.WriteLine("Failed to deobfuscate string: " + base64);
            return "";
        }

        public static List<byte> DownloadFile(string name)
        {
            IntPtr buf;
            int size;
            bool result = Bindings.SC_DownloadFile(name, out buf, out size);
            if (result)
            {
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);

                if (!Bindings.SC_FreeMemory(out buf) && Utils.DebugMode)
                {
                    Console.WriteLine("Failed to free memory in DownloadFile function for file name: " + name);
                }


                return Utils.Xor(data.ToList(), Utils.AppSalt);
            }

            if (Utils.DebugMode) Console.WriteLine("Failed to download file: " + name);
            return null;
        }
    }

    internal class Program
    {
        private class Credentials
        {
            private string _licenseKey;
            private string _username;
            private string _password;

            public enum CredentialsMode
            {
                UsernamePassword,
                LicenseKey
            }

            public Credentials(string username, string password)
            {
                this._username = username;
                this._password = password;
            }

            public Credentials(string licenseKey)
            {
                this._licenseKey = licenseKey;
            }

            private bool SaveCredentials()
            {
                //save to file credentials.txt
                try
                {
                    //create credentials file
                    if (File.Exists("credentials.txt"))
                    {
                        File.Delete("credentials.txt");
                    }

                    //save credentials to file credentials.txt
                    if (this._licenseKey != null)
                    {
                        File.WriteAllText("credentials.txt", this._licenseKey);
                    }
                    else
                    {
                        File.WriteAllText("credentials.txt", this._username + Environment.NewLine + this._password);
                    }

                    return true;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to save credentials: " + e.Message);
                    return false;
                }
            }


            public Credentials(CredentialsMode mode)
            {
                //read credentials from file
                //get credentials from file credentials.txt
                if (File.Exists("credentials.txt"))
                {
                    var lines = File.ReadAllLines("credentials.txt");
                    switch (lines.Length)
                    {
                        case 2:
                            //valid credentials (username and password)
                            this._username = lines[0];
                            this._password = lines[1];
                            Console.WriteLine(
                                "Found credentials in file credentials.txt, logging in using username and password...");
                            break;
                        case 1:
                            //valid credentials (license key)
                            this._licenseKey = lines[0];
                            Console.WriteLine(
                                "Found credentials in file credentials.txt, logging in using license key...");
                            break;
                        default:
                            //invalid credentials, delete file
                            File.Delete("credentials.txt");
                            throw new Exception("Invalid credentials format in file credentials.txt");
                    }
                }
                else
                {
                    Console.WriteLine("No credentials found in file credentials.txt, please enter your credentials:");
                    switch (mode)
                    {
                        case CredentialsMode.UsernamePassword:
                            Console.WriteLine("Please enter your username:");
                            this._username = Console.ReadLine();
                            Console.WriteLine("Please enter your password:");
                            this._password = Console.ReadLine();
                            SaveCredentials();
                            break;
                        case CredentialsMode.LicenseKey:
                            Console.WriteLine("Please enter your license key:");
                            this._licenseKey = Console.ReadLine();
                            SaveCredentials();
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
                    }
                }
            }

            public string GetUsername()
            {
                return this._username;
            }

            public string GetPassword()
            {
                return this._password;
            }

            public string GetLicenseKey()
            {
                return this._licenseKey;
            }
        }


        public static void Main(string[] args)
        {
            //define credentials mode
            //LicenseKey - use license key to login
            //UsernamePassword - use username and password to login
            Credentials.CredentialsMode mode = Credentials.CredentialsMode.UsernamePassword;

            Console.WriteLine("Please wait, we are checking your account...");

            //initialize
            if (!ShieldyApi.Initialize("76934b5e-2191-47e2-88a2-a05000a3bbf9", "1.0",
                    "6166edbd36aec11af66e722e40baa2c7645387f28efe4e60abcc454723f6439e"))
            {
                Console.WriteLine("Failed to initialize");
                Environment.Exit(0);
            }

            //try to login with credentials from file
            var credentials = new Credentials(mode);
            //login
            /*if (!ShieldyApi.Login("username123", "tajnehaslo"))
             */

            if (!ShieldyApi.Login(credentials.GetUsername(), credentials.GetPassword()))
            {
                Console.WriteLine("Failed to login, error: " + ShieldyApi.GetLastError());
                return;
            }

            Console.WriteLine("Welcome " + ShieldyApi.GetUserProperty("username") + "!");
            Console.WriteLine(ShieldyApi.GetVariable("PerApp"));
            Console.WriteLine(ShieldyApi.DeobfuscateString("qeOIDvtmi0Qd71WRFHUlMg==", 10));

            Console.WriteLine(ShieldyApi.GetUserProperty("hwid"));

            var file = ShieldyApi.DownloadFile("ScoopyNG.zip");
            Console.WriteLine("File size: " + file.Count);
            File.WriteAllBytes("ScoopyNG.zip", file.ToArray());
        }
    }
}