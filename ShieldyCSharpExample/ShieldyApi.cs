using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ShieldyCSharpExample
{
    public class ShieldyApi
    {
        /**
         * ShieldyApi.cs
         *
         * Shieldy API wrapper for C# applications.
         * Contains all the functions needed to interact with the Shieldy Authentication API.
         *
         * Under the hood, this wrapper uses the native.dll file to communicate with the Shieldy Authentication API.
         * The native.dll file is a C++ library that contains the native functions that are called by this wrapper.
         *
         * License: MIT
         * Author: Shieldy
         * Website: https://shieldy.app
         * Copyright (c) 2023 Shieldy
         */

        //native.dll file path, can be changed if needed
        //take note that the native.dll update path must be also changed
        private const string DllFilePath = "lib/native.dll";

        private const string DllFilePathUpdate = "lib/native.update";

        //delegate for callback function
        public delegate void MessageCallbackDelegate(int code, string message);

        public delegate void DownloadCallbackDelegate(float progress);

        private string _appSalt;
        private bool _initialized;
        private static string _currDlFile;
        private const bool DebugMode = true;
        public UserData Data;

        private static class Internals
        {
            public static string XorStr(string val, string key)
            {
                var result = new StringBuilder();
                for (var i = 0; i < val.Length; i++)
                {
                    result.Append((char)(val[i] ^ key[i % key.Length]));
                }

                return result.ToString();
            }

            public static List<byte> XorBytes(List<byte> toEncrypt, string xorKey)
            {
                for (var i = 0; i < toEncrypt.Count; i++)
                {
                    toEncrypt[i] = (byte)(toEncrypt[i] ^ xorKey[i % xorKey.Length]);
                }

                return toEncrypt;
            }

            public static string Xor(string val, IList<byte> key)
            {
                var result = new StringBuilder();
                for (var i = 0; i < val.Length; i++)
                {
                    result.Append((char)(val[i] ^ key[i % key.Count]));
                }

                return result.ToString();
            }

            public static void PerformUpdate()
            {
                //FIXME
                /*if (!File.Exists(DllFilePathUpdate)) return;

                //update file exists, delete old file and replace with new one
                File.Delete(DllFilePath);
                File.Move(DllFilePathUpdate, DllFilePath);*/
            }

            private static bool CompareBytearrays(ICollection<byte> a, IList<byte> b)
            {
                if (a.Count != b.Count)
                    return false;
                var i = 0;
                foreach (var c in a)
                {
                    if (c != b[i])
                        return false;
                    i++;
                }

                return true;
            }

            public static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509Key)
            {
                // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
                byte[] seqOid =
                    { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
                // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
                var memoryStream = new MemoryStream(x509Key);
                var binaryReader =
                    new BinaryReader(memoryStream); //wrap Memory Stream with BinaryReader for easy reading

                try
                {
                    var twobytes = binaryReader.ReadUInt16();
                    switch (twobytes)
                    {
                        //data read as little endian order (actual data order for Sequence is 30 81)
                        case 0x8130:
                            binaryReader.ReadByte(); //advance 1 byte
                            break;
                        case 0x8230:
                            binaryReader.ReadInt16(); //advance 2 bytes
                            break;
                        default:
                            return null;
                    }

                    var seq = binaryReader.ReadBytes(15);
                    if (!CompareBytearrays(seq, seqOid)) //make sure Sequence for OID is correct
                        return null;

                    twobytes = binaryReader.ReadUInt16();
                    switch (twobytes)
                    {
                        //data read as little endian order (actual data order for Bit String is 03 81)
                        case 0x8103:
                            binaryReader.ReadByte(); //advance 1 byte
                            break;
                        case 0x8203:
                            binaryReader.ReadInt16(); //advance 2 bytes
                            break;
                        default:
                            return null;
                    }

                    var bt = binaryReader.ReadByte();
                    if (bt != 0x00) //expect null byte next
                        return null;

                    twobytes = binaryReader.ReadUInt16();
                    switch (twobytes)
                    {
                        //data read as little endian order (actual data order for Sequence is 30 81)
                        case 0x8130:
                            binaryReader.ReadByte(); //advance 1 byte
                            break;
                        case 0x8230:
                            binaryReader.ReadInt16(); //advance 2 bytes
                            break;
                        default:
                            return null;
                    }

                    twobytes = binaryReader.ReadUInt16();
                    byte lowbyte;
                    byte highbyte = 0x00;

                    switch (twobytes)
                    {
                        //data read as little endian order (actual data order for Integer is 02 81)
                        case 0x8102:
                            lowbyte = binaryReader.ReadByte(); // read next bytes which is bytes in modulus
                            break;
                        case 0x8202:
                            highbyte = binaryReader.ReadByte(); //advance 2 bytes
                            lowbyte = binaryReader.ReadByte();
                            break;
                        default:
                            return null;
                    }

                    byte[] modint =
                        { lowbyte, highbyte, 0x00, 0x00 }; //reverse byte order since asn.1 key uses big endian order
                    var modsize = BitConverter.ToInt32(modint, 0);

                    var firstbyte = binaryReader.ReadByte();
                    binaryReader.BaseStream.Seek(-1, SeekOrigin.Current);

                    if (firstbyte == 0x00)
                    {
                        //if first byte (highest order) of modulus is zero, don't include it
                        binaryReader.ReadByte(); //skip this null byte
                        modsize -= 1; //reduce modulus buffer size by 1
                    }

                    var modulus = binaryReader.ReadBytes(modsize); //read the modulus bytes

                    if (binaryReader.ReadByte() != 0x02) //expect an Integer for the exponent data
                        return null;
                    var expbytes =
                        (int)binaryReader
                            .ReadByte(); // should only need one byte for actual exponent data (for all useful values)
                    var exponent = binaryReader.ReadBytes(expbytes);

                    // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                    var rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                    var rsaKeyInfo = new RSAParameters
                    {
                        Modulus = modulus,
                        Exponent = exponent
                    };
                    rsaCryptoServiceProvider.ImportParameters(rsaKeyInfo);
                    return rsaCryptoServiceProvider;
                }
                catch (Exception)
                {
                    return null;
                }

                finally
                {
                    binaryReader.Close();
                }
            }
        }

        public class UserData
        {
            public string Hwid { get; set; }
            public int HwidLimit { get; set; }
            public long LastAccessDate { get; set; }
            public string LastAccessIp { get; set; }
            public int UserId { get; set; }
            public string Username { get; set; }
            public List<string> Files { get; set; }
            public List<string> Variables { get; set; }
            public Access Accesses { get; set; }
        }

        public class Access
        {
            public long Created { get; set; }
            public long Expiry { get; set; }
            public int Level { get; set; }
            public string Name { get; set; }
        }

        private static class Bindings
        {
            //TODO
            public static void DefaultMessageCallbackFunction(int code, string message)
            {
                Console.WriteLine("[INFO] code: " + code + " " + message);
            }

            public static void DefaultDownloadProgressFunction(float progress)
            {
                if (float.IsNaN(progress) || float.IsInfinity(progress)) return;
                if (_currDlFile == "") return;
                if (progress == 100)
                {
                    Console.Write("\r[INFO] File '" + _currDlFile + "' downloaded.             \n");
                    _currDlFile = "";
                    return;
                }
                Console.Write("\r[INFO] Downloading file '" + _currDlFile + "' -> " + progress + "%");
            }

            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_Initialize(string licenseKey, string appSecret,
                [MarshalAs(UnmanagedType.FunctionPtr)] MessageCallbackDelegate msgCallback,
                [MarshalAs(UnmanagedType.FunctionPtr)] DownloadCallbackDelegate downloadProgressCallback);

            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_GetVariable(string variableName, out IntPtr buf, out int size);

            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_GetUserProperty(string fileName, out IntPtr buf, out int size);

            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_DownloadFile(string secret, out IntPtr fileBuf, out int fileSize);

            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_DeobfString(string obfB64, int rounds, out IntPtr buf, out int size);

            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_Log(string text);

            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_LoginLicenseKey(string licenseKey);

            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_LoginUserPass(string username, string password);

            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SC_GetLastError();

            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_FreeMemory(out IntPtr buf);
        }

        /**
        * Verifies the authenticity of the ShieldyCore auth dll by checking if it is signed with a Shieldy private key.
        * The last 256 bytes of the dll contain the signed sha256 of the dll without the last 256 bytes (dll before signing).
        * This function verifies the dll by comparing the sha256 of the dll without the last 256 bytes with the signed sha256.
        * If the sha256 is the same, the dll is verified and deemed to be from Shieldy and not from a malicious source.
        */
        private static string GetPublicKey()
        {
            var encryptedBytes = new byte[]
            {
                0x70, 0x64, 0x64, 0x69, 0x64, 0x81, 0x5c, 0x5d,
                0x59, 0x76, 0x42, 0x5c, 0x43, 0x42, 0x54, 0x26,
                0x64, 0x46, 0x5b, 0x29, 0x2c, 0xec, 0x28, 0x25,
                0x1c, 0xec, 0xee, 0xea, 0xec, 0xec, 0x23, 0xdc,
                0xf0, 0xe4, 0xe4, 0xe9, 0xea, 0x06, 0xb2, 0xda,
                0xdc, 0xbc, 0xd8, 0xac, 0xc6, 0xc9, 0x16, 0xd0,
                0x09, 0xa3, 0x99, 0xa1, 0xd6, 0xa0, 0xd5, 0xbc,
                0x94, 0x9a, 0xd4, 0x65, 0x91, 0x74, 0x5e, 0x94,
                0x61, 0x66, 0x31, 0xce, 0x33, 0x7f, 0x59, 0x8b,
                0x78, 0x33, 0x3a, 0x2a, 0x98, 0x95, 0x36, 0x95,
                0x8e, 0x1c, 0x4f, 0x58, 0x1b, 0xf8, 0xf8, 0x11,
                0x37, 0x5b, 0x19, 0xe8, 0x1a, 0x17, 0x55, 0xdd,
                0xf6, 0xed, 0x1c, 0xe6, 0xd8, 0xdd, 0xff, 0x06,
                0xd1, 0xa4, 0xc1, 0xf6, 0xdc, 0xbc, 0xa9, 0x9a,
                0xb4, 0xa7, 0xd9, 0xca, 0xa1, 0x9a, 0x83, 0xe3,
                0xa4, 0xb8, 0x82, 0x81, 0x5d, 0x7a, 0x63, 0x96,
                0x5a, 0x8e, 0x76, 0x56, 0x8a, 0x66, 0x37, 0x32,
                0x50, 0x88, 0x9b, 0x44, 0x94, 0x58, 0x48, 0x53,
                0x63, 0x2a, 0x37, 0x46, 0xf3, 0x17, 0x0c, 0xf4,
                0xe9, 0xf0, 0x38, 0x57, 0xe0, 0xf3, 0xd9, 0x08,
                0xd6, 0xf9, 0x03, 0x04, 0x00, 0xdf, 0xff, 0xe1,
                0xd7, 0xb3, 0xc3, 0xd5, 0xa6, 0xaa, 0xc5, 0xcf,
                0xe3, 0xa3, 0xa4, 0xbf, 0xd9, 0xa2, 0x8b, 0xbd,
                0xa4, 0xa1, 0x69, 0x98, 0x64, 0x67, 0x8c, 0x90,
                0x88, 0x86, 0x6d, 0x5c, 0x61, 0x65, 0x87, 0x5c,
                0x57, 0x33, 0x5b, 0x59, 0x23, 0x1f, 0x54, 0x55,
                0x8b, 0x85, 0x85, 0x20, 0x55, 0xeb, 0x64, 0xf6,
                0xf2, 0x1b, 0x53, 0xfa, 0x57, 0xfe, 0xf4, 0xf9,
                0x4b, 0xb4, 0x1b, 0xda, 0x13, 0x02, 0x16, 0xfc,
                0xd4, 0xf5, 0x06, 0xa9, 0xfe, 0x17, 0xb9, 0xa3,
                0xb3, 0xad, 0xb8, 0x05, 0x98, 0xc2, 0x74, 0xc9,
                0x88, 0x85, 0x65, 0x80, 0x6c, 0x60, 0xcb, 0x93,
                0x58, 0x75, 0x5c, 0x98, 0x86, 0x8c, 0x4b, 0x50,
                0x89, 0x51, 0x45, 0x45, 0x2c, 0x38, 0x64, 0x23,
                0x24, 0x47, 0x45, 0x59, 0x14, 0xf6, 0x18, 0x04,
                0xec, 0x45, 0x08, 0x42, 0x5b, 0xfa, 0xe1, 0xf6,
                0x12, 0xe9, 0xec, 0xff, 0xbb, 0x0b, 0xe0, 0xd7,
                0xb2, 0xa5, 0x14, 0xa6, 0xda, 0xa8, 0xfe, 0x9c,
                0xb2, 0xce, 0xd4, 0xc6, 0xa4, 0xa7, 0xd2, 0x74,
                0x8e, 0xb7, 0xdb, 0x98, 0xd4, 0x78, 0xa3, 0x87,
                0x58, 0x91, 0xc5, 0x63, 0x82, 0x54, 0x38, 0x53,
                0x2c, 0x9b, 0x25, 0x8e, 0x5c, 0x8b, 0x19, 0x32,
                0x51, 0x2a, 0x26, 0x16, 0x1e, 0x28, 0xf8, 0x24,
                0x08, 0x11, 0xe5, 0x0e, 0x0c, 0x0a, 0xf5, 0x06,
                0x0a, 0x06, 0xef, 0xee, 0xbc, 0xb8, 0x15, 0xfd,
                0xa5, 0xf7, 0xcd, 0xcd, 0xd7, 0xa1, 0xa8, 0xbe,
                0x81, 0xd4, 0xa1, 0xb5, 0xd3, 0xc0, 0x9e, 0xbd,
                0xb9, 0x94, 0x6f, 0x8a, 0xd5, 0x63, 0x77, 0x57,
                0x67, 0x86, 0x64, 0x67, 0x6c, 0x2c, 0x5c, 0x59,
                0x9b
            };

            for (var m = 0; m < encryptedBytes.Length; ++m)
            {
                var c = encryptedBytes[m];
                c += 0x6c;
                c = (byte)-c;
                c -= (byte)m;
                c = (byte)~c;
                c += (byte)m;
                c ^= 0x97;
                c += (byte)m;
                c = (byte)-c;
                c -= (byte)m;
                c = (byte)~c;
                c += 0xee;
                c = (byte)~c;
                c += 0xa5;
                c ^= 0xd9;
                c = (byte)~c;
                encryptedBytes[m] = c;
            }

            //get all bytes except last one
            var encryptedBytesWithoutLast = new byte[encryptedBytes.Length - 1];
            for (var i = 0; i < encryptedBytesWithoutLast.Length; i++)
            {
                encryptedBytesWithoutLast[i] = encryptedBytes[i];
            }

            return Encoding.UTF8.GetString(encryptedBytesWithoutLast);
        }

        private static bool VerifyLibrary()
        {
            //check if dll update file exists, if so replace dll with it
            Internals.PerformUpdate();

            var buff = File.ReadAllBytes(DllFilePath);

            //get last 256 bytes
            var last256 = new byte[256];
            for (var i = 0; i < 256; i++)
            {
                last256[i] = buff[buff.Length - 256 + i];
            }

            //get buff without last 256 bytes
            var buffWithoutLast256 = new byte[buff.Length - 256];
            for (var i = 0; i < buffWithoutLast256.Length; i++)
            {
                buffWithoutLast256[i] = buff[i];
            }

            //get sha256 of buff without last 256 bytes
            var nativeSha256Hash = SHA256.Create().ComputeHash(buffWithoutLast256);

            var rsaCryptoServiceProvider = Internals.DecodeX509PublicKey(Convert.FromBase64String(GetPublicKey()));

            //verify
            if (rsaCryptoServiceProvider.VerifyData(nativeSha256Hash, CryptoConfig.MapNameToOID("SHA256"), last256))
            {
                return true;
            }

            if (DebugMode) Console.WriteLine("Verification of dll failed.");
            Environment.Exit(0);
            return false;
        }

        public bool Initialize(string appGuid, string version, string appSalt, MessageCallbackDelegate callbackDelegate, DownloadCallbackDelegate downloadCallbackDelegate)
        {
            _appSalt = appSalt;
            if (!VerifyLibrary()) return false;

            if (callbackDelegate == null)
            {
                //use default callback delegate
                callbackDelegate = Bindings.DefaultMessageCallbackFunction;
            }
            if (downloadCallbackDelegate == null)
            {
                //use default download callback delegate
                downloadCallbackDelegate = Bindings.DefaultDownloadProgressFunction;
            }

            _initialized = Bindings.SC_Initialize(appGuid, version, callbackDelegate, downloadCallbackDelegate);
            return _initialized;
        }

        public bool Login(string username, string password)
        {
            if (!_initialized)
            {
                if (DebugMode) Console.WriteLine("You must initialize the library before logging in.");
                return false;
            }

            if (Bindings.SC_LoginUserPass(username, password))
            {
                FillUserData();
                return true;
            }

            if (DebugMode) Console.WriteLine("Login failed. Error code: " + Bindings.SC_GetLastError());
            return false;
        }

        public bool Login(string licenseKey)
        {
            if (!_initialized)
            {
                if (DebugMode) Console.WriteLine("You must initialize the library before logging in.");
                return false;
            }

            if (Bindings.SC_LoginLicenseKey(licenseKey))
            {
                FillUserData();
                return true;
            }

            if (DebugMode) Console.WriteLine("Login failed. Error code: " + Bindings.SC_GetLastError());
            return false;
        }

        private void FillUserData()
        {
            try
            {
                Data = new UserData
                {
                    Username = GetUserProperty("username"),
                    UserId = int.Parse(GetUserProperty("userId")),
                    LastAccessIp = GetUserProperty("lastAccessIp"),
                    LastAccessDate = long.Parse(GetUserProperty("lastAccessDate")),
                    HwidLimit = int.Parse(GetUserProperty("hwidLimit")),
                    Hwid = GetUserProperty("hwid"),
                    Accesses = new Access
                    {
                        Name = GetUserProperty("accessLevelName"),
                        Level = int.Parse(GetUserProperty("accessLevel")),
                        Created = long.Parse(GetUserProperty("accessCreated")),
                        Expiry = long.Parse(GetUserProperty("accessExpiry"))
                    },
                    Variables = new List<string>(),
                    Files = new List<string>()
                };

                var variables = GetUserProperty("variables");
                variables.Split(';').ToList().ForEach(x => Data.Variables.Add(x));

                var files = GetUserProperty("files");
                files.Split(';').ToList().ForEach(x => Data.Files.Add(x));
            }
            catch (Exception e)
            {
                if (DebugMode) Console.WriteLine("Failed to fill user data. Error: " + e.Message);
            }
        }

        public static int GetLastError()
        {
            return Bindings.SC_GetLastError();
        }

        public string GetVariable(string name)
        {
            if (!_initialized)
            {
                if (DebugMode) Console.WriteLine("You must initialize the library before logging in.");
                return "";
            }

            var result = Bindings.SC_GetVariable(name, out var buf, out var size);
            if (result)
            {
                var data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                var resultVariable = Encoding.UTF8.GetString(data);

                if (!Bindings.SC_FreeMemory(out buf) && DebugMode)
                {
                    Console.WriteLine("Failed to free memory in GetVariable function for variable: " + name);
                }

                return Internals.XorStr(resultVariable, _appSalt);
            }

            if (DebugMode) Console.WriteLine("Failed to get variable: " + name);
            return "";
        }

        private string GetUserProperty(string propertyName)
        {
            if (!_initialized)
            {
                if (DebugMode) Console.WriteLine("You must initialize the library before logging in.");
                return "";
            }

            var result = Bindings.SC_GetUserProperty(propertyName, out var buf, out var size);
            if (result)
            {
                var data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                var resultVariable = Encoding.UTF8.GetString(data);

                if (!Bindings.SC_FreeMemory(out buf) && DebugMode)
                {
                    Console.WriteLine("Failed to free memory in GetUserProperty function for user property: " +
                                      propertyName);
                }

                return Internals.XorStr(resultVariable, _appSalt);
            }

            if (DebugMode) Console.WriteLine("Failed to get user property: " + propertyName);
            return "";
        }

        public string DeobfuscateString(string base64, int rounds)
        {
            if (!_initialized)
            {
                if (DebugMode) Console.WriteLine("You must initialize the library before logging in.");
                return "";
            }

            var result = Bindings.SC_DeobfString(base64, rounds, out var buf, out var size);
            if (result)
            {
                var data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                var resultVariable = Encoding.UTF8.GetString(data);

                if (!Bindings.SC_FreeMemory(out buf) && DebugMode)
                {
                    Console.WriteLine("Failed to free memory in DeobfuscateString function for str: " + base64 +
                                      " and rounds: " + rounds);
                }

                return Internals.XorStr(resultVariable, _appSalt);
            }

            if (DebugMode) Console.WriteLine("Failed to deobfuscate string: " + base64);
            return "";
        }

        public List<byte> DownloadFile(string name)
        {
            _currDlFile = name;
            if (!_initialized)
            {
                if (DebugMode) Console.WriteLine("You must initialize the library before logging in.");
                return null;
            }

            var result = Bindings.SC_DownloadFile(name, out var buf, out var size);
            _currDlFile = "";
            if (result)
            {
                var data = new byte[size];
                Marshal.Copy(buf, data, 0, size);

                if (!Bindings.SC_FreeMemory(out buf) && DebugMode)
                {
                    Console.WriteLine("Failed to free memory in DownloadFile function for file name: " + name);
                }


                return Internals.XorBytes(data.ToList(), _appSalt);
            }

            if (DebugMode) Console.WriteLine("Failed to download file: " + name);

            return null;
        }
    }
}