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
        
        private string _appSalt;
        private bool _initialized;
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
                if (!File.Exists(DllFilePathUpdate)) return;

                //update file exists, delete old file and replace with new one
                File.Delete(DllFilePath);
                File.Move(DllFilePathUpdate, DllFilePath);
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
            [DllImport(DllFilePath, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool SC_Initialize(string licenseKey, string appSecret);

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
        * The last 256 bytes of the dll contain the signed md5 of the dll without the last 256 bytes (dll before signing).
        * This function verifies the dll by comparing the md5 of the dll without the last 256 bytes with the signed md5.
        * If the md5 is the same, the dll is verified and deemed to be from Shieldy and not from a malicious source.
        */
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

            //get md5 of buff without last 256 bytes
            var md5 = MD5.Create().ComputeHash(buffWithoutLast256);
            //print md5

            var rsaCryptoServiceProvider = Internals.DecodeX509PublicKey(Convert.FromBase64String(
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgb7m2HrJ7M6aiC9VzIOizWZ/XlB0eXSC56W6/ql5pUUjd0rEst6NgN1WuNlgjIjgqaRCIT2cJsX8yekjNSxwCogGcGTKm50i9ueh8SdwXtqIRMe4MHBuGbhimLlzDXhFGCfl8HIl2KpnyzBuIDqmuwNqJFdADXprHLiv066M6P9WKp8S4oIb0Y0s8k7aif7B/4bxHNe6ukI2uvVmAM0hEfq5g1pm2jvvAU9xytv2yWuYQ6u+0SzWkRAlP0MDKV9WsE/AKo9wID+Iod0u9U8tEj6HkiUhQ0V/q0BKjSWGOEUyujVoacVgswLOQU6nVdnntJEoZ9Jf8mOnbyLc6xTDTwIDAQAB"));

            //verify
            if (rsaCryptoServiceProvider.VerifyData(md5, CryptoConfig.MapNameToOID("SHA256"), last256)) return true;

            if (DebugMode) Console.WriteLine("Verification of dll failed.");
            Environment.Exit(0);
            return false;
        }

        public bool Initialize(string appGuid, string version, string appSalt)
        {
            _appSalt = appSalt;
            if (!VerifyLibrary()) return false;

            _initialized = Bindings.SC_Initialize(appGuid, version);
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
            if (!_initialized)
            {
                if (DebugMode) Console.WriteLine("You must initialize the library before logging in.");
                return null;
            }

            var result = Bindings.SC_DownloadFile(name, out var buf, out var size);
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