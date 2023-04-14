using System;
using System.IO;

namespace ShieldyCSharpExample
{
    internal static class Program
    {
        /**
         * Credentials handler
         * 
         * This class handles the credentials from the user.
         * It will try to read the credentials from the file credentials.txt.
         * If the file does not exist, it will ask the user to enter the credentials.
         * After fetching the credentials, they will be used to login via the Shieldy API.
         *
         * Support two modes:
         * - UsernamePassword - use username and password to login
         * - LicenseKey - use license key to login
         */
        private class Credentials
        {
            private const string Filename = "credentials.txt";
            private readonly string _licenseKey;
            private readonly string _username;
            private readonly string _password;
            private readonly CredentialsMode _credentialsMode;

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
                //save credentials to file
                try
                {
                    //create credentials file if it does not exist
                    if (!File.Exists(Filename))
                    {
                        File.Delete(Filename);
                    }

                    //save credentials depending on the mode
                    if (this._licenseKey != null)
                    {
                        File.WriteAllText(Filename, this._licenseKey);
                    }
                    else
                    {
                        File.WriteAllText(Filename, this._username + Environment.NewLine + this._password);
                    }

                    return true;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to save credentials: " + e.Message);
                    return false;
                }
            }

            public Credentials(CredentialsMode credentialsMode)
            {
                _credentialsMode = credentialsMode;

                //credentials file does not exist, ask user to enter credentials
                if (!File.Exists(Filename))
                {
                    Console.WriteLine("No credentials found in file " + Credentials.Filename +
                                      ", please enter your credentials:");
                    switch (credentialsMode)
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
                            throw new ArgumentOutOfRangeException(nameof(credentialsMode), credentialsMode, null);
                    }
                }

                //read credentials from file
                var lines = File.ReadAllLines(Filename);
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
                        File.Delete(Filename);
                        throw new Exception("Invalid credentials format in file credentials.txt");
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

            public bool PerformLogin(ShieldyApi api)
            {
                switch (_credentialsMode)
                {
                    case CredentialsMode.UsernamePassword:
                        return api.Login(_username, _password);
                    case CredentialsMode.LicenseKey:
                        return api.Login(_licenseKey);
                    default:
                        return false;
                }
            }
        }

        public static void Main(string[] args)
        {
            //define credentials mode
            //LicenseKey - use license key to login
            //UsernamePassword - use username and password to login
            const Credentials.CredentialsMode mode = Credentials.CredentialsMode.UsernamePassword;

            //initialize api and credentials handler
            var shieldyApi = new ShieldyApi();
            var credentialsHandler = new Credentials(mode);

            //define license key, version and salt
            //you can get your license key from https://dashboard.shieldy.app
            const string licenseKey = "76934b5e-2191-47e2-88a2-a05000a3bbf9";
            const string version = "1.0";
            const string salt = "6166edbd36aec11af66e722e40baa2c7645387f28efe4e60abcc454723f6439e";

            Console.WriteLine("Please wait, we are checking your account...");

            //initialize api, required to be called before any other api function
            if (!shieldyApi.Initialize(licenseKey, version, salt))
            {
                Console.WriteLine("Failed to initialize, error: " + ShieldyApi.GetLastError());
                Environment.Exit(0);
            }

            //try to login with credentials from file, if failed, ask for input and save to file
            if (!credentialsHandler.PerformLogin(shieldyApi))
            {
                Console.WriteLine("Failed to login, error: " + ShieldyApi.GetLastError());
                return;
            }

            Console.WriteLine("Welcome " + shieldyApi.Data.Username + "!");
            Console.WriteLine(shieldyApi.GetVariable("PerApp"));
            Console.WriteLine(shieldyApi.DeobfuscateString("qeOIDvtmi0Qd71WRFHUlMg==", 10));

            Console.WriteLine(shieldyApi.Data.Hwid);
            Console.WriteLine("Files: " + shieldyApi.Data.Files);

            var file = shieldyApi.DownloadFile("ScoopyNG.zip");
            Console.WriteLine("File size: " + file.Count);
            File.WriteAllBytes("ScoopyNG.zip", file.ToArray());

            Console.ReadKey();
        }
    }
}