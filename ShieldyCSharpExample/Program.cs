using System;
using System.IO;

namespace ShieldyCSharpExample
{
    internal static class Program
    {
        private class Credentials
        {
            private readonly string _licenseKey;
            private readonly string _username;
            private readonly string _password;

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
            const Credentials.CredentialsMode mode = Credentials.CredentialsMode.UsernamePassword;

            //define license key, version and salt
            //you can get your license key from https://dashboard.shieldy.app
            const string licenseKey = "76934b5e-2191-47e2-88a2-a05000a3bbf9";
            const string version = "1.0";
            const string salt = "6166edbd36aec11af66e722e40baa2c7645387f28efe4e60abcc454723f6439e";

            Console.WriteLine("Please wait, we are checking your account...");

            //initialize
            if (!ShieldyApi.Initialize(licenseKey, version, salt))
            {
                Console.WriteLine("Failed to initialize, error: " + ShieldyApi.GetLastError());
                Environment.Exit(0);
            }

            //try to login with credentials from file
            var credentials = new Credentials(mode);

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