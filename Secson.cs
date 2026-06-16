Here's a simple console app in .NET 10 with basic security features:

1. Create the Project

```bash
dotnet new console -n SecureConsoleApp
cd SecureConsoleApp
dotnet add package Microsoft.Extensions.Configuration
dotnet add package Microsoft.Extensions.Configuration.Json
dotnet add package Microsoft.Extensions.Configuration.UserSecrets
```

2. Program.cs

```csharp
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;

namespace SecureConsoleApp;

class Program
{
    private static IConfiguration _config;
    private static readonly byte[] Salt = Encoding.UTF8.GetBytes("FixedSaltForDemo"); // In production, use random salt

    static void Main(string[] args)
    {
        // Load configuration
        var builder = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
            .AddUserSecrets<Program>()
            .AddEnvironmentVariables();
        
        _config = builder.Build();

        Console.WriteLine("=== Secure Console App ===");
        Console.WriteLine("1. Login");
        Console.WriteLine("2. Store Secret");
        Console.WriteLine("3. Retrieve Secret");
        Console.WriteLine("4. Exit");
        Console.Write("Choose option: ");

        var choice = Console.ReadLine();

        switch (choice)
        {
            case "1":
                Login();
                break;
            case "2":
                StoreSecret();
                break;
            case "3":
                RetrieveSecret();
                break;
            case "4":
                return;
            default:
                Console.WriteLine("Invalid option");
                break;
        }
    }

    static void Login()
    {
        Console.Write("Username: ");
        var username = Console.ReadLine();
        
        Console.Write("Password: ");
        var password = ReadPassword();

        // Never hardcode credentials! Use secure storage
        var storedPassword = _config["User:Password"] ?? 
                            Environment.GetEnvironmentVariable("APP_PASSWORD") ?? 
                            "default123";

        // Use constant-time comparison to prevent timing attacks
        if (SecureCompare(password, storedPassword))
        {
            Console.WriteLine("\n✅ Login successful!");
        }
        else
        {
            Console.WriteLine("\n❌ Login failed!");
        }
    }

    static void StoreSecret()
    {
        Console.Write("Enter secret to store: ");
        var plainSecret = Console.ReadLine();

        if (string.IsNullOrEmpty(plainSecret))
        {
            Console.WriteLine("Invalid secret");
            return;
        }

        var encrypted = Encrypt(plainSecret);
        var encryptedBase64 = Convert.ToBase64String(encrypted);
        
        // In real app, store in secure database or encrypted file
        File.WriteAllText("secret.encrypted", encryptedBase64);
        Console.WriteLine("✅ Secret stored securely!");
    }

    static void RetrieveSecret()
    {
        if (!File.Exists("secret.encrypted"))
        {
            Console.WriteLine("No secret found");
            return;
        }

        Console.Write("Enter encryption key: ");
        var key = Console.ReadLine();

        try
        {
            var encryptedBase64 = File.ReadAllText("secret.encrypted");
            var encryptedBytes = Convert.FromBase64String(encryptedBase64);
            var decrypted = Decrypt(encryptedBytes, key ?? "");
            
            Console.WriteLine($"📝 Secret: {decrypted}");
        }
        catch
        {
            Console.WriteLine("❌ Failed to decrypt. Wrong key?");
        }
    }

    static byte[] Encrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = DeriveKey(_config["Encryption:Key"] ?? "default-key-change-me");
        aes.GenerateIV();
        
        using var encryptor = aes.CreateEncryptor();
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        
        // Prepend IV to ciphertext
        var result = new byte[aes.IV.Length + cipherBytes.Length];
        Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
        Array.Copy(cipherBytes, 0, result, aes.IV.Length, cipherBytes.Length);
        
        return result;
    }

    static string Decrypt(byte[] cipherTextWithIv, string key)
    {
        using var aes = Aes.Create();
        
        // Extract IV from first 16 bytes
        var iv = new byte[16];
        Array.Copy(cipherTextWithIv, 0, iv, 0, 16);
        aes.IV = iv;
        
        aes.Key = DeriveKey(key);
        
        using var decryptor = aes.CreateDecryptor();
        var cipherBytes = new byte[cipherTextWithIv.Length - 16];
        Array.Copy(cipherTextWithIv, 16, cipherBytes, 0, cipherBytes.Length);
        
        var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
        return Encoding.UTF8.GetString(plainBytes);
    }

    static byte[] DeriveKey(string password)
    {
        using var deriveBytes = new Rfc2898DeriveBytes(
            password,
            Salt,
            10000,
            HashAlgorithmName.SHA256
        );
        return deriveBytes.GetBytes(32); // 256-bit key for AES-256
    }

    static bool SecureCompare(string a, string b)
    {
        if (a.Length != b.Length) return false;
        
        // Constant-time comparison
        int result = 0;
        for (int i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    static string ReadPassword()
    {
        var password = new StringBuilder();
        ConsoleKeyInfo keyInfo;
        
        do
        {
            keyInfo = Console.ReadKey(true);
            if (keyInfo.Key != ConsoleKey.Backspace && keyInfo.Key != ConsoleKey.Enter)
            {
                password.Append(keyInfo.KeyChar);
                Console.Write("*");
            }
            else if (keyInfo.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Remove(password.Length - 1, 1);
                Console.Write("\b \b");
            }
        } while (keyInfo.Key != ConsoleKey.Enter);
        
        return password.ToString();
    }
}
```

3. appsettings.json (optional)

```json
{
  "User": {
    "Password": "SecurePassword123"
  },
  "Encryption": {
    "Key": "ChangeMeInProduction"
  }
}
```

4. Add User Secrets (Development Only)

```bash
dotnet user-secrets init
dotnet user-secrets set "User:Password" "YourStrongPassword"
dotnet user-secrets set "Encryption:Key" "YourEncryptionKey"
```

5. Environment Variables (Production)

```bash
# Windows
setx APP_PASSWORD "YourStrongPassword"

# Linux/Mac
export APP_PASSWORD="YourStrongPassword"
```

Security Features Demonstrated:

1. Password Masking - Hides password input with *
2. Secure Password Storage - Uses User Secrets/Environment Variables
3. AES-256 Encryption - For storing sensitive data
4. Key Derivation - PBKDF2 with 10,000 iterations
5. Constant-Time Comparison - Prevents timing attacks
6. Configuration Sources - Multiple secure sources (user secrets, env vars)
7. Input Validation - Checks for null/empty inputs

Run the App

```bash
dotnet run
```

Important Notes:

· In production, use Azure Key Vault, AWS Secrets Manager, or Windows Credential Manager
· Never hardcode keys or passwords
· Use a random salt per password in production
· Implement proper logging and auditing
· Consider using ASP.NET Core Identity or similar for production auth
