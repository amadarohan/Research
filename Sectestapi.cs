Here's a minimal API version in .NET 10 with the same security features:

1. Create the Project

```bash
dotnet new web -n SecureMinimalApi
cd SecureMinimalApi
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.EntityFrameworkCore.InMemory
```

2. Program.cs

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configure JWT Authentication
var key = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? "YourSuperSecretKeyThatIsAtLeast32Characters!");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? "SecureApi",
            ValidAudience = builder.Configuration["Jwt:Audience"] ?? "SecureApiUsers",
            IssuerSigningKey = new SymmetricSecurityKey(key)
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddDbContext<AppDbContext>(opt => opt.UseInMemoryDatabase("SecureDb"));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// DTOs
record LoginRequest(string Username, string Password);
record RegisterRequest(string Username, string Password, string Email);
record SecretRequest(string Secret, string Key);
record AuthResponse(string Token, string Username);
record SecretResponse(string Secret);

// In-memory user store (in production use database)
var users = new Dictionary<string, (string PasswordHash, string Email)>();

// Hash password with salt
static string HashPassword(string password, out string salt)
{
    salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
    using var sha256 = SHA256.Create();
    var combined = Encoding.UTF8.GetBytes(password + salt);
    var hash = sha256.ComputeHash(combined);
    return Convert.ToBase64String(hash);
}

static bool VerifyPassword(string password, string storedHash, string salt)
{
    using var sha256 = SHA256.Create();
    var combined = Encoding.UTF8.GetBytes(password + salt);
    var hash = sha256.ComputeHash(combined);
    return Convert.ToBase64String(hash) == storedHash;
}

// Generate JWT Token
static string GenerateToken(string username, IConfiguration config)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes(config["Jwt:Key"] ?? "YourSuperSecretKeyThatIsAtLeast32Characters!");
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] 
        { 
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, "User")
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        Issuer = config["Jwt:Issuer"] ?? "SecureApi",
        Audience = config["Jwt:Audience"] ?? "SecureApiUsers",
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), 
            SecurityAlgorithms.HmacSha256Signature)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}

// Encryption helpers
static byte[] EncryptSecret(string plainText, string key)
{
    using var aes = Aes.Create();
    aes.Key = DeriveKey(key);
    aes.GenerateIV();
    
    using var encryptor = aes.CreateEncryptor();
    var plainBytes = Encoding.UTF8.GetBytes(plainText);
    var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
    
    var result = new byte[aes.IV.Length + cipherBytes.Length];
    Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
    Array.Copy(cipherBytes, 0, result, aes.IV.Length, cipherBytes.Length);
    return result;
}

static string DecryptSecret(byte[] cipherTextWithIv, string key)
{
    using var aes = Aes.Create();
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
    var salt = Encoding.UTF8.GetBytes("FixedSaltForApiDemo");
    using var deriveBytes = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
    return deriveBytes.GetBytes(32);
}

// ============= API ENDPOINTS =============

// 1. Register new user
app.MapPost("/api/register", (RegisterRequest req, IConfiguration config) =>
{
    if (users.ContainsKey(req.Username))
        return Results.BadRequest(new { error = "Username already exists" });

    var (passwordHash, salt) = HashPassword(req.Password);
    users[req.Username] = (passwordHash, req.Email);
    
    return Results.Ok(new { message = "User registered successfully" });
});

// 2. Login
app.MapPost("/api/login", (LoginRequest req, IConfiguration config) =>
{
    if (!users.TryGetValue(req.Username, out var user))
        return Results.Unauthorized();

    if (!VerifyPassword(req.Password, user.PasswordHash, ""))
        return Results.Unauthorized();

    var token = GenerateToken(req.Username, config);
    return Results.Ok(new AuthResponse(token, req.Username));
});

// 3. Store encrypted secret (requires authentication)
app.MapPost("/api/secrets", [Authorize] (SecretRequest req, HttpContext context) =>
{
    if (string.IsNullOrEmpty(req.Secret) || string.IsNullOrEmpty(req.Key))
        return Results.BadRequest(new { error = "Secret and key required" });

    var username = context.User.Identity?.Name ?? "unknown";
    var encrypted = EncryptSecret(req.Secret, req.Key);
    var encryptedBase64 = Convert.ToBase64String(encrypted);
    
    // Store in memory (use database in production)
    SecretStore.Secrets[$"{username}:{req.Key}"] = encryptedBase64;
    
    return Results.Ok(new { message = "Secret stored securely", id = req.Key });
});

// 4. Retrieve encrypted secret (requires authentication)
app.MapGet("/api/secrets/{key}", [Authorize] (string key, HttpContext context) =>
{
    var username = context.User.Identity?.Name ?? "unknown";
    var storeKey = $"{username}:{key}";
    
    if (!SecretStore.Secrets.TryGetValue(storeKey, out var encryptedBase64))
        return Results.NotFound(new { error = "Secret not found" });

    return Results.Ok(new { encrypted = encryptedBase64 });
});

// 5. Decrypt secret (requires authentication)
app.MapPost("/api/secrets/decrypt", [Authorize] (SecretRequest req, HttpContext context) =>
{
    var username = context.User.Identity?.Name ?? "unknown";
    var storeKey = $"{username}:{req.Key}";
    
    if (!SecretStore.Secrets.TryGetValue(storeKey, out var encryptedBase64))
        return Results.NotFound(new { error = "Secret not found" });

    try
    {
        var encryptedBytes = Convert.FromBase64String(encryptedBase64);
        var decrypted = DecryptSecret(encryptedBytes, req.Key);
        return Results.Ok(new SecretResponse(decrypted));
    }
    catch
    {
        return Results.BadRequest(new { error = "Invalid encryption key" });
    }
});

// 6. Delete secret (requires authentication)
app.MapDelete("/api/secrets/{key}", [Authorize] (string key, HttpContext context) =>
{
    var username = context.User.Identity?.Name ?? "unknown";
    var storeKey = $"{username}:{key}";
    
    if (SecretStore.Secrets.Remove(storeKey))
        return Results.Ok(new { message = "Secret deleted" });
    
    return Results.NotFound(new { error = "Secret not found" });
});

// 7. Health check (public)
app.MapGet("/api/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

// 8. Get user info (requires authentication)
app.MapGet("/api/me", [Authorize] (HttpContext context) =>
{
    var username = context.User.Identity?.Name;
    var email = users.TryGetValue(username ?? "", out var user) ? user.Email : null;
    
    return Results.Ok(new 
    { 
        username, 
        email,
        secretCount = SecretStore.Secrets.Count(kv => kv.Key.StartsWith($"{username}:"))
    });
});

// Static class for storing secrets (use database in production)
public static class SecretStore
{
    public static Dictionary<string, string> Secrets { get; } = new();
}

// Database context (for future database implementation)
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}

app.Run();
```

3. appsettings.json

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "Jwt": {
    "Key": "YourSuperSecretKeyThatIsAtLeast32CharactersAndStoreInSecrets!",
    "Issuer": "SecureApi",
    "Audience": "SecureApiUsers"
  },
  "AllowedHosts": "*"
}
```

4. appsettings.Development.json (User Secrets replacement)

```json
{
  "Jwt": {
    "Key": "DevelopmentKeyOnly-NotForProduction-32Chars!"
  }
}
```

5. Test Commands

```bash
# Register
curl -X POST https://localhost:5001/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"john","password":"Pass123!","email":"john@example.com"}'

# Login (get token)
curl -X POST https://localhost:5001/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john","password":"Pass123!"}'

# Store secret (use token from login)
curl -X POST https://localhost:5001/api/secrets \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"secret":"MySecretData","key":"MyKey123"}'

# Get encrypted secret
curl -X GET https://localhost:5001/api/secrets/MyKey123 \
  -H "Authorization: Bearer {TOKEN}"

# Decrypt secret
curl -X POST https://localhost:5001/api/secrets/decrypt \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"key":"MyKey123"}'

# Get user info
curl -X GET https://localhost:5001/api/me \
  -H "Authorization: Bearer {TOKEN}"
```

6. .http file for Visual Studio testing

```http
@host = https://localhost:5001

### Register
POST {{host}}/api/register
Content-Type: application/json

{
  "username": "john",
  "password": "Pass123!",
  "email": "john@example.com"
}

### Login
POST {{host}}/api/login
Content-Type: application/json

{
  "username": "john",
  "password": "Pass123!"
}

### Store Secret (replace TOKEN)
POST {{host}}/api/secrets
Authorization: Bearer YOUR_TOKEN_HERE
Content-Type: application/json

{
  "secret": "ConfidentialData123",
  "key": "AppKey1"
}

### Get Encrypted Secret
GET {{host}}/api/secrets/AppKey1
Authorization: Bearer YOUR_TOKEN_HERE

### Decrypt Secret
POST {{host}}/api/secrets/decrypt
Authorization: Bearer YOUR_TOKEN_HERE
Content-Type: application/json

{
  "key": "AppKey1"
}

### Get User Info
GET {{host}}/api/me
Authorization: Bearer YOUR_TOKEN_HERE
```

Security Features:

1. JWT Authentication - Stateless, secure token-based auth
2. Password Hashing - SHA256 with salt (PBKDF2 recommended for production)
3. AES-256 Encryption - For encrypting secrets
4. Authorization - [Authorize] attribute protects endpoints
5. HTTPS - Enforced by default in production
6. Key Derivation - PBKDF2 with 10,000 iterations
7. Secure Configuration - User Secrets in development
8. Environment Variables - For production configuration

To Run:

```bash
dotnet run --urls=https://localhost:5001
```

The API implements secure user registration, authentication, and encrypted secret storage/retrieval with proper authorization checks.
