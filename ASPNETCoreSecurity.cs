Here are 15 code challenges with solutions, categorized into Beginner, Intermediate, and Senior levels, to help you master ASP.NET Core security concepts as outlined in the document. These challenges cover key topics like XSS, CSRF, authentication, authorization, secure data storage, and more.

---

### **Beginner Level**

#### **Challenge 1: Prevent XSS in Razor Views**
**Task**: Create a Razor view that displays user-supplied input safely by escaping HTML.  
**Solution**:  
```html
<!-- In your Razor view -->
@model string

<!-- Safe output (auto-escaped) -->
<p>@Model</p>

<!-- Unsafe output (avoid this!) -->
<p>@Html.Raw(Model)</p>
```
**Explanation**: The `@` syntax automatically HTML-encodes output, while `Html.Raw()` bypasses escaping and should be avoided for untrusted input.

---

#### **Challenge 2: Implement CSRF Protection in a Form**
**Task**: Add anti-forgery token validation to a form in an ASP.NET Core MVC application.  
**Solution**:  
```html
<!-- In your Razor view -->
<form asp-action="Submit" method="post">
    @Html.AntiForgeryToken()
    <input type="text" name="data" />
    <button type="submit">Submit</button>
</form>
```
```csharp
// In your controller
[HttpPost]
[ValidateAntiForgeryToken]
public IActionResult Submit(string data)
{
    // Process data
    return View();
}
```
**Explanation**: The `@Html.AntiForgeryToken()` generates a token, and `[ValidateAntiForgeryToken]` ensures it is validated on submission.

---

#### **Challenge 3: Configure Secure Cookies**
**Task**: Configure cookie settings to include `HttpOnly` and `Secure` flags.  
**Solution**:  
```csharp
// In Program.cs
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.Secure = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
});
```
**Explanation**: `HttpOnly` prevents client-side script access, and `Secure` ensures cookies are sent only over HTTPS.

---

#### **Challenge 4: Validate User Input with Data Annotations**
**Task**: Create a model with validation attributes to ensure input meets requirements.  
**Solution**:  
```csharp
public class UserModel
{
    [Required]
    [StringLength(100, MinimumLength = 3)]
    public string Name { get; set; }

    [EmailAddress]
    public string Email { get; set; }
}
```
```csharp
// In your controller
[HttpPost]
public IActionResult Register(UserModel model)
{
    if (!ModelState.IsValid)
    {
        return View(model);
    }
    // Proceed if valid
}
```
**Explanation**: Data annotations enforce validation rules, and `ModelState.IsValid` checks compliance.

---

#### **Challenge 5: Use Secret Manager for Development Secrets**
**Task**: Store a database connection string using the Secret Manager tool.  
**Solution**:  
1. Right-click the project > **Manage User Secrets**.  
2. Add to `secrets.json`:  
```json
{
  "ConnectionStrings": {
    "Default": "YourConnectionString"
  }
}
```
3. Access in `Program.cs`:  
```csharp
var connectionString = builder.Configuration.GetConnectionString("Default");
```
**Explanation**: Secrets are stored outside the project directory to avoid accidental commits.

---

### **Intermediate Level**

#### **Challenge 6: Implement Password Hashing with ASP.NET Core Identity**
**Task**: Hash a password using ASP.NET Core Identity's `PasswordHasher`.  
**Solution**:  
```csharp
var hasher = new PasswordHasher<IdentityUser>();
string hashedPassword = hasher.HashPassword(null, "YourPassword");

// Verify
var result = hasher.VerifyHashedPassword(null, hashedPassword, "YourPassword");
if (result == PasswordVerificationResult.Success)
{
    // Password is correct
}
```
**Explanation**: The `PasswordHasher` uses PBKDF2 with a salt by default.

---

#### **Challenge 7: Configure Content Security Policy (CSP)**
**Task**: Add a CSP header to restrict script sources to 'self'.  
**Solution**:  
```csharp
// In Program.cs
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
    await next();
});
```
**Explanation**: CSP mitigates XSS by whitelisting trusted sources for scripts, styles, and other resources.

---

#### **Challenge 8: Prevent Mass Assignment with `[Bind]`**
**Task**: Use `[Bind]` to allow only specific properties for model binding.  
**Solution**:  
```csharp
[HttpPost]
public IActionResult Update([Bind("Name,Email")] UserModel user)
{
    // Only Name and Email are bound
}
```
**Explanation**: `[Bind]` creates an allowlist to prevent overposting attacks.

---

#### **Challenge 9: Secure Health Check Endpoints**
**Task**: Add authentication to a health check endpoint.  
**Solution**:  
```csharp
// In Program.cs
builder.Services.AddHealthChecks();
app.UseEndpoints(endpoints =>
{
    endpoints.MapHealthChecks("/health").RequireAuthorization();
});
```
**Explanation**: Health checks should be protected to avoid exposing sensitive system info.

---

#### **Challenge 10: Implement Custom Error Pages**
**Task**: Redirect to a custom error page for 404 and 500 errors.  
**Solution**:  
```csharp
// In Program.cs
app.UseStatusCodePagesWithReExecute("/Error/{0}");
app.UseExceptionHandler("/Error/500");
```
```csharp
// In ErrorController
public IActionResult Index(int? statusCode = null)
{
    return View(statusCode);
}
```
**Explanation**: Custom error pages avoid leaking stack traces or system details.

---

### **Senior Level**

#### **Challenge 11: Secure JWT Authentication for APIs**
**Task**: Configure JWT bearer authentication for an API.  
**Solution**:  
```csharp
// In Program.cs
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = "YourIssuer",
            ValidAudience = "YourAudience",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("YourSecretKey"))
        };
    });
```
**Explanation**: JWTs are validated for issuer, audience, and signature.

---

#### **Challenge 12: Implement Two-Factor Authentication (2FA)**
**Task**: Enable TOTP-based 2FA in ASP.NET Core Identity.  
**Solution**:  
```csharp
// In your controller
var user = await _userManager.GetUserAsync(User);
var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

// Verify
var result = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", token);
```
**Explanation**: TOTP tokens add a second layer of security.

---

#### **Challenge 13: Scan for Vulnerable NuGet Packages**
**Task**: Use the CLI to check for vulnerable dependencies.  
**Solution**:  
```bash
dotnet list package --vulnerable --include-transitive
```
**Explanation**: Regularly auditing dependencies mitigates risks from known vulnerabilities.

---

#### **Challenge 14: Secure File Uploads**
**Task**: Validate file uploads to prevent malicious files.  
**Solution**:  
```csharp
[HttpPost]
public IActionResult Upload(IFormFile file)
{
    var allowedExtensions = new[] { ".jpg", ".png" };
    var extension = Path.GetExtension(file.FileName).ToLower();
    if (!allowedExtensions.Contains(extension))
    {
        return BadRequest("Invalid file type.");
    }
    // Process file
}
```
**Explanation**: Whitelisting extensions prevents uploading executable files.

---

#### **Challenge 15: Audit Security Headers with a Middleware**
**Task**: Create middleware to enforce security headers.  
**Solution**:  
```csharp
// In Program.cs
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("Referrer-Policy", "no-referrer");
    await next();
});
```
**Explanation**: Headers like `X-Frame-Options` prevent clickjacking.

---

### **Bonus Challenge: OAuth 2.0 with IdentityServer**
**Task**: Configure IdentityServer for OAuth 2.0 authorization code flow.  
**Solution**:  
```csharp
// In IdentityServer config
services.AddIdentityServer()
    .AddInMemoryClients(new[]
    {
        new Client
        {
            ClientId = "client",
            AllowedGrantTypes = GrantTypes.Code,
            RedirectUris = { "https://client/callback" },
            ClientSecrets = { new Secret("secret".Sha256()) }
        }
    });
```
**Explanation**: IdentityServer provides a certified OpenID Connect implementation.

---

Here are **10 advanced-level challenges** focused on secure password storage, cryptographic techniques, secret management, and encryption in ASP.NET Core. These will deepen your mastery of security best practices beyond the intermediate level.

---

### **Challenge 16: Custom Password Hashing with Salt (PBKDF2)**
**Task**: Implement PBKDF2 with a cryptographically random salt (without ASP.NET Core Identity).  
**Solution**:  
```csharp
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

public string HashPassword(string password)
{
    // Generate a 128-bit salt
    byte[] salt = new byte[16];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(salt);
    }

    // Hash the password with PBKDF2 (100,000 iterations)
    string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
        password: password,
        salt: salt,
        prf: KeyDerivationPrf.HMACSHA256,
        iterationCount: 100_000,
        numBytesRequested: 32));

    // Combine salt and hash for storage (format: salt:hash)
    return $"{Convert.ToBase64String(salt)}:{hashed}";
}

public bool VerifyPassword(string storedHash, string inputPassword)
{
    var parts = storedHash.Split(':');
    var salt = Convert.FromBase64String(parts[0]);
    var hashedPassword = parts[1];

    string newHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
        password: inputPassword,
        salt: salt,
        prf: KeyDerivationPrf.HMACSHA256,
        iterationCount: 100_000,
        numBytesRequested: 32));

    return hashedPassword == newHash;
}
```
**Key Points**:  
- Uses `RandomNumberGenerator` for secure salt generation.  
- PBKDF2 with HMAC-SHA256 and high iteration count (100,000) to resist brute-force attacks.  
- Salt is stored alongside the hash for verification.  

---

### **Challenge 17: Migrate from Weak Hashes (MD5/SHA1) to Argon2**
**Task**: Upgrade legacy password hashes (stored as MD5) to Argon2 with salt.  
**Solution**:  
1. Install the `LibHac.Net` NuGet package for Argon2.  
```csharp
using Konscious.Security.Cryptography;

public string HashWithArgon2(string password, byte[] salt)
{
    using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
    {
        argon2.Salt = salt;
        argon2.DegreeOfParallelism = 4;  // 4 threads
        argon2.MemorySize = 65536;       // 64MB memory cost
        argon2.Iterations = 4;           // 4 passes
        return Convert.ToBase64String(argon2.GetBytes(32)); // 32-byte hash
    }
}

// Migration logic for existing MD5 passwords
public string UpgradeHash(string md5Hash, string password)
{
    byte[] salt = new byte[16];
    RandomNumberGenerator.Fill(salt); // .NET 6+
    string newHash = HashWithArgon2(password, salt);
    return $"{Convert.ToBase64String(salt)}:{newHash}";
}
```
**Key Points**:  
- Argon2 is memory-hard, resistant to GPU/ASIC attacks.  
- Salt is generated per-password.  
- Legacy hashes are upgraded during user login.  

---

### **Challenge 18: Secure Secret Storage with Azure Key Vault**
**Task**: Fetch a database connection string from Azure Key Vault in production.  
**Solution**:  
1. Install `Azure.Security.KeyVault.Secrets` and `Azure.Identity`.  
```csharp
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

// In Program.cs
builder.Configuration.AddAzureKeyVault(
    new Uri("https://your-keyvault-name.vault.azure.net/"),
    new DefaultAzureCredential());

// Access secret
string connectionString = builder.Configuration["DatabaseConnectionString"];
```
**Key Points**:  
- Uses Managed Identity or service principal for authentication.  
- Secrets are never hardcoded or stored in config files.  

---

### **Challenge 19: Encrypt Sensitive Data with AES in ASP.NET Core**
**Task**: Encrypt/decrypt user PII (e.g., SSN) using AES-256-GCM.  
**Solution**:  
```csharp
using System.Security.Cryptography;

public class AesEncryptionService
{
    private readonly byte[] _key; // 256-bit key (stored in Key Vault)

    public AesEncryptionService(IConfiguration config)
    {
        _key = Convert.FromBase64String(config["AesEncryptionKey"]);
    }

    public (string Ciphertext, byte[] Nonce, byte[] Tag) Encrypt(string plaintext)
    {
        byte[] nonce = new byte[12]; // 96-bit nonce
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(_key);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[16]; // 128-bit tag

        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        return (Convert.ToBase64String(ciphertext), nonce, tag);
    }

    public string Decrypt(string ciphertext, byte[] nonce, byte[] tag)
    {
        using var aes = new AesGcm(_key);
        byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
        byte[] plaintext = new byte[ciphertextBytes.Length];

        aes.Decrypt(nonce, ciphertextBytes, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }
}
```
**Key Points**:  
- AES-GCM provides authenticated encryption.  
- Nonce (IV) is generated randomly per encryption.  
- Key is fetched from a secure store (e.g., Key Vault).  

---

### **Challenge 20: Secure Session Management with Redis and Data Protection**
**Task**: Store ASP.NET Core session data in Redis with encryption.  
**Solution**:  
1. Install `Microsoft.Extensions.Caching.StackExchangeRedis` and `Microsoft.AspNetCore.DataProtection.StackExchangeRedis`.  
```csharp
// In Program.cs
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
});

builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(ConnectionMultiplexer.Connect("RedisConnectionString"), "DataProtection-Keys")
    .SetApplicationName("MyApp");

builder.Services.AddSession(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.Secure = true;
    options.IdleTimeout = TimeSpan.FromMinutes(20);
});
```
**Key Points**:  
- Session data is encrypted using ASP.NET Core's Data Protection API.  
- Keys are persisted in Redis for distributed scenarios.  

---

### **Challenge 21: Dynamic CSP Nonce Generation for Inline Scripts**
**Task**: Allow inline scripts in CSP using a nonce.  
**Solution**:  
```csharp
// Middleware to generate nonce
app.Use(async (context, next) =>
{
    var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    context.Items["Nonce"] = nonce;
    context.Response.Headers.Add("Content-Security-Policy", 
        $"script-src 'self' 'nonce-{nonce}'");
    await next();
});

// In Razor view
<script nonce="@Context.Items["Nonce"]">
    // Your inline script
</script>
```
**Key Points**:  
- Nonce is cryptographically random and regenerated per request.  
- Only scripts with matching nonce execute.  

---

### **Challenge 22: Secure Logging of Sensitive Data (Redaction)**
**Task**: Redact PII (e.g., emails) from logs using Serilog.  
**Solution**:  
1. Install `Serilog` and `Serilog.Expressions`.  
```csharp
// In Program.cs
Log.Logger = new LoggerConfiguration()
    .Enrich.FromLogContext()
    .Destructure.ByTransforming<Person>(p => new { p.Name, Email = "REDACTED" })
    .WriteTo.Console()
    .CreateLogger();

// Usage
logger.LogInformation("User {User} logged in", new Person("Alice", "alice@example.com"));
```
**Key Points**:  
- Destructuring rules redact sensitive fields.  
- Logs show: `User { Name: "Alice", Email: "REDACTED" }`.  

---

### **Challenge 23: Hardware-Backed Key Storage (HSM) with Data Protection**
**Task**: Configure ASP.NET Core to use Azure Key Vault HSM for key storage.  
**Solution**:  
```csharp
builder.Services.AddDataProtection()
    .PersistKeysToAzureKeyVault(
        new Uri("https://your-keyvault.vault.azure.net/keys/DataProtection-Keys/"),
        new DefaultAzureCredential());
```
**Key Points**:  
- Keys are generated and stored in FIPS 140-2 Level 2+ HSM.  
- No private key material leaves the HSM.  

---

### **Challenge 24: Secure Password Reset with Time-Limited Tokens**
**Task**: Generate a time-limited, single-use token for password reset.  
**Solution**:  
```csharp
public string GeneratePasswordResetToken(string userId)
{
    byte[] tokenData = new byte[32];
    RandomNumberGenerator.Fill(tokenData);
    string token = Convert.ToBase64String(tokenData);

    // Store token with expiry (e.g., 1 hour)
    _cache.Set($"pwd_reset:{userId}", token, TimeSpan.FromHours(1));
    return token;
}

public bool ValidatePasswordResetToken(string userId, string token)
{
    string storedToken = _cache.Get<string>($"pwd_reset:{userId}");
    return storedToken != null && storedToken == token;
}
```
**Key Points**:  
- Token is cryptographically random and expires after 1 hour.  
- Cache (e.g., Redis) ensures single-use.  

---

### **Challenge 25: Secure File Encryption at Rest**
**Task**: Encrypt uploaded files using AES-256-CBC before saving to disk.  
**Solution**:  
```csharp
public async Task SaveEncryptedFile(IFormFile file, string outputPath, byte[] key)
{
    using var aes = Aes.Create();
    aes.Key = key;
    aes.GenerateIV();

    using var output = new FileStream(outputPath, FileMode.Create);
    await output.WriteAsync(aes.IV, 0, aes.IV.Length); // Prepend IV

    using var cryptoStream = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write);
    await file.CopyToAsync(cryptoStream);
}
```
**Key Points**:  
- IV is prepended to the file for decryption.  
- Key is managed separately (e.g., Key Vault).  

---

### **Challenge 26: Secure Configuration Binding with Options Pattern**
**Task**: Bind sensitive configuration to a strongly-typed object and validate it.  
**Solution**:  
```csharp
public class DatabaseSettings
{
    [Required]
    public string ConnectionString { get; set; }

    [Range(1, 100)]
    public int Timeout { get; set; }
}

// In Program.cs
builder.Services.AddOptions<DatabaseSettings>()
    .BindConfiguration("Database")
    .ValidateDataAnnotations()
    .Validate(s => s.ConnectionString.Contains("Encrypt=True"), "Require encrypted connection.");
```
**Key Points**:  
- Configuration is validated using data annotations and custom rules.  
- Prevents misconfiguration (e.g., missing encryption).  

---

### **Final Notes**  
- **Always** store keys/secrets in secure systems (Azure Key Vault, AWS Secrets Manager).  
- **Benchmark** cryptographic operations (e.g., Argon2 iterations) to balance security and performance.  
- **Audit** your security setup with tools like OWASP ZAP or `dotnet list package --vulnerable`.  

These challenges cover real-world scenarios where security is critical. Let me know if you'd like deeper dives into specific areas!

Here are **10 code challenges with solutions** focused on **authentication, authorization, roles, and claims** in ASP.NET Core. These range from basic to advanced scenarios, covering JWT, policies, custom attributes, and more.

---

### **Challenge 1: Basic JWT Authentication**
**Task**: Secure an API endpoint with JWT authentication.  
**Solution**:  
```csharp
// Program.cs
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = "https://your-issuer.com",
            ValidAudience = "https://your-audience.com",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your-256-bit-secret"))
        };
    });

// Controller
[ApiController]
[Route("api/[controller]")]
[Authorize] // Requires any valid JWT
public class SecureController : ControllerBase
{
    [HttpGet("data")]
    public IActionResult GetData() => Ok("Authorized!");
}
```
**Key Points**:  
- Uses `[Authorize]` to require a valid JWT.  
- Configured `JwtBearer` middleware to validate tokens.  

---

### **Challenge 2: Role-Based Authorization**
**Task**: Restrict an endpoint to users with the **"Admin"** role.  
**Solution**:  
```csharp
[HttpGet("admin-only")]
[Authorize(Roles = "Admin")] // Only users with "Admin" role can access
public IActionResult AdminOnly() => Ok("Admin access granted.");
```
**How to Assign Roles**:  
When generating a JWT, include the role claim:  
```csharp
var claims = new List<Claim>
{
    new Claim(ClaimTypes.Name, "user1"),
    new Claim(ClaimTypes.Role, "Admin") // Add role
};
```

---

### **Challenge 3: Policy-Based Authorization**
**Task**: Create a custom policy requiring users to have a **"CanEdit"** claim.  
**Solution**:  
```csharp
// Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanEdit", policy => 
        policy.RequireClaim("CanEdit", "true"));
});

// Controller
[HttpGet("edit")]
[Authorize(Policy = "CanEdit")] // Requires "CanEdit=true" claim
public IActionResult Edit() => Ok("You can edit!");
```

---

### **Challenge 4: Dynamic Claims Transformation**
**Task**: Add runtime claims (e.g., user permissions) to a JWT.  
**Solution**:  
```csharp
// Custom ClaimsTransformer
public class ClaimsTransformer : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity!.IsAuthenticated)
        {
            var identity = (ClaimsIdentity)principal.Identity;
            identity.AddClaim(new Claim("CustomClaim", "Value"));
        }
        return Task.FromResult(principal);
    }
}

// Program.cs
builder.Services.AddTransient<IClaimsTransformation, ClaimsTransformer>();
```

---

### **Challenge 5: Custom Authorization Attribute**
**Task**: Create an attribute to check if a user has a **specific email domain**.  
**Solution**:  
```csharp
public class EmailDomainAttribute : AuthorizeAttribute, IAuthorizationFilter
{
    private readonly string _domain;

    public EmailDomainAttribute(string domain) => _domain = domain;

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var userEmail = context.HttpContext.User.FindFirst(ClaimTypes.Email)?.Value;
        if (userEmail == null || !userEmail.EndsWith($"@{_domain}"))
        {
            context.Result = new ForbidResult();
        }
    }
}

// Usage
[HttpGet("domain-only")]
[EmailDomain("company.com")] // Only allows company.com emails
public IActionResult DomainOnly() => Ok("Access granted.");
```

---

### **Challenge 6: Claims-Based Access Control (CBAC)**
**Task**: Allow access only if a user has a **"Department=IT"** claim.  
**Solution**:  
```csharp
// Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ITOnly", policy => 
        policy.RequireClaim("Department", "IT"));
});

// Controller
[HttpGet("it-dashboard")]
[Authorize(Policy = "ITOnly")]
public IActionResult ITDashboard() => Ok("IT dashboard loaded.");
```

---

### **Challenge 7: Multiple Roles or Claims**
**Task**: Allow access if a user has **either "Admin" or "Editor"** role.  
**Solution**:  
```csharp
[HttpGet("admin-or-editor")]
[Authorize(Roles = "Admin,Editor")] // Requires Admin OR Editor
public IActionResult AdminOrEditor() => Ok("Access granted.");
```

---

### **Challenge 8: Resource-Based Authorization**
**Task**: Check if a user owns a resource (e.g., can edit their own post).  
**Solution**:  
```csharp
public class PostOwnerRequirement : IAuthorizationRequirement { }

public class PostOwnerHandler : AuthorizationHandler<PostOwnerRequirement, Post>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PostOwnerRequirement requirement,
        Post post)
    {
        if (context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value == post.OwnerId)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}

// Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("PostOwner", policy =>
        policy.Requirements.Add(new PostOwnerRequirement()));
});
builder.Services.AddSingleton<IAuthorizationHandler, PostOwnerHandler>();

// Controller
[HttpPut("posts/{id}")]
[Authorize(Policy = "PostOwner")]
public IActionResult UpdatePost(int id, Post post) => Ok("Updated.");
```

---

### **Challenge 9: Time-Based Access (JWT Expiry + Custom Logic)**
**Task**: Deny access to an endpoint **after business hours (5 PM)**.  
**Solution**:  
```csharp
public class BusinessHoursAttribute : AuthorizeAttribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var now = DateTime.Now;
        if (now.Hour >= 17) // 5 PM
        {
            context.Result = new ForbidResult();
        }
    }
}

// Usage
[HttpGet("business-only")]
[BusinessHours]
public IActionResult BusinessHoursOnly() => Ok("Access granted during business hours.");
```

---

### **Challenge 10: Two-Factor Authentication (2FA) Check**
**Task**: Allow access only if 2FA is enabled for the user.  
**Solution**:  
```csharp
[HttpGet("high-security")]
[Authorize]
public IActionResult HighSecurity()
{
    var has2FA = User.Claims.Any(c => c.Type == "amr" && c.Value == "mfa");
    if (!has2FA)
    {
        return Forbid();
    }
    return Ok("High-security access granted.");
}
```

---

### **Bonus: Testing Auth in Swagger**
**Task**: Configure Swagger to accept JWT for testing.  
**Solution**:  
```csharp
// Program.cs
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});
```

---
# Preventing SQL Injection in ASP.NET Core Without ORM

When not using an ORM like Entity Framework, you need to be extra careful to prevent SQL injection attacks. Here are the best approaches:

## 1. Use Parameterized Queries (Strongly Recommended)

```csharp
// Good - Parameterized query
public async Task<User> GetUserById(int userId)
{
    using (var connection = new SqlConnection(_connectionString))
    {
        await connection.OpenAsync();
        
        var query = "SELECT * FROM Users WHERE UserId = @UserId";
        
        return await connection.QueryFirstOrDefaultAsync<User>(query, new { UserId = userId });
    }
}
```

## 2. Using ADO.NET with Parameters

```csharp
// Using SqlCommand with parameters
public async Task<User> GetUserById(int userId)
{
    using (var connection = new SqlConnection(_connectionString))
    {
        await connection.OpenAsync();
        
        using (var command = new SqlCommand("SELECT * FROM Users WHERE UserId = @UserId", connection))
        {
            command.Parameters.AddWithValue("@UserId", userId);
            
            using (var reader = await command.ExecuteReaderAsync())
            {
                if (await reader.ReadAsync())
                {
                    return new User
                    {
                        UserId = reader.GetInt32(0),
                        Username = reader.GetString(1)
                        // ...
                    };
                }
            }
        }
    }
    return null;
}
```

## 3. Stored Procedures (Another Safe Option)

```csharp
public async Task<User> GetUserById(int userId)
{
    using (var connection = new SqlConnection(_connectionString))
    {
        await connection.OpenAsync();
        
        using (var command = new SqlCommand("sp_GetUserById", connection))
        {
            command.CommandType = CommandType.StoredProcedure;
            command.Parameters.AddWithValue("@UserId", userId);
            
            // Execute and process results...
        }
    }
}
```

## What NOT to Do (SQL Injection Vulnerabilities)

```csharp
// BAD - String concatenation (SQL injection risk!)
public async Task<User> GetUserById(int userId)
{
    using (var connection = new SqlConnection(_connectionString))
    {
        await connection.OpenAsync();
        
        // Vulnerable to SQL injection!
        var query = $"SELECT * FROM Users WHERE UserId = {userId}";
        
        return await connection.QueryFirstOrDefaultAsync<User>(query);
    }
}
```

## Additional Security Measures

1. **Input Validation**: Always validate user input before using it in queries
   ```csharp
   if (userId <= 0) throw new ArgumentException("Invalid user ID");
   ```

2. **Principle of Least Privilege**: Database user should have only necessary permissions

3. **Use Dapper**: While not a full ORM, Dapper makes parameterized queries easier
   ```csharp
   // With Dapper
   var user = await connection.QuerySingleOrDefaultAsync<User>(
       "SELECT * FROM Users WHERE Username = @username", 
       new { username = inputUsername });
   ```

4. **Sanitize Inputs**: For dynamic SQL (when absolutely necessary), sanitize inputs

Remember that parameterized queries are the most reliable defense against SQL injection, as they ensure user input is always treated as data rather than executable code.
