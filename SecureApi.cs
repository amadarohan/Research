Here's a complete implementation of authentication and authorization with roles and policies in a .NET 10 Web API using Minimal APIs.

Project Setup

First, create the project:

```bash
dotnet new web -n AuthMinimalApi
cd AuthMinimalApi
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package Microsoft.EntityFrameworkCore.Design
```

Complete Implementation

1. Program.cs (Main Entry Point)

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// Configure Database
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite("Data Source=auth.db"));

// Configure Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

// Configure Authorization Policies
builder.Services.AddAuthorization(options =>
{
    // Role-based policies
    options.AddPolicy("AdminOnly", policy => 
        policy.RequireRole("Admin"));
    
    options.AddPolicy("UserOrAdmin", policy => 
        policy.RequireRole("User", "Admin"));
    
    // Custom policy with requirements
    options.AddPolicy("CanDeleteUsers", policy =>
        policy.Requirements.Add(new UserDeletionRequirement()));
});

// Register custom authorization handler
builder.Services.AddScoped<IAuthorizationHandler, UserDeletionHandler>();

var app = builder.Build();

// Initialize Database
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.EnsureCreatedAsync();
    await SeedData(db);
}

app.UseAuthentication();
app.UseAuthorization();

// ============================================
// AUTHENTICATION ENDPOINTS
// ============================================

app.MapPost("/api/auth/login", async (LoginRequest request, AppDbContext db, IConfiguration config) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => 
        u.Username == request.Username && u.Password == request.Password);
    
    if (user == null)
        return Results.Unauthorized();

    var token = GenerateJwtToken(user, config);
    return Results.Ok(new { Token = token });
});

// ============================================
// PUBLIC ENDPOINTS (No Authentication)
// ============================================

app.MapGet("/api/public", () => 
    Results.Ok(new { Message = "Public endpoint - anyone can access" }));

// ============================================
// AUTHENTICATED ENDPOINTS (Any authenticated user)
// ============================================

app.MapGet("/api/user/profile", async (ClaimsPrincipal user, AppDbContext db) =>
{
    var userId = int.Parse(user.FindFirst(ClaimTypes.NameIdentifier)?.Value);
    var dbUser = await db.Users.FindAsync(userId);
    return Results.Ok(new { 
        Username = dbUser?.Username, 
        Role = dbUser?.Role 
    });
}).RequireAuthorization();

// ============================================
// ROLE-BASED ENDPOINTS
// ============================================

// Admin only endpoint
app.MapGet("/api/admin/dashboard", () =>
    Results.Ok(new { Message = "Admin dashboard - only admins can access" }))
    .RequireAuthorization("AdminOnly");

// User or Admin endpoint
app.MapGet("/api/user/data", () =>
    Results.Ok(new { Message = "User data - accessible by Users and Admins" }))
    .RequireAuthorization("UserOrAdmin");

// ============================================
// POLICY-BASED ENDPOINTS
// ============================================

// Custom policy for user deletion
app.MapDelete("/api/admin/users/{id}", async (int id, AppDbContext db) =>
{
    var user = await db.Users.FindAsync(id);
    if (user == null)
        return Results.NotFound();
    
    db.Users.Remove(user);
    await db.SaveChangesAsync();
    return Results.Ok(new { Message = $"User {id} deleted successfully" });
}).RequireAuthorization("CanDeleteUsers");

// ============================================
// ACTION-BASED AUTHORIZATION
// ============================================

app.MapPost("/api/admin/users", async (CreateUserRequest request, AppDbContext db, ClaimsPrincipal user) =>
{
    // Inline authorization check
    if (!user.IsInRole("Admin"))
        return Results.Forbid();
    
    var newUser = new User
    {
        Username = request.Username,
        Password = request.Password,
        Role = request.Role
    };
    
    db.Users.Add(newUser);
    await db.SaveChangesAsync();
    
    return Results.Created($"/api/users/{newUser.Id}", newUser);
});

// ============================================
// RESOURCE-BASED AUTHORIZATION
// ============================================

app.MapPut("/api/users/{id}", async (int id, UpdateUserRequest request, AppDbContext db, ClaimsPrincipal user) =>
{
    var targetUser = await db.Users.FindAsync(id);
    if (targetUser == null)
        return Results.NotFound();
    
    // Users can update their own profile, admins can update anyone
    var userId = int.Parse(user.FindFirst(ClaimTypes.NameIdentifier)?.Value);
    var isAdmin = user.IsInRole("Admin");
    
    if (userId != id && !isAdmin)
        return Results.Forbid();
    
    targetUser.Username = request.Username;
    targetUser.Password = request.Password;
    await db.SaveChangesAsync();
    
    return Results.Ok(targetUser);
});

app.Run();

// ============================================
// HELPER METHODS
// ============================================

string GenerateJwtToken(User user, IConfiguration config)
{
    var securityKey = new SymmetricSecurityKey(
        Encoding.UTF8.GetBytes(config["Jwt:Key"]));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Username),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, user.Role)
    };

    var token = new JwtSecurityToken(
        issuer: config["Jwt:Issuer"],
        audience: config["Jwt:Audience"],
        claims: claims,
        expires: DateTime.UtcNow.AddHours(2),
        signingCredentials: credentials
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
}

async Task SeedData(AppDbContext db)
{
    if (await db.Users.AnyAsync())
        return;

    db.Users.AddRange(
        new User { Username = "admin", Password = "admin123", Role = "Admin" },
        new User { Username = "user1", Password = "user123", Role = "User" }
    );
    await db.SaveChangesAsync();
}

// ============================================
// MODELS AND DTOs
// ============================================

public class User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
    public string Role { get; set; }
}

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<User> Users { get; set; }
}

public record LoginRequest(string Username, string Password);
public record CreateUserRequest(string Username, string Password, string Role);
public record UpdateUserRequest(string Username, string Password);

// ============================================
// CUSTOM AUTHORIZATION REQUIREMENT AND HANDLER
// ============================================

public class UserDeletionRequirement : IAuthorizationRequirement { }

public class UserDeletionHandler : AuthorizationHandler<UserDeletionRequirement>
{
    private readonly AppDbContext _db;

    public UserDeletionHandler(AppDbContext db)
    {
        _db = db;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, 
        UserDeletionRequirement requirement)
    {
        // Admin can always delete
        if (context.User.IsInRole("Admin"))
        {
            context.Succeed(requirement);
            return;
        }

        // Custom logic: maybe users can't delete themselves
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId != null)
        {
            var user = await _db.Users.FindAsync(int.Parse(userId));
            if (user?.Role == "User")
            {
                context.Fail();
                return;
            }
        }

        context.Succeed(requirement);
    }
}
```

2. appsettings.json

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "Jwt": {
    "Key": "YourSuperSecretKeyWithAtLeast32CharactersLong!",
    "Issuer": "AuthMinimalApi",
    "Audience": "AuthMinimalApiClient"
  },
  "AllowedHosts": "*"
}
```

3. Test the API

Test Endpoints

Login and Get Token:

```bash
# Login as Admin
curl -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Login as User
curl -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"user123"}'
```

Test Different Endpoints:

```bash
# Set token as environment variable
TOKEN="your_jwt_token_here"

# Public endpoint (no auth needed)
curl https://localhost:5001/api/public

# User profile (any authenticated user)
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost:5001/api/user/profile

# User data (User or Admin role)
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost:5001/api/user/data

# Admin dashboard (Admin only)
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost:5001/api/admin/dashboard

# Delete user (requires policy)
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  https://localhost:5001/api/admin/users/2
```

Key Features Demonstrated

1. JWT Authentication: Token-based authentication with role claims
2. Role-Based Authorization:
   · AdminOnly policy restricts to Admin role
   · UserOrAdmin policy allows both User and Admin roles
3. Policy-Based Authorization:
   · Custom CanDeleteUsers policy with custom requirement
4. Action-Based Authorization: Inline role checks in endpoints
5. Resource-Based Authorization: Users can only update their own profiles
6. SQLite Database: Simple data storage for users

Database Setup

The app uses SQLite, but you can switch to any other database by changing the connection string in appsettings.json and installing the appropriate provider.

Security Best Practices

1. Don't store plaintext passwords - Use hashing (bcrypt, Argon2, etc.)
2. Use HTTPS in production
3. Rotate JWT secrets regularly
4. Implement refresh tokens for long-lived sessions
5. Add rate limiting to login endpoints
6. Use proper logging for security events

This implementation provides a solid foundation for authentication and authorization in .NET 10 Minimal APIs with support for multiple roles and custom policies.
