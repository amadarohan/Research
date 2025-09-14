Of course. Here are the 15 authorization challenges, reimagined for ASP.NET Core Minimal APIs.

---

Challenge 1: Basic Role-Based Authorization

Problem: Create a minimal API endpoint GET /admin/reports that is only accessible to users in the "Administrator" role.

Solution:

```csharp
app.MapGet("/admin/reports", () => "Super secret admin reports.")
   .RequireAuthorization(new AuthorizeAttribute { Roles = "Administrator" }); // Apply authorization
```

---

Challenge 2: Policy-Based Authorization

Problem: Create a custom authorization policy named "RequireEditorRole" that requires the user to be in the "Editor" role. Apply it to a PUT /content/{id} endpoint.

Solution:

```csharp
// Policy setup
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("RequireEditorRole", policy => policy.RequireRole("Editor"));

// Endpoint
app.MapPut("/content/{id}", (int id) => $"Editing content {id}")
   .RequireAuthorization("RequireEditorRole"); // Reference policy by name
```

---

Challenge 3: Multiple Roles in a Policy

Problem: Create a policy named "PowerUser" that grants access to users who are in either the "Administrator" or "SuperUser" role. Apply it to GET /power/data.

Solution:

```csharp
// Policy setup
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("PowerUser", policy => policy.RequireRole("Administrator", "SuperUser"));

// Endpoint
app.MapGet("/power/data", () => "Power user data.")
   .RequireAuthorization("PowerUser");
```

---

Challenge 4: Claim-Based Authorization

Problem: Create a policy named "CanViewLogs" that requires the user to have a claim of type "Permission" with a value of "View.Logs". Apply it to GET /system/logs.

Solution:

```csharp
// Policy setup
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("CanViewLogs", policy => policy.RequireClaim("Permission", "View.Logs"));

// Endpoint
app.MapGet("/system/logs", () => "System logs content.")
   .RequireAuthorization("CanViewLogs");
```

---

Challenge 5: Custom Authorization Requirement & Handler

Problem: Create a custom requirement that checks if a user's registration date (stored in a RegistrationDate claim) is at least 30 days old. Create a policy named "MinimumTenure" and apply it to GET /exclusive/content.

Solution:

```csharp
// 1. Define the Requirement
public class MinimumTenureRequirement : IAuthorizationRequirement
{
    public int MinimumDays { get; }
    public MinimumTenureRequirement(int minimumDays) => MinimumDays = minimumDays;
}

// 2. Define the Handler
public class MinimumTenureHandler : AuthorizationHandler<MinimumTenureRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
                                                  MinimumTenureRequirement requirement)
    {
        var registrationDateClaim = context.User.FindFirst("RegistrationDate");
        if (registrationDateClaim is null || 
            !DateTime.TryParse(registrationDateClaim.Value, out var registrationDate))
            return Task.CompletedTask;

        if ((DateOnly.FromDateTime(DateTime.Today).DayNumber - DateOnly.FromDateTime(registrationDate).DayNumber) >= requirement.MinimumDays)
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}

// 3. Register Handler and Policy in Program.cs
builder.Services.AddSingleton<IAuthorizationHandler, MinimumTenureHandler>();
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("MinimumTenure", policy => 
        policy.Requirements.Add(new MinimumTenureRequirement(30)));

// 4. Endpoint
app.MapGet("/exclusive/content", () => "Welcome, long-term user!")
   .RequireAuthorization("MinimumTenure");
```

---

Challenge 6: Resource-Based Authorization

Problem: A Document has an OwnerId. Only the owner should be able to delete it. Implement this using the IAuthorizationService directly in the endpoint.

Starter Code (Define Document first):

```csharp
public record Document(int Id, string Title, string OwnerId);
// Assume a service or DB context exists to fetch documents
```

Solution:

```csharp
// 1. & 2. Define Requirement & Handler (Same as Challenge 5)
public class DocumentOwnerRequirement : IAuthorizationRequirement { }
public class DocumentOwnerAuthorizationHandler : AuthorizationHandler<DocumentOwnerRequirement, Document>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
                                                   DocumentOwnerRequirement requirement,
                                                   Document resource)
    {
        if (context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value == resource.OwnerId)
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}

// 3. Register Handler and Policy
builder.Services.AddSingleton<IAuthorizationHandler, DocumentOwnerAuthorizationHandler>();
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("DocumentOwnerPolicy", policy => 
        policy.Requirements.Add(new DocumentOwnerRequirement()));

// 4. Endpoint using IAuthorizationService
app.MapDelete("/documents/{id}", async (int id, IAuthorizationService authService, HttpContext context) => {
    // Fetch document from database (simulated here)
    var document = new Document(Id: id, Title: "Test Doc", OwnerId: "user-123"); 

    var authResult = await authService.AuthorizeAsync(context.User, document, "DocumentOwnerPolicy");
    
    if (!authResult.Succeeded)
        return Results.Forbid();

    // Delete logic would go here
    return Results.Ok($"Document {id} deleted.");
});
```

---

Challenge 7: Fallback Authorization Policy

Problem: Configure a global policy that requires authorization for all endpoints, then explicitly allow anonymous access to GET /public and GET /about.

Solution:

```csharp
// 1. Set the Fallback Policy
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build());

// ... other services ...

var app = builder.Build();

// 2. Use Authorization Middleware
app.UseAuthorization();

// 3. Endpoints
app.MapGet("/public", () => "Public info.").AllowAnonymous(); // Explicit override
app.MapGet("/about", () => "About us.").AllowAnonymous();     // Explicit override
app.MapGet("/contact", () => "Contact info.");                // Requires auth due to fallback
```

---

Challenge 8: Combining Multiple Requirements

Problem: Create a policy named "SeniorEditor" that requires the user to be in the "Editor" role AND have a "Permission" claim with the value "Approve.Article". Apply it to POST /articles/approve.

Solution:

```csharp
// Policy setup
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("SeniorEditor", policy => 
    {
        policy.RequireRole("Editor");
        policy.RequireClaim("Permission", "Approve.Article");
    });

// Endpoint
app.MapPost("/articles/approve", (ApprovalRequest request) => $"Article {request.ArticleId} approved.")
   .RequireAuthorization("SeniorEditor");
```

---

Challenge 9: Authorize with a Specific Authentication Scheme

Problem: You have two authentication schemes: "Cookie" and "JwtBearer". Create an endpoint GET /api/secure that only authorizes users who authenticated via a JWT Bearer token.

Solution:

```csharp
// In Program.cs, configure both schemes (example for JWT simplified):
// builder.Services.AddAuthentication().AddCookie("Cookie").AddJwtBearer("JwtBearer");

// Endpoint - specify the authentication scheme(s)
app.MapGet("/api/secure", () => "This is from API auth.")
   .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "JwtBearer" });
```

---

Challenge 10: Programmatically Check Policies in Endpoints

Problem: Inside an endpoint, manually check the "PowerUser" policy using IAuthorizationService and return a custom message if it fails, instead of a standard 403.

Solution:

```csharp
app.MapGet("/manual-auth-check", async (IAuthorizationService authService, HttpContext context) =>
{
    var authResult = await authService.AuthorizeAsync(context.User, null, "PowerUser");
    
    if (!authResult.Succeeded)
        return Results.Json(new { error = "Custom failure message" }, statusCode: 403); // Custom response

    return Results.Ok("Access granted.");
});
```

---

Challenge 11: Authorize SignalR Hubs (Minimal API)

Problem: Apply authorization to a SignalR Hub so that only authenticated users in the "Client" role can connect to it.

Solution:

```csharp
// 1. Define your Hub
public class SupportHub : Hub
{
    public async Task SendMessage(string user, string message)
    {
        await Clients.All.SendAsync("ReceiveMessage", user, message);
    }
}

// 2. Map the Hub and require authorization
app.MapHub<SupportHub>("/supporthub")
   .RequireAuthorization(new AuthorizeAttribute { Roles = "Client" }); // Apply auth to the hub route
```

---

Challenge 12: Dynamic Policy via Configuration

Problem: At startup, read a list of roles from appsettings.json and create a policy that requires the user to be in any one of those roles. Apply it to GET /dynamic-policy.

Starter appsettings.json:

```json
{
  "AllowedRolesForPolicyX": [ "RoleA", "RoleB", "RoleC" ]
}
```

Solution:

```csharp
// Read configuration
var allowedRoles = builder.Configuration.GetSection("AllowedRolesForPolicyX").Get<string[]>();

// Build policy dynamically
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("DynamicRolePolicy", policy =>
    {
        if (allowedRoles != null && allowedRoles.Length > 0)
            policy.RequireRole(allowedRoles);
    });

// Endpoint
app.MapGet("/dynamic-policy", () => "You have a dynamic role!")
   .RequireAuthorization("DynamicRolePolicy");
```

---

Challenge 13: Custom Authorization Failure Response for APIs

Problem: Customize the response body and HTTP status code (e.g., return a consistent JSON error message) when authorization fails for any endpoint.

Solution:

```csharp
// Handle Authorization failures
builder.Services.Configure<AuthorizationOptions>(options =>
{
    options.AddPolicy("SomePolicy", policy => policy.RequireRole("Admin"));
});

// Add a middleware to handle the Forbid result
app.UseExceptionHandler(); // Optional: for other errors
app.UseAuthentication();
app.UseAuthorization();

// Custom handling after UseAuthorization
app.Use(async (context, next) =>
{
    await next(context);
    
    // Check if the response is a 403 Forbidden from authorization failure
    if (context.Response.StatusCode == StatusCodes.Status403Forbidden)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new { error = "Custom authorization failure message." });
    }
});

// Endpoint to test
app.MapGet("/test-forbid", () => "test").RequireAuthorization("SomePolicy"); // Will 403 for non-Admins
```

---

Challenge 14: Policy with Custom Logic using RequireAssertion

Problem: Create a policy named "IsActiveUser" using RequireAssertion that checks a custom IsActive claim value. Apply it to GET /active-users-only.

Solution:

```csharp
// Policy setup using assertion
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("IsActiveUser", policy =>
        policy.RequireAssertion(ctx =>
            ctx.User.HasClaim(c => c.Type == "IsActive" && 
                                  bool.TryParse(c.Value, out var isActive) && 
                                  isActive)));

// Endpoint
app.MapGet("/active-users-only", () => "Welcome, active user!")
   .RequireAuthorization("IsActiveUser");
```

---

Challenge 15: Minimal API Authorization Helper Extension

Problem: Create an extension method RequireRoleOrClaim(string role, string claimType, string claimValue) to easily apply this complex requirement to multiple endpoints.

Solution:

```csharp
// Extension Method
public static class AuthorizationExtensions
{
    public static TBuilder RequireRoleOrClaim<TBuilder>(this TBuilder builder, string role, string claimType, string claimValue) where TBuilder : IEndpointConventionBuilder
    {
        // Create a unique policy name based on parameters
        var policyName = $"RoleOrClaim:{role}:{claimType}:{claimValue}";
        
        // Ensure the policy is added to the services
        builder.Services.AddAuthorizationBuilder().AddPolicy(policyName, policy =>
        {
            policy.RequireAssertion(ctx =>
                ctx.User.IsInRole(role) ||
                ctx.User.HasClaim(claimType, claimValue)
            );
        });
        
        // Apply the policy to the endpoint
        return builder.RequireAuthorization(policyName);
    }
}

// Usage in an endpoint
app.MapGet("/flexible-access", () => "You have either the role or the claim!")
   .RequireRoleOrClaim("Admin", "SpecialAccess", "true");
```