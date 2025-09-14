Of course. As an ASP.NET Core expert, I'll provide you with 15 code challenges focused on authorization, ranging from fundamental to advanced scenarios. Each challenge includes a problem statement, starter code (where applicable), and a detailed solution.

---

Challenge 1: Basic Role-Based Authorization

Problem: Create a controller AdminController with an action ViewReports that is only accessible to users in the "Administrator" role.

Starter Code:

```csharp
// Your solution goes here
public class AdminController : Controller
{
    public IActionResult ViewReports()
    {
        return Content("Super secret admin reports.");
    }
}
```

Solution:

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

public class AdminController : Controller
{
    [Authorize(Roles = "Administrator")] // Apply the Authorize attribute with the Roles property
    public IActionResult ViewReports()
    {
        return Content("Super secret admin reports.");
    }
}
```

---

Challenge 2: Policy-Based Authorization

Problem: Create a custom authorization policy named "RequireEditorRole" that requires the user to be in the "Editor" role. Apply it to a ContentController's Edit action.

Starter Code:

```csharp
// In Program.cs or Startup.cs, configure authorization policies
// In your controller
public class ContentController : Controller
{
    public IActionResult Edit(int id)
    {
        return Content($"Editing content {id}");
    }
}
```

Solution:

```csharp
// In Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireEditorRole", policy =>
        policy.RequireRole("Editor"));
});

// In ContentController.cs
public class ContentController : Controller
{
    [Authorize(Policy = "RequireEditorRole")]
    public IActionResult Edit(int id)
    {
        return Content($"Editing content {id}");
    }
}
```

---

Challenge 3: Multiple Roles in a Policy

Problem: Create a policy named "PowerUser" that grants access to users who are in either the "Administrator" or "SuperUser" role.

Solution:

```csharp
// In Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("PowerUser", policy =>
        policy.RequireRole("Administrator", "SuperUser")); // User can be in ANY of these roles
});
```

---

Challenge 4: Claim-Based Authorization

Problem: Create a policy named "CanViewLogs" that requires the user to have a claim of type "Permission" with a value of "View.Logs".

Solution:

```csharp
// In Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanViewLogs", policy =>
        policy.RequireClaim("Permission", "View.Logs")); // Must have this specific claim
});
```

---

Challenge 5: Custom Authorization Requirement & Handler

Problem: Create a custom requirement that checks if a user's registration date (stored in a RegistrationDate claim) is at least 30 days old (i.e., a "VerifiedUser"). Create a handler for this requirement and a policy named "MinimumTenure".

Solution:

```csharp
// 1. Define the Requirement
public class MinimumTenureRequirement : IAuthorizationRequirement
{
    public int MinimumDays { get; }
    public MinimumTenureRequirement(int minimumDays)
    {
        MinimumDays = minimumDays;
    }
}

// 2. Define the Handler
public class MinimumTenureHandler : AuthorizationHandler<MinimumTenureRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
                                                  MinimumTenureRequirement requirement)
    {
        if (!context.User.HasClaim(c => c.Type == "RegistrationDate"))
        {
            return Task.CompletedTask; // Fail if claim is missing
        }

        var registrationDateValue = context.User.FindFirst(c => c.Type == "RegistrationDate")?.Value;
        if (DateTime.TryParse(registrationDateValue, out var registrationDate))
        {
            var tenureInDays = (DateTime.Today - registrationDate.Date).TotalDays;
            if (tenureInDays >= requirement.MinimumDays)
            {
                context.Succeed(requirement);
            }
        }
        return Task.CompletedTask;
    }
}

// 3. Register the Handler and Policy in Program.cs
builder.Services.AddSingleton<IAuthorizationHandler, MinimumTenureHandler>();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("MinimumTenure", policy =>
        policy.Requirements.Add(new MinimumTenureRequirement(30)));
});
```

---

Challenge 6: Resource-Based Authorization

Problem: A Document has an OwnerId property. Only the owner of the document should be able to delete it. Implement this using the IAuthorizationService in the controller.

Starter Code:

```csharp
public class Document
{
    public int Id { get; set; }
    public string Title { get; set; }
    public string OwnerId { get; set; } // This should match a User's Id
}

public class DocumentController : Controller
{
    private readonly AppDbContext _context;
    // You will need to inject IAuthorizationService

    public async Task<IActionResult> Delete(int id)
    {
        var document = await _context.Documents.FindAsync(id);
        if (document == null)
        {
            return NotFound();
        }

        // TODO: Check authorization here

        _context.Documents.Remove(document);
        await _context.SaveChangesAsync();
        return RedirectToAction("Index");
    }
}
```

Solution:

```csharp
// 1. Define a Requirement (e.g., "DocumentOwnerRequirement")
public class DocumentOwnerRequirement : IAuthorizationRequirement { }

// 2. Define a Handler for the Requirement
public class DocumentOwnerAuthorizationHandler : AuthorizationHandler<DocumentOwnerRequirement, Document>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
                                                   DocumentOwnerRequirement requirement,
                                                   Document resource)
    {
        // Check if the current user's ID matches the document's OwnerId
        if (context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value == resource.OwnerId)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}

// 3. Register Handler and Policy in Program.cs
builder.Services.AddSingleton<IAuthorizationHandler, DocumentOwnerAuthorizationHandler>();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("DocumentOwnerPolicy", policy =>
        policy.Requirements.Add(new DocumentOwnerRequirement()));
});

// 4. Use IAuthorizationService in the Controller
public class DocumentController : Controller
{
    private readonly AppDbContext _context;
    private readonly IAuthorizationService _authorizationService;

    public DocumentController(AppDbContext context, IAuthorizationService authorizationService)
    {
        _context = context;
        _authorizationService = authorizationService;
    }

    public async Task<IActionResult> Delete(int id)
    {
        var document = await _context.Documents.FindAsync(id);
        if (document == null) return NotFound();

        // Authorize the user against the specific document resource
        var authResult = await _authorizationService.AuthorizeAsync(User, document, "DocumentOwnerPolicy");
        if (!authResult.Succeeded)
        {
            // return Forbid() or Challenge() for a better user experience
            return Forbid();
            // Alternatively, return a 404 to hide the resource's existence:
            // return NotFound();
        }

        _context.Documents.Remove(document);
        await _context.SaveChangesAsync();
        return RedirectToAction("Index");
    }
}
```

---

Challenge 7: Razor Page Handler Authorization

Problem: Apply the "RequireEditorRole" policy to the OnPostDelete handler of a Razor Page named EditArticle.cshtml, but allow anyone to access the OnGet handler.

Solution:

```csharp
// In the EditArticle.cshtml.cs Page Model
public class EditArticleModel : PageModel
{
    public void OnGet() // Anyone can access this
    {
    }

    [Authorize(Policy = "RequireEditorRole")] // Apply policy to this specific handler
    public IActionResult OnPostDelete(int id)
    {
        // Delete logic
        return RedirectToPage("./Index");
    }
}
// Alternatively, you can apply [Authorize] at the class level for the entire page.
```

---

Challenge 8: Fallback Authorization Policy

Problem: Configure a global fallback policy that requires authorization for all endpoints, then explicitly allow anonymous access to the HomeController::Index and HomeController::About actions.

Solution:

```csharp
// In Program.cs
// 1. Set the Fallback Policy
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// ... other services ...

var app = builder.Build();

// 2. Use Authorization Middleware
app.UseAuthorization();

// In HomeController.cs
public class HomeController : Controller
{
    [AllowAnonymous] // Explicitly override the fallback policy
    public IActionResult Index()
    {
        return View();
    }

    [AllowAnonymous] // Explicitly override the fallback policy
    public IActionResult About()
    {
        return View();
    }

    // This action will require authentication due to the fallback policy
    public IActionResult Contact()
    {
        return View();
    }
}
```

---

Challenge 9: Combining Multiple Requirements

Problem: Create a policy named "SeniorEditor" that requires the user to be in the "Editor" role AND have a "Permission" claim with the value "Approve.Article".

Solution:

```csharp
// In Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("SeniorEditor", policy =>
    {
        policy.RequireRole("Editor"); // First requirement
        policy.RequireClaim("Permission", "Approve.Article"); // Second requirement
    }); // User must satisfy BOTH conditions
});
```

---

Challenge 10: Authorize with a Specific Authentication Scheme

Problem: You have two authentication schemes: "Cookie" and "JwtBearer". Create an action that only authorizes users who authenticated via a JWT Bearer token.

Solution:

```csharp
// In Program.cs, you would have configured both schemes:
// builder.Services.AddAuthentication()
//     .AddCookie("Cookie")
//     .AddJwtBearer("JwtBearer", options => { ... });

// In your Controller
[Authorize(AuthenticationSchemes = "JwtBearer")] // Only accepts tokens from this scheme
[ApiController]
[Route("api/[controller]")]
public class ApiDataController : ControllerBase
{
    [HttpGet]
    public IActionResult GetSecureData()
    {
        return Ok(new { data = "This is from API auth." });
    }
}
```

---

Challenge 11: Programmatically Check Policies in Middleware

Problem: Write a custom middleware that checks for the "PowerUser" policy before allowing access to a specific path (/admin-dashboard).

Starter Code:

```csharp
app.Use(async (context, next) =>
{
    // TODO: Check if the path is /admin-dashboard
    // TODO: Use IAuthorizationService to check the "PowerUser" policy
    await next(context);
});
```

Solution:

```csharp
// Create a custom middleware class or write it inline in Program.cs
app.Use(async (context, next) =>
{
    var endpoint = context.GetEndpoint();
    // Only run auth check for a specific path
    if (context.Request.Path.StartsWithSegments("/admin-dashboard"))
    {
        // Resolve the authorization service
        var authService = context.RequestServices.GetRequiredService<IAuthorizationService>();
        // Authorize the user
        var authResult = await authService.AuthorizeAsync(context.User, null, "PowerUser");
        if (!authResult.Succeeded)
        {
            // If not authorized, set 403 and return
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
    }
    // Continue processing the request if authorized or not the target path
    await next(context);
});
```

---

Challenge 12: Authorize SignalR Hubs

Problem: Apply authorization to a SignalR Hub so that only authenticated users in the "Client" role can connect to it.

Starter Code:

```csharp
public class SupportHub : Hub
{
    // ... hub methods ...
}
```

Solution:

```csharp
// Apply the Authorize attribute at the class level
[Authorize(Roles = "Client")]
public class SupportHub : Hub
{
    public async Task SendMessage(string user, string message)
    {
        await Clients.All.SendAsync("ReceiveMessage", user, message);
    }
}
```

---

Challenge 13: Authorize Specific Blazor Components

Problem: In a Blazor Server app, use the AuthorizeView component to display a "Edit Settings" button only to users in the "Administrator" role. Also, use the [Authorize] directive to protect an entire component.

Solution:

```html
@* Using AuthorizeView in a .razor component **
<AuthorizeView Roles="Administrator">
    <Authorized>
        <button @onclick="EditSettings">Edit Settings</button>
    </Authorized>
    <NotAuthorized>
        <!-- Optional: show nothing or a message -->
        <p>You cannot edit settings.</p>
    </NotAuthorized>
</AuthorizeView>

@code {
    private void EditSettings() { ... }
}
```

```html
@* Protecting an entire component (at the top of the .razor file) **
@attribute [Authorize(Roles = "Administrator")]

<h3>Super Secret Admin Panel</h3>
<!-- ... -->
```

---

Challenge 14: Dynamic Policy via AuthorizationOptions

Problem: At startup, read a list of roles from a configuration file (e.g., appsettings.json) and create a policy that requires the user to be in any one of those roles.

Starter appsettings.json:

```json
{
  "AllowedRolesForPolicyX": [ "RoleA", "RoleB", "RoleC" ]
}
```

Solution:

```csharp
// In Program.cs
var allowedRoles = builder.Configuration.GetSection("AllowedRolesForPolicyX").Get<string[]>();

builder.Services.AddAuthorization(options =>
{
    if (allowedRoles != null && allowedRoles.Length > 0)
    {
        // Creates a policy that requires the user to be in any of the roles from config
        options.AddPolicy("DynamicRolePolicy", policy =>
            policy.RequireRole(allowedRoles));
    }
});
```

---

Challenge 15: Custom Authorization Failure Response

Problem: Customize the response body and HTTP status code (e.g., return a custom JSON message and a 403 status) when authorization fails for an API endpoint.

Solution:

```csharp
// In Program.cs
// This will handle all authorization failures
builder.Services.Configure<AuthorizationOptions>(options =>
{
    // Optionally configure policies here too
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        // Return a custom JSON response for API calls
        return context.Response.WriteAsJsonAsync(new { error = "You are not authorized to access this resource." });
    };
});

// For JWT Bearer scheme failures, you would need a JWT bearer events handler.
```