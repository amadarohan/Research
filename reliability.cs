Of course. As an ASP.NET Core expert, I'll provide 15 code challenges focused on reliability, covering critical areas like resilience, error handling, data integrity, and observability. Each challenge includes a problem description, a "Bad Code" snippet, and a "Solution" with an explanation.

---

Challenge 1: Resilient HTTP Calls with Polly

Problem: An external API your application calls is occasionally slow or throws transient errors. Your current implementation fails immediately, causing user requests to fail.

Bad Code:

```csharp
public class UnreliableApiService
{
    private readonly HttpClient _httpClient;
    public UnreliableApiService(HttpClient httpClient) => _httpClient = httpClient;

    public async Task<string> GetDataAsync()
    {
        // Fails on any transient error (e.g., 5xx, timeout)
        var response = await _httpClient.GetAsync("https://unreliable-api.com/data");
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }
}
```

Solution:

```csharp
// 1. Install Microsoft.Extensions.Http.Polly NuGet package
// 2. Register the resilient policy in Program.cs

using Polly;
using Polly.Extensions.Http;

// In Program.cs
builder.Services.AddHttpClient<ReliableApiService>()
    .AddPolicyHandler(GetRetryPolicy()) // Handles transient faults
    .AddPolicyHandler(GetCircuitBreakerPolicy()); // Prevents overwhelming a failing service

// Define the policies
static IAsyncPolicy<HttpResponseMessage> GetRetryPolicy()
{
    return HttpPolicyExtensions
        .HandleTransientHttpError() // Handles 5xx, 408, and HttpRequestException
        .OrResult(msg => msg.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
        .WaitAndRetryAsync(3, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)));
}

static IAsyncPolicy<HttpResponseMessage> GetCircuitBreakerPolicy()
{
    return HttpPolicyExtensions
        .HandleTransientHttpError()
        .CircuitBreakerAsync(5, TimeSpan.FromSeconds(30)); // Opens circuit after 5 consecutive failures
}

// The Service remains clean and focused on business logic
public class ReliableApiService
{
    private readonly HttpClient _httpClient;
    public ReliableApiService(HttpClient httpClient) => _httpClient = httpClient;

    public async Task<string> GetDataAsync()
    {
        var response = await _httpClient.GetAsync("https://unreliable-api.com/data");
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }
}
```

---

Challenge 2: Global Exception Handling

Problem: Unhandled exceptions are leaking out of controllers, exposing stack traces and other sensitive information to the client.

Bad Code: (No centralized handling, relies on default ASP.NET behavior).

Solution:

```csharp
// Create a custom Exception Handling Middleware
public class CustomExceptionHandlerMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<CustomExceptionHandlerMiddleware> _logger;

    public CustomExceptionHandlerMiddleware(RequestDelegate next, ILogger<CustomExceptionHandlerMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unhandled exception occurred.");
            await HandleExceptionAsync(context, ex);
        }
    }

    private static Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = exception switch
        {
            KeyNotFoundException _ => StatusCodes.Status404NotFound,
            UnauthorizedAccessException _ => StatusCodes.Status401Unauthorized,
            _ => StatusCodes.Status500InternalServerError
        };

        // Never expose internal details in production
        var isDevelopment = context.RequestServices.GetService<IHostEnvironment>()?.IsDevelopment();
        var response = isDevelopment == true
            ? new { error = exception.Message, stackTrace = exception.StackTrace }
            : new { error = "An unexpected fault occurred. Please try again later." };

        return context.Response.WriteAsJsonAsync(response);
    }
}

// Register the middleware early in the pipeline in Program.cs
app.UseMiddleware<CustomExceptionHandlerMiddleware>();
```

---

Challenge 3: Idempotent POST Requests

Problem: A user's slow internet connection causes them to double-click a "Submit" button, resulting in two identical orders being created.

Bad Code:

```csharp
[HttpPost]
public async Task<IActionResult> CreateOrder(Order order)
{
    // No check for duplicate requests
    _context.Orders.Add(order);
    await _context.SaveChangesAsync();
    return Ok(order);
}
```

Solution:

```csharp
[HttpPost]
public async Task<IActionResult> CreateOrder(Order order, [FromHeader] string idempotencyKey)
{
    // 1. Client generates a unique Idempotency-Key GUID header for each distinct request
    if (string.IsNullOrEmpty(idempotencyKey))
        return BadRequest("Idempotency-Key header is required.");

    // 2. Check if a response for this key is already cached
    var cache = _requestContextAccessor.HttpContext.RequestServices.GetService<IDistributedCache>();
    var cachedResponse = await cache.GetStringAsync($"idempotency:{idempotencyKey}");
    
    if (cachedResponse != null)
    {
        // Replay the saved response to avoid duplicate processing
        return Content(cachedResponse, "application/json");
    }

    // 3. Process the request for the first time
    _context.Orders.Add(order);
    await _context.SaveChangesAsync();

    // 4. Serialize the successful response
    var result = new OkObjectResult(order);
    var responseJson = JsonSerializer.Serialize(order);

    // 5. Cache the response with the idempotency key for a limited time (e.g., 24 hours)
    var cacheOptions = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24) };
    await cache.SetStringAsync($"idempotency:{idempotencyKey}", responseJson, cacheOptions);

    return result;
}
```

---

Challenge 4: Database Concurrency Control

Problem: Two users edit the same product's inventory count simultaneously, leading to a "last write wins" scenario and a lost update.

Bad Code:

```csharp
[HttpPost]
public async Task<IActionResult> UpdateProduct(Product model)
{
    var product = await _context.Products.FindAsync(model.Id);
    product.StockQuantity = model.StockQuantity; // Overwrites without checking for conflicts
    await _context.SaveChangesAsync(); // Potential lost update!
    return Ok(product);
}
```

Solution:

```csharp
[HttpPost]
public async Task<IActionResult> UpdateProduct(Product model)
{
    // Fetch the product and track it
    var product = await _context.Products.FindAsync(model.Id);
    
    // Check if the received model has a concurrency token
    if (product.Version != model.Version)
    {
        // A concurrent edit occurred! Don't save, return a conflict.
        return Conflict("This record has been modified by another user. Please refresh and try again.");
    }

    product.StockQuantity = model.StockQuantity;
    product.Version = Guid.NewGuid(); // Update the concurrency token

    try
    {
        await _context.SaveChangesAsync();
        return Ok(product);
    }
    catch (DbUpdateConcurrencyException) // EF Core throws this if the token doesn't match
    {
        // Handle the exception, e.g., by reloading the entity and informing the user
        return Conflict("This record has been modified by another user. Please refresh and try again.");
    }
}

// The Product entity class must have a concurrency token property.
public class Product
{
    public int Id { get; set; }
    public string Name { get; set; }
    public int StockQuantity { get; set; }
    public Guid Version { get; set; } // Concurrency Token
}

// In your DbContext OnModelCreating:
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<Product>()
        .Property(p => p.Version)
        .IsConcurrencyToken(); // Configures this property as a concurrency token
}
```

---

Challenge 5: Structured Logging with Serilog

Problem: Your application uses Console.WriteLine for logging, making it impossible to effectively search, filter, and analyze logs in production.

Bad Code:

```csharp
public class WeatherService
{
    public string GetForecast()
    {
        Console.WriteLine($"Getting forecast for..."); // Unstructured, difficult to query
        return "Sunny";
    }
}
```

Solution:

```csharp
// 1. Install Serilog.AspNetCore, Serilog.Sinks.Console, Serilog.Sinks.File NuGet packages
// 2. Configure Serilog in Program.cs

using Serilog;

// Build the Serilog logger
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("logs/myapp.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

// In the app builder
var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSerilog(); // Tell ASP.NET Core to use Serilog for all logging

// The service now uses structured logging via Dependency Injection
public class WeatherService
{
    private readonly ILogger<WeatherService> _logger;

    public WeatherService(ILogger<WeatherService> logger) // Injected ILogger
    {
        _logger = logger;
    }

    public string GetForecast(string city)
    {
        // Structured logging with named properties
        _logger.LogInformation("Getting forecast for {City}", city);
        
        try
        {
            // ... logic
            return "Sunny";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get forecast for {City}", city);
            throw;
        }
    }
}
// Logs appear as: {"@t":"2023-10-27T12:00:00Z","@l":"Information","@m":"Getting forecast for London","City":"London"}
```

---

Challenge 6: Health Checks

Problem: Your deployment and monitoring tools have no way to automatically determine if your application is functioning correctly (liveness) and can connect to its dependencies (readiness).

Bad Code: (No health checks endpoint exists).

Solution:

```csharp
// In Program.cs
var builder = WebApplication.CreateBuilder(args);

// 1. Register Health Check Services
builder.Services.AddHealthChecks()
    .AddCheck("self", () => HealthCheckResult.Healthy()) // Basic liveness probe
    .AddSqlServer( // Readiness probe for database
        connectionString: builder.Configuration.GetConnectionString("DefaultConnection"),
        name: "sql",
        failureStatus: HealthStatus.Unhealthy,
        tags: new[] { "ready" })
    .AddUrlGroup( // Readiness probe for an external API
        new Uri("https://unreliable-api.com/health"),
        name: "external-api",
        tags: new[] { "ready" });

// ... other services

var app = builder.Build();

// 2. Map the health check endpoints
app.MapHealthChecks("/health"); // For overall liveness/readiness
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = (check) => check.Tags.Contains("ready") // Only checks dependencies
});
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = (_) => false // Excludes all checks, just returns 200 if app is live
});

// Kubernetes or a load balancer can now poll /health/ready to route traffic.
```

---

Challenge 7: Data Validation

Problem: Your controller actions receive invalid model data, causing exceptions deep inside your business logic or database.

Bad Code:

```csharp
[HttpPost]
public IActionResult CreateUser(User user)
{
    // No validation, trusts the client input completely
    _userRepository.Add(user);
    return Ok();
}
public class User
{
    public string Email { get; set; }
    public int Age { get; set; }
}
```

Solution:

```csharp
// Use Data Annotations for declarative validation
public class User
{
    [Required, EmailAddress]
    public string Email { get; set; }

    [Range(1, 120)]
    public int Age { get; set; }
}

[ApiController] // This attribute is crucial! It enables automatic model validation.
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    [HttpPost]
    public IActionResult CreateUser(User user) // The [ApiController] attribute automatically checks ModelState.IsValid
    {
        // If validation fails, the framework returns a 400 Bad Request automatically
        // with details of the errors. This code only runs if the model is valid.

        _userRepository.Add(user);
        return Ok();
    }
}

// For more complex validation logic, implement IValidatableObject
public class User : IValidatableObject
{
    [Required, EmailAddress]
    public string Email { get; set; }

    [Range(1, 120)]
    public int Age { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (Age < 13 && Email.Contains("admin"))
        {
            yield return new ValidationResult(
                "Minors cannot have admin emails.",
                new[] { nameof(Email) });
        }
    }
}
```

---

Challenge 8: Cancelling Long-Running Operations

Problem: A user cancels a request for a large report, but the server continues processing it, wasting resources.

Bad Code:

```csharp
[HttpGet("bigreport")]
public async Task<IActionResult> GenerateBigReport()
{
    // No cancellation token, process can't be aborted
    var data = await _reportService.GenerateReportAsync();
    return File(data, "text/csv", "report.csv");
}
```

Solution:

```csharp
[HttpGet("bigreport")]
public async Task<IActionResult> GenerateBigReport(CancellationToken cancellationToken)
{
    // The framework automatically provides the CancellationToken linked to the client request.
    // Pass it all the way down to async methods (EF Core, HttpClient, etc., support it).
    try
    {
        var data = await _reportService.GenerateReportAsync(cancellationToken);
        return File(data, "text/csv", "report.csv");
    }
    catch (OperationCanceledException)
    {
        // Handle the cancellation gracefully (log it, etc.)
        _logger.LogInformation("Report generation was cancelled by the user.");
        return StatusCode(499); // "Client Closed Request" (non-standard but useful)
    }
}

// The service method must accept and use the token.
public class ReportService
{
    public async Task<byte[]> GenerateReportAsync(CancellationToken cancellationToken = default)
    {
        await Task.Delay(5000, cancellationToken); // Simulate work, respects cancellation
        var bigData = await _dbContext.BigTable.ToListAsync(cancellationToken); // EF Core respects it
        return GenerateCsv(bigData);
    }
}
```

---

Challenge 9: Preventing Over-Posting / Mass Assignment

Problem: Your User model has an IsAdmin property. A malicious user can craft a request that sets this to true by including it in the JSON payload.

Bad Code:

```csharp
public class User
{
    public int Id { get; set; }
    public string Name { get; set; }
    public bool IsAdmin { get; set; } // Should not be settable via API call!
}

[HttpPost]
public IActionResult CreateUser(User user) // Binds all properties, including IsAdmin!
{
    _context.Users.Add(user);
    _context.SaveChanges();
    return Ok(user);
}
```

Solution:

```csharp
// Use a Input Model (DTO) to define the exact properties you expect from the client.
public class UserCreateInput
{
    [Required]
    public string Name { get; set; }
    // NO IsAdmin property here!
}

[HttpPost]
public IActionResult CreateUser(UserCreateInput userInput)
{
    var user = new User // Map from the input model to the data model
    {
        Name = userInput.Name,
        IsAdmin = false // Set sensitive properties server-side only
    };

    _context.Users.Add(user);
    _context.SaveChanges();
    return Ok(user);
}

// Alternatively, use the [BindNever] attribute on the data model property.
public class User
{
    public int Id { get; set; }
    public string Name { get; set; }

    [BindNever] // Prevents model binder from setting this property from a request
    public bool IsAdmin { get; set; }
}
// The controller action can then use the User class directly, but IsAdmin will be ignored.
```

---

Challenge 10: Safe Database Connections & Commands

Problem: Database operations are not wrapped in using statements, leading to potential connection leaks under high load or if an exception occurs.

Bad Code:

```csharp
// (Assuming raw ADO.NET for demonstration, same concept applies to proper resource disposal)
public void AddUser(string name)
{
    var connection = new SqlConnection(_connectionString);
    connection.Open(); // Connection might not be closed if an exception occurs

    var command = new SqlCommand("INSERT INTO Users (Name) VALUES (@name)", connection);
    command.Parameters.AddWithValue("@name", name);
    command.ExecuteNonQuery(); // Command might not be disposed

    // Missing connection.Close() and command.Dispose()
}
```

Solution:

```csharp
public void AddUser(string name)
{
    // Use 'using' statements to ensure objects are disposed, even if an exception is thrown.
    using (var connection = new SqlConnection(_connectionString))
    {
        connection.Open();
        
        using (var command = new SqlCommand("INSERT INTO Users (Name) VALUES (@name)", connection))
        {
            // Use parameters to prevent SQL injection
            command.Parameters.AddWithValue("@name", name);
            command.ExecuteNonQuery();
        } // command.Dispose() is called here
    } // connection.Close() and connection.Dispose() are called here
}

// The modern, preferred approach is to use Dependency Injection and let the framework manage the lifetime.
// For ADO.NET, inject `SqlConnection` (which is designed to be pooled and managed by the framework).
public class UserRepository
{
    private readonly SqlConnection _connection;

    public UserRepository(SqlConnection connection) // Injected
    {
        _connection = connection;
    }

    public async Task AddUserAsync(string name)
    {
        // Just open and use the connection, don't create or dispose it manually.
        await _connection.OpenAsync();
        using var command = new SqlCommand("INSERT ...", _connection);
        command.Parameters.AddWithValue("@name", name);
        await command.ExecuteNonQueryAsync();
    }
}
// Register in Program.cs: builder.Services.AddTransient<SqlConnection>(sp => new SqlConnection("..."));
```

---

Challenge 11: Configuration Validation

Problem: Your application starts up but immediately crashes because a required configuration value (like a connection string) is missing or invalid.

Bad Code:

```csharp
// In a service
_connectionString = configuration.GetValue<string>("ConnectionStrings:DefaultConnection");
// Throws NullReferenceException later if the key is missing.
```

Solution:

```csharp
// 1. Create a strongly-typed options class
public class DatabaseOptions
{
    public const string SectionName = "Database";
    
    [Required] // Uses System.ComponentModel.DataAnnotations
    public string ConnectionString { get; set; }

    [Range(1, 100)]
    public int MaxRetryCount { get; set; } = 3;
}

// 2. Bind and validate in Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOptions<DatabaseOptions>()
    .Bind(builder.Configuration.GetSection(DatabaseOptions.SectionName))
    .ValidateDataAnnotations() // Enforces [Required], [Range], etc.
    .ValidateOnStart(); // Critical: validates at startup, not first use

// 3. Inject IOptions<DatabaseOptions> into your service
public class MyReliableService
{
    private readonly DatabaseOptions _options;
    public MyReliableService(IOptions<DatabaseOptions> options)
    {
        _options = options.Value; // Guaranteed to be valid if app started
    }
}
// If validation fails, the app will fail fast on startup, which is more reliable than failing later.
```

---

Challenge 12: Safe File Path Handling

Problem: Your application allows user-input to form part of a file path, leading to directory traversal vulnerabilities (e.g., a user requesting ../../../etc/passwd).

Bad Code:

```csharp
[HttpGet("download")]
public IActionResult Download(string fileName)
{
    // EXTREMELY DANGEROUS: User input directly used in a path
    var filePath = Path.Combine(_contentRoot, "uploads", fileName);
    return PhysicalFile(filePath, "application/octet-stream");
}
```

Solution:

```csharp
[HttpGet("download")]
public IActionResult Download(string fileName)
{
    // 1. Validate the filename (e.g., allow only alphanumeric, hyphen, underscore)
    if (!IsValidFileName(fileName))
        return BadRequest("Invalid file name.");

    // 2. Use Path.GetFullPath to safely combine and then check if it's within the intended directory
    var safeBaseDir = Path.GetFullPath(_contentRoot);
    var userFilePath = Path.GetFullPath(Path.Combine(safeBaseDir, "uploads", fileName));

    // 3. Ensure the resolved path starts with the safe base directory
    if (!userFilePath.StartsWith(safeBaseDir))
    {
        return BadRequest("Invalid file path."); // Attempted path traversal
    }

    // 4. Check if the file exists before returning it
    if (!System.IO.File.Exists(userFilePath))
        return NotFound();

    return PhysicalFile(userFilePath, "application/octet-stream");
}

private bool IsValidFileName(string fileName)
{
    // Use a strict whitelist of allowed characters
    return !string.IsNullOrWhiteSpace(fileName) &&
           fileName.All(c => char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_');
}
```

---

Challenge 13: Background Task Queue

Problem: You fire off a long-running email-sending task directly from an HTTP request. The request waits for it to finish, causing timeouts, or if it's async void, failures are silent.

Bad Code:

```csharp
[HttpPost("order")]
public async Task<IActionResult> SubmitOrder(Order order)
{
    // ... save order logic

    // Problem: Makes the HTTP request wait for the email to send.
    await _emailService.SendConfirmationEmailAsync(order); 

    return Ok();
}

// OR EVEN WORSE:
[HttpPost("order")]
public IActionResult SubmitOrder(Order order)
{
    // ... save order logic

    // Fire and forget - exceptions will crash the process!
    Task.Run(async () => await _emailService.SendConfirmationEmailAsync(order));

    return Ok();
}
```

Solution:

```csharp
// 1. Create a Background Task Queue
public interface IBackgroundTaskQueue
{
    ValueTask QueueBackgroundWorkItemAsync(Func<CancellationToken, ValueTask> workItem);
    ValueTask<Func<CancellationToken, ValueTask>> DequeueAsync(CancellationToken cancellationToken);
}
// Implement a Channel-based queue (see https://learn.microsoft.com/en-us/aspnet/core/fundamentals/host/hosted-services?view=aspnetcore-8.0#queued-background-tasks)

// 2. Register a Hosted Service (QueuedHostedService) that processes the queue.

// 3. In your controller, inject the queue and enqueue work.
[HttpPost("order")]
public async Task<IActionResult> SubmitOrder(Order order)
{
    // ... save order logic

    // Reliably queue the work and return immediately.
    await _backgroundTaskQueue.QueueBackgroundWorkItemAsync(async token =>
    {
        // The hosted service will execute this.
        await _emailService.SendConfirmationEmailAsync(order);
    });

    return Accepted(); // 202 Accepted - the request is queued for processing
}
```

---

Challenge 14: Preventing Race Conditions with Distributed Lock

Problem: Your scaled-out application (multiple instances) is processing a background task that should only run once across the entire cluster (e.g., a cleanup job), but all instances are running it simultaneously.

Bad Code:

```csharp
// Running in a hosted service on every instance
protected override async Task ExecuteAsync(CancellationToken stoppingToken)
{
    while (!stoppingToken.IsCancellationRequested)
    {
        await DoCleanupAsync(); // All instances do this at the same time!
        await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
    }
}
```

Solution:

```csharp
// Use a distributed lock (e.g., with Redis via RedLock.net)
protected override async Task ExecuteAsync(CancellationToken stoppingToken)
{
    while (!stoppingToken.IsCancellationRequested)
    {
        // Try to acquire a lock with a unique resource name and expiry time
        await using (var redLock = await _distributedLockFactory
            .CreateLockAsync("cleanup-lock", TimeSpan.FromMinutes(5)))
        {
            if (redLock.IsAcquired)
            {
                // Only one instance in the cluster acquires the lock and runs the job.
                await DoCleanupAsync();
            }
            // Else, another instance has the lock, so we skip.
        }
        await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); // Check more frequently than lock expiry
    }
}

// Register IDistributedLockFactory in Program.cs (implementation depends on the library, e.g., RedLock.net)
```

---

Challenge 15: Request Timeout Configuration

Problem: A specific endpoint performs a very slow operation, but the server's default request timeout (e.g., 2 minutes in Kestrel) is too short, causing it to be aborted.

Bad Code: (Relies on the default server timeout).

Solution:

```csharp
// Use the [RequestTimeout] attribute (introduced in .NET 7)
[RequestTimeout(300)] // 300 seconds = 5 minutes for this specific endpoint
[HttpGet("slowreport")]
public async Task<IActionResult> GenerateVerySlowReport()
{
    // ... slow operation
    return Ok();
}

// For older versions, or more granular control, use a CancellationTokenSource
[HttpGet("slowreport")]
public async Task<IActionResult> GenerateVerySlowReport()
{
    // Create a CTS with a specific delay for this request
    using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
    try
    {
        var data = await _service.GetVerySlowDataAsync(cts.Token);
        return Ok(data);
    }
    catch (OperationCanceledException) when (cts.IsCancellationRequested)
    {
        // Handle the timeout specifically
        return StatusCode(StatusCodes.Status504GatewayTimeout);
    }
}

// You can also configure Kestrel-wide timeouts in Program.cs
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.RequestHeadersTimeout = TimeSpan.FromMinutes(1);
    options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
});
```