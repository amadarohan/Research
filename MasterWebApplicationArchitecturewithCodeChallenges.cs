Of course. This is an excellent way to solidify the concepts from the book. The provided document covers the full spectrum of web application architecture, from low-level protocols to high-level design patterns.

Here are 15+ code challenges in ASP.NET Core (C#), ranging from intermediate to senior level, designed to master the subject matter. They are heavily weighted towards state management, resource handling, and architectural patterns, with a specific focus on diagnosing and preventing memory leaks as requested.

---

### Memory Leak Specific Challenges (A Deep Dive)

**1. Challenge: The Caching Leak (Intermediate)**
**Scenario:** You are using `IMemoryCache` to cache a large dataset of `Product` objects to improve performance. However, the application's memory usage grows steadily over time until it crashes, even though the cached data shouldn't be changing that often.
**Task:** Identify the potential cause of the leak in the code below and rewrite it to be leak-proof. Implement a robust caching strategy with appropriate expiration.
**Concepts:** `IMemoryCache`, Cache Expiration & Policies, Sliding vs. Absolute Expiration, Weak References (conceptually).

```csharp
// Leaky Code - DO NOT USE
public class ProductService
{
    private readonly IMemoryCache _cache;
    public ProductService(IMemoryCache cache) => _cache = cache;

    public async Task<List<Product>> GetProductsAsync()
    {
        if (!_cache.TryGetValue("AllProducts", out List<Product> products))
        {
            products = await _database.GetProductsAsync(); // Expensive DB call
            _cache.Set("AllProducts", products); // LEAK: No expiration policy!
        }
        return products;
    }
}

// Fixed Code
public class ProductService
{
    private readonly IMemoryCache _cache;
    public ProductService(IMemoryCache cache) => _cache = cache;

    public async Task<List<Product>> GetProductsAsync()
    {
        // Use GetOrCreateAsync for thread-safe creation
        return await _cache.GetOrCreateAsync("AllProducts", async entry =>
        {
            entry.SlidingExpiration = TimeSpan.FromMinutes(30); // Reset timer on access
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(2); // Max lifetime
            entry.SetPriority(CacheItemPriority.Normal);

            return await _database.GetProductsAsync();
        });
    }
}
```

**2. Challenge: Event Handler Leaks with Dependency Injection (Senior)**
**Scenario:** A background service `DataPublisher` raises an event when new data arrives. Multiple controllers subscribe to this event. You notice that after stopping and starting HTTP requests (e.g., load testing), the number of subscribers keeps growing, and old controller instances are not being garbage collected.
**Task:** Fix the memory leak caused by improper event subscription. The subscriber must automatically unsubscribe when it is disposed.
**Concepts:** Event Handlers, Garbage Collection Roots, Deregistering Events, `IDisposable`, Scoped vs Singleton Services.

```csharp
// Leaky Publisher (Singleton service)
public class DataPublisher
{
    public event EventHandler<DataEventArgs> DataPublished;
    public void PublishData(string data) => DataPublished?.Invoke(this, new DataEventArgs(data));
}

// Leaky Subscriber (Scoped service - created per HTTP request)
public class LeakySubscriberController : Controller
{
    private readonly DataPublisher _publisher;
    public LeakySubscriberController(DataPublisher publisher)
    {
        _publisher = publisher;
        _publisher.DataPublished += OnDataPublished; // LEAK: Publisher is singleton, holds ref to scoped controller
    }

    private void OnDataPublished(object sender, DataEventArgs e)
    {
        // Process data
    }
}

// Fixed Subscriber
public class FixedSubscriberController : Controller, IDisposable
{
    private readonly DataPublisher _publisher;
    private bool _disposed = false;

    public FixedSubscriberController(DataPublisher publisher)
    {
        _publisher = publisher;
        _publisher.DataPublished += OnDataPublished;
    }

    private void OnDataPublished(object sender, DataEventArgs e) { /* Process data */ }

    public void Dispose()
    {
        if (!_disposed)
        {
            _publisher.DataPublished -= OnDataPublished; // CRITICAL: Unsubscribe
            _disposed = true;
        }
    }
}
```

**3. Challenge: Static Collection Leak (Intermediate)**
**Scenario:** A service uses a static `ConcurrentDictionary` to track in-progress operations for real-time status updates. Entries are added but never removed, leading to a memory leak.
**Task:** Implement a self-cleaning mechanism to automatically remove stale entries from the static collection. Use a `CancellationTokenSource` to enforce a timeout on operations and ensure cleanup happens even if an operation fails.
**Concepts:** Static References, `ConcurrentDictionary`, `CancellationTokenSource`, Timers, Self-Cleaning Data Structures.

```csharp
public class OperationTracker
{
    // Static collections are a common source of leaks.
    private static readonly ConcurrentDictionary<string, (OperationInfo Info, CancellationTokenSource Cts)> _operations =
        new ConcurrentDictionary<string, (OperationInfo, CancellationTokenSource)>();

    public void StartOperation(string id)
    {
        var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5)); // Auto-cancel after 5 min
        var operationInfo = new OperationInfo { Id = id, StartTime = DateTime.UtcNow };

        // Add the operation
        _operations.TryAdd(id, (operationInfo, cts));

        // Simulate work that might fail
        _ = DoWorkAsync(id, cts.Token);
    }

    private async Task DoWorkAsync(string id, CancellationToken ct)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(1), ct); // Simulate work
            // Complete work...
        }
        finally
        {
            // GUARANTEED CLEANUP: Remove the operation whether it succeeded, failed, or was cancelled.
            _operations.TryRemove(id, out _);
        }
    }

    public bool TryGetOperation(string id, out OperationInfo info)
    {
        var exists = _operations.TryGetValue(id, out var tuple);
        info = exists ? tuple.Info : null;
        return exists;
    }
}
```

---

### Core Protocol & HTTP Challenges

**4. Challenge: Custom HTTP Status Code & Response Middleware (Intermediate)**
**Task:** Create an ASP.NET Core Middleware that intercepts all responses. If an unhandled exception occurs, it should catch it, log it, and return a custom JSON error response with a status code of `500 Internal Server Error`, instead of the default HTML error page. For `404 Not Found` responses, return a consistent JSON format.
**Concepts:** HTTP Status Codes, Middleware Pipeline, Exception Handling, Response Generation.

```csharp
public class CustomHttpStatusMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<CustomHttpStatusMiddleware> _logger;

    public CustomHttpStatusMiddleware(RequestDelegate next, ILogger<CustomHttpStatusMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
            // Handle 404s on the way out
            if (context.Response.StatusCode == StatusCodes.Status404NotFound)
            {
                await HandleNotFoundAsync(context);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unhandled exception occurred.");
            await HandleExceptionAsync(context, ex);
        }
    }

    private static Task HandleNotFoundAsync(HttpContext context)
    {
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return context.Response.WriteAsync(JsonSerializer.Serialize(new {
            error = "Resource not found",
            path = context.Request.Path
        }));
    }

    private static Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        return context.Response.WriteAsync(JsonSerializer.Serialize(new {
            error = "An internal server error occurred. Please try again later.",
            referenceId = context.TraceIdentifier // Useful for support
        }));
    }
}
// Register in Startup.cs / Program.cs: app.UseMiddleware<CustomHttpStatusMiddleware>();
```

**5. Challenge: Conditional GET (ETag) Implementation (Senior)**
**Task:** Implement a `IActionResult` that returns a list of products. The action should generate an ETag (a hash of the product data). On subsequent requests, it should check the `If-None-Match` header against the current ETag. If they match, return `304 Not Modified` without sending the product data again.
**Concepts:** HTTP Caching, ETags, Conditional Requests, `If-None-Match` header, `304 Not Modified`.

```csharp
[HttpGet("products")]
public async Task<IActionResult> GetProducts()
{
    var products = await _productService.GetAllProductsAsync();
    // Generate a weak ETag from the data (simplified example)
    var data = JsonSerializer.Serialize(products);
    var etag = "\"W/" + ComputeHash(data) + "\""; // Weak ETag

    // Check if the client's ETag matches
    if (Request.Headers.IfNoneMatch.ToString() == etag)
    {
        return StatusCode(StatusCodes.Status304NotModified);
    }

    // Set the ETag header for the client to cache
    Response.Headers.ETag = etag;
    return Ok(products);
}

private static string ComputeHash(string input)
{
    using var sha256 = SHA256.Create();
    var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
    return Convert.ToBase64String(bytes);
}
```

---

### State Management & Sessions

**6. Challenge: Distributed Session Store with Redis (Intermediate)**
**Task:** Configure the application to use Redis as a distributed cache for session state. Implement a login controller that stores a user's session in this distributed cache, making the application stateless and ready for a web farm environment.
**Concepts:** HTTP Statelessness, Distributed Session State, `IDistributedCache`, Redis.

```csharp
// In Program.cs / Startup.ConfigureServices
services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = Configuration.GetConnectionString("Redis");
    options.InstanceName = "MyApp_";
});
services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Login Controller
[HttpPost]
public async Task<IActionResult> Login(LoginModel model)
{
    if (ModelState.IsValid && await _authService.ValidateUserAsync(model))
    {
        var user = await _authService.GetUserAsync(model.Username);
        // Store minimal user info in session
        HttpContext.Session.SetString("UserId", user.Id.ToString());
        HttpContext.Session.SetString("Username", user.Username);

        return RedirectToAction("Index", "Home");
    }
    return View(model);
}
```

---

### Architectural Patterns & Security

**7. Challenge: Implement the Front Controller Pattern with a Custom Middleware (Senior)**
**Task:** Create middleware that acts as a front controller. It should inspect the incoming request URL (e.g., `/api/v1/products` or `/api/v2/products`) and dynamically route the request to different internal endpoints or application logic based on the API version in the path, without using MVC's attribute routing.
**Concepts:** Front Controller Pattern, Middleware, Routing, URL Rewriting.

```csharp
public class ApiVersionRoutingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IReadOnlyDictionary<string, RequestDelegate> _versionHandlers;

    public ApiVersionRoutingMiddleware(RequestDelegate next, IServiceProvider serviceProvider)
    {
        _next = next;
        // Map version prefixes to their respective handling pipelines
        _versionHandlers = new Dictionary<string, RequestDelegate>(StringComparer.OrdinalIgnoreCase)
        {
            ["/api/v1"] = BuildVersionPipeline(serviceProvider, "V1"),
            ["/api/v2"] = BuildVersionPipeline(serviceProvider, "V2"),
        };
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";
        foreach (var prefix in _versionHandlers.Keys)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                // Rewrite the path to remove the version prefix for the downstream middleware
                context.Request.Path = path[prefix.Length..];
                await _versionHandlers[prefix](context);
                return;
            }
        }
        await _next(context); // Not an API request we handle
    }

    private static RequestDelegate BuildVersionPipeline(IServiceProvider services, string version)
    {
        // Build a separate middleware pipeline for each version
        var appBuilder = new ApplicationBuilder(services);
        appBuilder.UseMiddleware<VersionSpecificMiddleware>(version);
        appBuilder.UseRouting();
        appBuilder.UseEndpoints(endpoints => { endpoints.MapControllers(); }); // Controllers for this version
        return appBuilder.Build();
    }
}
public class VersionSpecificMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _version;
    public VersionSpecificMiddleware(RequestDelegate next, string version) { _next = next; _version = version; }
    public async Task InvokeAsync(HttpContext context)
    {
        context.Items["ApiVersion"] = _version; // Pass version to controllers
        await _next(context);
    }
}
```

**8. Challenge: Secure Cookie Implementation with Essential Flags (Intermediate)**
**Task:** Configure the application's authentication cookie to be secure. It must be HTTP-only, use strict SameSite policies, have a limited lifetime, and be marked as "Essential" to comply with GDPR regulations for requiring user consent for non-essential cookies.
**Concepts:** Web Security, Cookies, `CookieAuthenticationOptions`, GDPR, HTTPS.

```csharp
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true; // Not accessible by JavaScript
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Only sent over HTTPS
        options.Cookie.SameSite = SameSiteMode.Strict; // Protection against CSRF
        options.SlidingExpiration = true; // Reset expiration on activity
        options.ExpireTimeSpan = TimeSpan.FromHours(8); // Absolute max lifetime
        options.Cookie.IsEssential = true; // Bypasses GDPR consent checks
        options.LoginPath = "/Account/Login"; // Custom paths
        options.AccessDeniedPath = "/Account/AccessDenied";
    });
```

---

### Data Access & Performance

**9. Challenge: Database Connection Pooling & Dapper (Intermediate)**
**Task:** Implement a data access service using Dapper. The key is to ensure it correctly leverages the built-in ADO.NET connection pooling by *not* manually implementing a pool, but by creating and disposing `IDbConnection` objects quickly for each operation.
**Concepts:** Database Connections, Connection Pooling, ORMs (Dapper), `IDisposable`.

```csharp
public class ProductRepository : IProductRepository
{
    private readonly IConfiguration _config;
    public ProductRepository(IConfiguration config) => _config = config;

    public async Task<IEnumerable<Product>> GetAllAsync()
    {
        // Connection is opened from the pool (or a new one is created)
        using var connection = new SqlConnection(_config.GetConnectionString("DefaultConnection"));
        // Connection is automatically closed when 'using' block exits, returning it to the pool.
        return await connection.QueryAsync<Product>("SELECT * FROM Products");
    }
}
```

**10. Challenge: Repository Pattern with Dependency Injection (Intermediate)**
**Task:** Create a `GenericRepository<T>` class and register it in the DI container with a scoped lifetime. Ensure your controllers and services depend on the abstract `IRepository<T>` interface, not the concrete class.
**Concepts:** Dependency Injection (DI), Inversion of Control (IoC), Repository Pattern, Scoped Lifetime.

```csharp
public interface IRepository<T> where T : class
{
    Task<T> GetByIdAsync(int id);
    Task<IEnumerable<T>> GetAllAsync();
    Task AddAsync(T entity);
    void Update(T entity);
    void Delete(T entity);
}
public class GenericRepository<T> : IRepository<T> where T : class
{
    private readonly AppDbContext _context;
    public GenericRepository(AppDbContext context) => _context = context;
    public async Task<T> GetByIdAsync(int id) => await _context.Set<T>().FindAsync(id);
    // ... other implementations
}

// Registration in Program.cs
services.AddScoped(typeof(IRepository<>), typeof(GenericRepository<>));
```

**11. Challenge: Resilient Database Connection with Polly (Senior)**
**Task:** Use the Polly library to wrap a database call in a retry policy. The policy should retry the operation 3 times with an exponential backoff if the exception is a `SqlException` with a transient error number (e.g., timeout).
**Concepts:** Resilience, Transient Fault Handling, Polly Library, Exponential Backoff.

```csharp
// In your service or repository
private readonly IAsyncPolicy _retryPolicy;

public ProductService()
{
    // Define a policy to handle transient SQL errors
    _retryPolicy = Policy
        .Handle<SqlException>(ex => TransientErrorNumbers.Contains(ex.Number))
        .WaitAndRetryAsync(3, retryAttempt =>
            TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)), // Exponential backoff: 2, 4, 8 sec
            onRetry: (exception, timeSpan, retryCount, context) =>
            {
                // Log the retry attempt
                _logger.LogWarning(exception, $"Retry {retryCount} after {timeSpan.TotalSeconds}s...");
            });
}

public async Task<Product> GetProductResilientlyAsync(int id)
{
    return await _retryPolicy.ExecuteAsync(async () =>
    {
        using var connection = new SqlConnection(_config.GetConnectionString("DefaultConnection"));
        return await connection.QuerySingleOrDefaultAsync<Product>(
            "SELECT * FROM Products WHERE Id = @Id", new { Id = id });
    });
}
private static readonly int[] TransientErrorNumbers = { 4060, 40197, 40501, 40613, 49918, 49919, 49920, 11001, 208, 18456 }; // Example codes
```

---

### Advanced Challenges

**12. Challenge: Custom Model Binder for Complex Query Strings (Senior)**
**Task:** Create a custom model binder that can parse a complex query string like `?filters=Category:Electronics,Price<100&sort=Name:asc` into a strongly-typed `ProductQuery` object used by your controller action.
**Concepts:** Model Binding, Query Strings, `IModelBinder`.

```csharp
public class ProductQuery
{
    public List<Filter> Filters { get; set; } = new();
    public SortOptions SortBy { get; set; }
}
public class ProductQueryBinder : IModelBinder
{
    public Task BindModelAsync(ModelBindingContext bindingContext)
    {
        var query = new ProductQuery();
        var filtersValue = bindingContext.ValueProvider.GetValue("filters").FirstValue;
        var sortValue = bindingContext.ValueProvider.GetValue("sort").FirstValue;

        // Parse the complex string logic here...
        if (!string.IsNullOrEmpty(filtersValue))
        {
            var filterPairs = filtersValue.Split(',');
            foreach (var pair in filterPairs)
            {
                // ... parsing logic for "Property:Value" or "Property<Value"
            }
        }
        // ... parsing logic for sort

        bindingContext.Result = ModelBindingResult.Success(query);
        return Task.CompletedTask;
    }
}
// Usage: public IActionResult GetProducts([ModelBinder(BinderType = typeof(ProductQueryBinder))] ProductQuery query)

```

**13. Challenge: Health Checks for Database and External API (Intermediate)**
**Task:** Implement ASP.NET Core Health Checks to monitor the database connectivity and the responsiveness of a critical third-party API.
**Concepts:** Application Health Monitoring, `IHealthCheck`, Middleware.

```csharp
// In Program.cs
services.AddHealthChecks()
    .AddSqlServer(Configuration.GetConnectionString("DefaultConnection"),
                 name: "sql",
                 failureStatus: HealthStatus.Unhealthy,
                 tags: new[] { "ready", "db" })
    .AddUrlGroup(new Uri("https://api.criticalservice.com/health"),
                 name: "external-api",
                 failureStatus: HealthStatus.Degraded,
                 tags: new[] { "ready" });

// Map endpoint: app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") });

public class ThirdPartyApiHealthCheck : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            // Ping the external API
            using var client = new HttpClient();
            var response = await client.GetAsync("https://api.criticalservice.com/ping", ct);
            return response.IsSuccessStatusCode
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Degraded($"API returned {response.StatusCode}");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Failed to contact external API.", ex);
        }
    }
}
```

**14. Challenge: Response Compression Middleware (Intermediate)**
**Task:** Configure the application to use GZIP or Brotli compression for HTTP responses, but only for MIME types like `application/json` and `text/html`.
**Concepts:** HTTP Headers (`Content-Encoding`), Response Compression, Performance.

```csharp
// In Program.cs
services.AddResponseCompression(options =>
{
    options.EnableForHttps = true;
    options.Providers.Add<BrotliCompressionProvider>();
    options.Providers.Add<GzipCompressionProvider>();
    options.MimeTypes = new[] { "application/json", "text/html" }; // Only compress these
});
app.UseResponseCompression(); // Must be placed before other middleware that writes to the response (e.g., UseStaticFiles, UseMvc)
```

**15. Challenge: Structured Logging with Serilog (Intermediate)**
**Task:** Replace the default ILogger with Serilog. Configure it to log structured JSON to a file and to the console, including enrichers for the machine name and application name.
**Concepts:** Structured Logging, Serilog, Enrichment, Sinks.

```csharp
// Using Serilog.AspNetCore package
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .Enrich.WithMachineName()
    .Enrich.WithProperty("Application", "MyWebApp")
    .WriteTo.Console(new JsonFormatter())
    .WriteTo.File(new JsonFormatter(),
                  "logs/myapp-.json",
                  rollingInterval: RollingInterval.Day)
    .CreateLogger();

// In Program.cs: 
// builder.Host.UseSerilog(); // <-- Add this
```

Mastering these challenges will give you a profound, practical understanding of building robust, scalable, and efficient web applications in ASP.NET Core, directly applying the fundamental principles outlined in your book summary.
