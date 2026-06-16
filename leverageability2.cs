Here are ultra-simple single-file versions of both Console and Web API apps that demonstrate leverageability with minimal code.

---

1. Console App (Single File)

```csharp
// Program.cs - Complete console app in one file
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;

// ============ CORE INTERFACES ============
public interface IDataProvider
{
    string GetData();
}

public interface IOutputFormatter
{
    void Print(string data);
}

public interface ILogger
{
    void Log(string message);
}

// ============ IMPLEMENTATIONS ============
public class DatabaseProvider : IDataProvider
{
    public string GetData() => "Data from SQL Database: 42 orders";
}

public class ApiProvider : IDataProvider
{
    public string GetData() => "Data from REST API: 15 orders";
}

public class FileProvider : IDataProvider
{
    public string GetData() => "Data from CSV file: 7 orders";
}

public class ConsoleFormatter : IOutputFormatter
{
    public void Print(string data) => Console.WriteLine($"📊 {data}");
}

public class JsonFormatter : IOutputFormatter
{
    public void Print(string data) => Console.WriteLine($"{{\"data\": \"{data}\"}}");
}

public class ConsoleLogger : ILogger
{
    public void Log(string message) => Console.WriteLine($"[LOG] {message}");
}

public class FileLogger : ILogger
{
    private readonly string _path = "log.txt";
    public void Log(string message) => File.AppendAllText(_path, $"{DateTime.Now}: {message}\n");
}

// ============ BUSINESS SERVICE ============
public class DataProcessor
{
    private readonly IDataProvider _provider;
    private readonly IOutputFormatter _formatter;
    private readonly ILogger _logger;

    public DataProcessor(IDataProvider provider, IOutputFormatter formatter, ILogger logger)
    {
        _provider = provider;
        _formatter = formatter;
        _logger = logger;
    }

    public void Process()
    {
        _logger.Log("Processing started");
        var data = _provider.GetData();
        _logger.Log($"Data retrieved: {data.Length} chars");
        _formatter.Print(data);
        _logger.Log("Processing complete");
    }
}

// ============ MAIN PROGRAM ============
class Program
{
    static void Main(string[] args)
    {
        // Build configuration from appsettings.json or environment
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        // Choose implementations based on config
        var providerType = config["Provider"] ?? "Database";
        var formatterType = config["Formatter"] ?? "Console";
        var loggerType = config["Logger"] ?? "Console";

        // Build DI container
        var services = new ServiceCollection();

        // Register provider
        services.AddSingleton<IDataProvider>(providerType switch
        {
            "Api" => new ApiProvider(),
            "File" => new FileProvider(),
            _ => new DatabaseProvider()
        });

        // Register formatter
        services.AddSingleton<IOutputFormatter>(formatterType switch
        {
            "Json" => new JsonFormatter(),
            _ => new ConsoleFormatter()
        });

        // Register logger
        services.AddSingleton<ILogger>(loggerType switch
        {
            "File" => new FileLogger(),
            _ => new ConsoleLogger()
        });

        services.AddSingleton<DataProcessor>();

        var serviceProvider = services.BuildServiceProvider();

        // Run the processor
        var processor = serviceProvider.GetRequiredService<DataProcessor>();
        processor.Process();

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }
}
```

Sample appsettings.json (optional)

```json
{
  "Provider": "Api",      // Change to "Database", "Api", or "File"
  "Formatter": "Console", // Change to "Console" or "Json"
  "Logger": "Console"     // Change to "Console" or "File"
}
```

How to run:

```bash
# Default (Database provider)
dotnet run

# Override with environment variable
Provider=Api dotnet run

# Cross-platform (Windows)
set Provider=Api && dotnet run
```

---

2. Web API (Single File)

```csharp
// Program.cs - Complete Web API in one file
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Text.Json;

// ============ CORE INTERFACES ============
public interface IDataProvider
{
    Task<IEnumerable<string>> GetItemsAsync();
}

public interface IDataProcessor
{
    Task<string> ProcessDataAsync();
}

public interface ILogger
{
    void Log(string message);
}

// ============ IMPLEMENTATIONS ============
public class DatabaseProvider : IDataProvider
{
    private readonly ILogger _logger;
    public DatabaseProvider(ILogger logger) => _logger = logger;
    
    public async Task<IEnumerable<string>> GetItemsAsync()
    {
        _logger.Log("Fetching from database");
        await Task.Delay(100);
        return new[] { "SQL Item 1", "SQL Item 2", "SQL Item 3" };
    }
}

public class ApiProvider : IDataProvider
{
    private readonly ILogger _logger;
    private readonly HttpClient _http;
    
    public ApiProvider(HttpClient http, ILogger logger)
    {
        _http = http;
        _logger = logger;
    }
    
    public async Task<IEnumerable<string>> GetItemsAsync()
    {
        _logger.Log("Fetching from external API");
        // Simulate API call
        await Task.Delay(200);
        return new[] { "API Item A", "API Item B", "API Item C" };
    }
}

public class CacheProvider : IDataProvider
{
    private readonly IDataProvider _inner;
    private readonly ILogger _logger;
    private IEnumerable<string>? _cache;
    
    public CacheProvider(IDataProvider inner, ILogger logger)
    {
        _inner = inner;
        _logger = logger;
    }
    
    public async Task<IEnumerable<string>> GetItemsAsync()
    {
        if (_cache != null)
        {
            _logger.Log("Returning cached data");
            return _cache;
        }
        
        _logger.Log("Cache miss - fetching fresh data");
        _cache = await _inner.GetItemsAsync();
        return _cache;
    }
}

public class ConsoleLogger : ILogger
{
    public void Log(string message) => Console.WriteLine($"[LOG] {DateTime.Now:T} - {message}");
}

public class NoOpLogger : ILogger
{
    public void Log(string message) { /* Do nothing */ }
}

// ============ PROCESSOR SERVICE ============
public class DataProcessor : IDataProcessor
{
    private readonly IDataProvider _provider;
    private readonly ILogger _logger;

    public DataProcessor(IDataProvider provider, ILogger logger)
    {
        _provider = provider;
        _logger = logger;
    }

    public async Task<string> ProcessDataAsync()
    {
        _logger.Log("Processing started");
        var items = await _provider.GetItemsAsync();
        var result = string.Join(", ", items);
        _logger.Log($"Processed {items.Count()} items");
        return result;
    }
}

// ============ API CONTROLLER ============
[ApiController]
[Route("api/[controller]")]
public class DataController : ControllerBase
{
    private readonly IDataProcessor _processor;

    public DataController(IDataProcessor processor) => _processor = processor;

    [HttpGet]
    public async Task<IActionResult> Get()
    {
        try
        {
            var result = await _processor.ProcessDataAsync();
            return Ok(new { data = result, timestamp = DateTime.UtcNow });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = ex.Message });
        }
    }

    [HttpGet("health")]
    public IActionResult Health() => Ok(new { status = "Healthy", time = DateTime.UtcNow });
}

// ============ MIDDLEWARE ============
public class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        _logger.Log($"➡️ {context.Request.Method} {context.Request.Path}");
        await _next(context);
        _logger.Log($"⬅️ {context.Response.StatusCode}");
    }
}

// ============ MAIN PROGRAM ============
var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddControllers();

// Configuration-based swapping
var config = builder.Configuration;

// ----- Register Logger (swap via config) -----
var loggerType = config["Logger"] ?? "Console";
builder.Services.AddSingleton<ILogger>(loggerType == "NoOp" 
    ? new NoOpLogger() 
    : new ConsoleLogger());

// ----- Register DataProvider (swap via config) -----
var providerType = config["Provider"] ?? "Database";

if (providerType == "Api")
{
    builder.Services.AddHttpClient<IDataProvider, ApiProvider>()
        .ConfigureHttpClient(c => c.BaseAddress = new Uri("https://api.example.com"));
}
else if (providerType == "Cache")
{
    // Decorator pattern - wraps the underlying provider with caching
    builder.Services.AddSingleton<IDataProvider>(sp =>
    {
        var logger = sp.GetRequiredService<ILogger>();
        var inner = new DatabaseProvider(logger);
        return new CacheProvider(inner, logger);
    });
}
else // Database (default)
{
    builder.Services.AddSingleton<IDataProvider, DatabaseProvider>();
}

// ----- Register processor -----
builder.Services.AddSingleton<IDataProcessor, DataProcessor>();

// ----- Build and configure app -----
var app = builder.Build();

// Development tools
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Custom logging middleware
app.UseMiddleware<RequestLoggingMiddleware>();

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

// Minimal API endpoint (alternative to controller)
app.MapGet("/api/minimal", async (IDataProcessor processor) =>
{
    var result = await processor.ProcessDataAsync();
    return Results.Ok(new { data = result });
});

// Run the app
app.Run();
```

Sample appsettings.json for Web API

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning"
    }
  },
  "Provider": "Database",  // Change to "Api" or "Cache"
  "Logger": "Console",      // Change to "NoOp" to disable logging
  "AllowedHosts": "*"
}
```

How to run:

```bash
# Default (Database provider)
dotnet run

# Use API provider
Provider=Api dotnet run

# Use Cache provider (with Database underneath)
Provider=Cache dotnet run

# Test endpoints
curl https://localhost:5001/api/data
curl https://localhost:5001/api/data/health
curl https://localhost:5001/api/minimal
```

---

Key Leverageability Features in Both Versions

What changes Console App Web API
Data source Change Provider config Change Provider config
Output format Change Formatter config Swagger/JSON by default
Logging Change Logger config Change Logger config
Add cache Not shown Add CacheProvider decorator
Run anywhere dotnet run dotnet run + HTTP calls

---

Testing Leverageability (Both Apps)

```bash
# Console App - Different providers
dotnet run                           # Database provider
Provider=Api dotnet run              # API provider  
Provider=File dotnet run             # File provider
Formatter=Json dotnet run            # JSON output
Logger=File dotnet run               # File logging

# Web API - Different providers (set env vars)
$env:Provider="Api"; dotnet run      # Windows
Provider=Api dotnet run              # Linux/Mac
```

---

Why This Works (Leverageability Principles)

1. Dependency Inversion — All services depend on interfaces (IDataProvider, ILogger)
2. Open/Closed — Add new providers by creating classes, not modifying existing code
3. Configuration-Driven — Change behavior without recompiling
4. Single Responsibility — Each class does one thing (provider, logger, formatter)
5. Liskov Substitution — Any implementation can be swapped without breaking the app

---

The Minimal Approach

If you want even smaller (no interfaces, just delegates):

```csharp
// Ultra-minimal console app with leverageability
using Microsoft.Extensions.DependencyInjection;

// Define behavior as functions
Func<string> getData = () => "Hello from Database";
Action<string> print = (s) => Console.WriteLine(s);
Action<string> log = (s) => Console.WriteLine($"[LOG] {s}");

// Swap easily
if (args.Contains("--api"))
    getData = () => "Hello from API";
if (args.Contains("--json"))
    print = (s) => Console.WriteLine($"{{\"message\":\"{s}\"}}");

// Process
log("Starting");
var data = getData();
print(data);
log("Done");
```

But the interface-based approach above is more maintainable and follows SOLID principles! 🎯
