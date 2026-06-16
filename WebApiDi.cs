Here's a complete .NET 10 Web API example demonstrating DI lifetimes with multiple endpoints and scoped behavior per HTTP request:

1. Project Setup

```bash
dotnet new webapi -n DiWebApi
cd DiWebApi
dotnet add package Microsoft.Extensions.DependencyInjection
```

2. Services with Different Lifetimes

```csharp
// Services/IGuidService.cs
public interface IGuidService
{
    string GetGuid();
    string GetLifetime();
}

// Transient: New instance every injection
public class TransientGuidService : IGuidService
{
    private readonly string _guid = Guid.NewGuid().ToString();
    public string GetGuid() => _guid;
    public string GetLifetime() => "Transient (New per injection)";
}

// Scoped: New instance per HTTP request
public class ScopedGuidService : IGuidService
{
    private readonly string _guid = Guid.NewGuid().ToString();
    public string GetGuid() => _guid;
    public string GetLifetime() => "Scoped (New per request)";
}

// Singleton: Single instance for app lifetime
public class SingletonGuidService : IGuidService
{
    private readonly string _guid = Guid.NewGuid().ToString();
    public string GetGuid() => _guid;
    public string GetLifetime() => "Singleton (One instance)";
}

// Service to demonstrate multiple injections in same request
public class CompositeService
{
    public IGuidService Transient { get; }
    public IGuidService Scoped { get; }
    public IGuidService Singleton { get; }

    public CompositeService(
        TransientGuidService transient,
        ScopedGuidService scoped,
        SingletonGuidService singleton)
    {
        Transient = transient;
        Scoped = scoped;
        Singleton = singleton;
    }
}
```

3. Controller with Multiple Endpoints

```csharp
// Controllers/DiDemoController.cs
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class DiDemoController : ControllerBase
{
    private readonly IGuidService _transient1;
    private readonly IGuidService _transient2;
    private readonly IGuidService _scoped1;
    private readonly IGuidService _scoped2;
    private readonly IGuidService _singleton1;
    private readonly IGuidService _singleton2;
    private readonly CompositeService _composite;
    private readonly ILogger<DiDemoController> _logger;

    public DiDemoController(
        // Multiple injections of same type
        [FromKeyedServices("transient")] IGuidService transient1,
        [FromKeyedServices("transient")] IGuidService transient2,
        [FromKeyedServices("scoped")] IGuidService scoped1,
        [FromKeyedServices("scoped")] IGuidService scoped2,
        [FromKeyedServices("singleton")] IGuidService singleton1,
        [FromKeyedServices("singleton")] IGuidService singleton2,
        CompositeService composite,
        ILogger<DiDemoController> logger)
    {
        _transient1 = transient1;
        _transient2 = transient2;
        _scoped1 = scoped1;
        _scoped2 = scoped2;
        _singleton1 = singleton1;
        _singleton2 = singleton2;
        _composite = composite;
        _logger = logger;
    }

    [HttpGet("single-injection")]
    public IActionResult GetSingleInjection()
    {
        var result = new
        {
            Title = "Single Injection Per Service",
            Transient = new { Guid = _transient1.GetGuid(), Lifetime = _transient1.GetLifetime() },
            Scoped = new { Guid = _scoped1.GetGuid(), Lifetime = _scoped1.GetLifetime() },
            Singleton = new { Guid = _singleton1.GetGuid(), Lifetime = _singleton1.GetLifetime() }
        };
        
        _logger.LogInformation("Single injection requested");
        return Ok(result);
    }

    [HttpGet("multiple-injections")]
    public IActionResult GetMultipleInjections()
    {
        var result = new
        {
            Title = "Multiple Injections (Same Request)",
            Transient = new 
            { 
                Instance1 = _transient1.GetGuid(), 
                Instance2 = _transient2.GetGuid(),
                Same = _transient1.GetGuid() == _transient2.GetGuid() ? "SAME" : "DIFFERENT"
            },
            Scoped = new 
            { 
                Instance1 = _scoped1.GetGuid(), 
                Instance2 = _scoped2.GetGuid(),
                Same = _scoped1.GetGuid() == _scoped2.GetGuid() ? "SAME" : "DIFFERENT"
            },
            Singleton = new 
            { 
                Instance1 = _singleton1.GetGuid(), 
                Instance2 = _singleton2.GetGuid(),
                Same = _singleton1.GetGuid() == _singleton2.GetGuid() ? "SAME" : "DIFFERENT"
            },
            CompositeService = new
            {
                Transient = _composite.Transient.GetGuid(),
                Scoped = _composite.Scoped.GetGuid(),
                Singleton = _composite.Singleton.GetGuid()
            }
        };

        _logger.LogInformation("Multiple injections requested");
        return Ok(result);
    }

    [HttpGet("scoped-service")]
    public IActionResult GetScopedService([FromServices] ScopedGuidService scopedService)
    {
        return Ok(new
        {
            Title = "Scoped Service from Method Injection",
            Guid = scopedService.GetGuid(),
            Lifetime = scopedService.GetLifetime()
        });
    }
}
```

4. Background Service (Singleton Example)

```csharp
// Services/BackgroundLoggerService.cs
public class BackgroundLoggerService : BackgroundService
{
    private readonly IGuidService _singleton;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<BackgroundLoggerService> _logger;

    public BackgroundLoggerService(
        [FromKeyedServices("singleton")] IGuidService singleton,
        IServiceScopeFactory scopeFactory,
        ILogger<BackgroundLoggerService> logger)
    {
        _singleton = singleton;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            _logger.LogInformation(
                "Background Service - Singleton GUID: {Guid}", 
                _singleton.GetGuid());

            // Create a scope for scoped services in background
            using (var scope = _scopeFactory.CreateScope())
            {
                var scoped = scope.ServiceProvider
                    .GetRequiredKeyedService<IGuidService>("scoped");
                _logger.LogInformation(
                    "Background Service - New Scoped GUID: {Guid}", 
                    scoped.GetGuid());
            }

            await Task.Delay(10000, stoppingToken);
        }
    }
}
```

5. Program.cs Configuration

```csharp
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Register services with different lifetimes using keyed services
builder.Services.AddKeyedSingleton<IGuidService, SingletonGuidService>("singleton");
builder.Services.AddKeyedScoped<IGuidService, ScopedGuidService>("scoped");
builder.Services.AddKeyedTransient<IGuidService, TransientGuidService>("transient");

// Register concrete types for constructor injection
builder.Services.AddSingleton<SingletonGuidService>();
builder.Services.AddScoped<ScopedGuidService>();
builder.Services.AddTransient<TransientGuidService>();

// Register composite service
builder.Services.AddScoped<CompositeService>();

// Register background service
builder.Services.AddHostedService<BackgroundLoggerService>();

// Add logging
builder.Services.AddLogging(config =>
{
    config.AddConsole();
    config.AddDebug();
});

var app = builder.Build();

// Configure pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

// Endpoint to show DI info
app.MapGet("/di-info", (IServiceProvider sp) =>
{
    var singleton = sp.GetRequiredKeyedService<IGuidService>("singleton");
    var scoped = sp.GetRequiredKeyedService<IGuidService>("scoped");
    var transient = sp.GetRequiredKeyedService<IGuidService>("transient");
    
    return new
    {
        Message = "DI Info - Note: Scoped and Transient will be same instance here because it's not an HTTP request",
        Singleton = singleton.GetGuid(),
        Scoped = scoped.GetGuid(),
        Transient = transient.GetGuid()
    };
});

app.Run();
```

6. Test Script (PowerShell/curl)

```powershell
# Test single injection
curl -X GET "https://localhost:5001/api/didemo/single-injection" | ConvertFrom-Json | Format-List

# Test multiple injections in same request
curl -X GET "https://localhost:5001/api/didemo/multiple-injections" | ConvertFrom-Json | Format-List

# Test scoped service
curl -X GET "https://localhost:5001/api/didemo/scoped-service" | ConvertFrom-Json | Format-List

# Make multiple requests to see scoped behavior
1..3 | ForEach-Object {
    Write-Host "`nRequest $_"
    curl -X GET "https://localhost:5001/api/didemo/single-injection" | ConvertFrom-Json
}
```

7. Expected JSON Responses

Single Injection (First Request):

```json
{
  "title": "Single Injection Per Service",
  "transient": {
    "guid": "a7f3e9c1-4d2b-4e8f-9a3c-5d6e7f8a9b0c",
    "lifetime": "Transient (New per injection)"
  },
  "scoped": {
    "guid": "b5d8f2a4-6e3f-4a7b-8c9d-0e1f2a3b4c5d",
    "lifetime": "Scoped (New per request)"
  },
  "singleton": {
    "guid": "c6e1f3b9-7d4e-4f8a-9b0c-1d2e3f4a5b6c",
    "lifetime": "Singleton (One instance)"
  }
}
```

Multiple Injections (Same Request):

```json
{
  "title": "Multiple Injections (Same Request)",
  "transient": {
    "instance1": "a7f3e9c1-4d2b-4e8f-9a3c-5d6e7f8a9b0c",
    "instance2": "d4g7h2k5-8e1f-4c9a-2b3d-6e7f8a9b0c1d",
    "same": "DIFFERENT"
  },
  "scoped": {
    "instance1": "b5d8f2a4-6e3f-4a7b-8c9d-0e1f2a3b4c5d",
    "instance2": "b5d8f2a4-6e3f-4a7b-8c9d-0e1f2a3b4c5d",
    "same": "SAME"
  },
  "singleton": {
    "instance1": "c6e1f3b9-7d4e-4f8a-9b0c-1d2e3f4a5b6c",
    "instance2": "c6e1f3b9-7d4e-4f8a-9b0c-1d2e3f4a5b6c",
    "same": "SAME"
  }
}
```

Key Differences in Web API

Lifetime HTTP Request 1 HTTP Request 2 Multiple Injections
Transient New instance New instance Different instances
Scoped New instance New instance Same instance
Singleton Same instance Same instance Same instance

Important Notes

1. Scoped = per HTTP request in Web API (DbContext default)
2. Transient = new every time, even in same request
3. Singleton = one instance for whole app lifetime
4. Avoid injecting Scoped/Transient into Singleton (creates captive dependencies)
5. Use IServiceScopeFactory for scoped services in background services
