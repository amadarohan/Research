Here's a complete .NET 10 console app example demonstrating all DI lifetimes (Transient, Scoped, Singleton):

1. Project Setup

```bash
dotnet new console -n DiExample
cd DiExample
dotnet add package Microsoft.Extensions.DependencyInjection
dotnet add package Microsoft.Extensions.Hosting
```

2. Services with Different Lifetimes

```csharp
// Services/IGuidService.cs
public interface IGuidService
{
    string GetGuid();
}

// Transient: New instance every time
public class TransientGuidService : IGuidService
{
    private readonly string _guid = Guid.NewGuid().ToString();
    public string GetGuid() => $"Transient: {_guid}";
}

// Scoped: New instance per scope
public class ScopedGuidService : IGuidService
{
    private readonly string _guid = Guid.NewGuid().ToString();
    public string GetGuid() => $"Scoped: {_guid}";
}

// Singleton: Single instance for app lifetime
public class SingletonGuidService : IGuidService
{
    private readonly string _guid = Guid.NewGuid().ToString();
    public string GetGuid() => $"Singleton: {_guid}";
}
```

3. Consumer Service

```csharp
// Services/ConsumerService.cs
public class ConsumerService
{
    private readonly IGuidService _transient;
    private readonly IGuidService _scoped;
    private readonly IGuidService _singleton;

    public ConsumerService(
        [FromKeyedServices("transient")] IGuidService transient,
        [FromKeyedServices("scoped")] IGuidService scoped,
        [FromKeyedServices("singleton")] IGuidService singleton)
    {
        _transient = transient;
        _scoped = scoped;
        _singleton = singleton;
    }

    public void DisplayGuids(string context)
    {
        Console.WriteLine($"\n{context}:");
        Console.WriteLine($"  {_transient.GetGuid()}");
        Console.WriteLine($"  {_scoped.GetGuid()}");
        Console.WriteLine($"  {_singleton.GetGuid()}");
    }
}
```

4. Program.cs with Host Setup

```csharp
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection.Extensions;

var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((context, services) =>
    {
        // Register services with different lifetimes
        services.AddKeyedSingleton<IGuidService, SingletonGuidService>("singleton");
        services.AddKeyedScoped<IGuidService, ScopedGuidService>("scoped");
        services.AddKeyedTransient<IGuidService, TransientGuidService>("transient");
        
        // Register consumer
        services.AddHostedService<ConsoleHostedService>();
        services.AddScoped<ConsumerService>();
    })
    .Build();

await host.RunAsync();

// Background service to manage scopes
public class ConsoleHostedService : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IHostApplicationLifetime _lifetime;

    public ConsoleHostedService(
        IServiceProvider serviceProvider,
        IHostApplicationLifetime lifetime)
    {
        _serviceProvider = serviceProvider;
        _lifetime = lifetime;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine("=== DI Lifetime Demo ===\n");

        // First scope
        using (var scope = _serviceProvider.CreateScope())
        {
            var consumer = scope.ServiceProvider.GetRequiredService<ConsumerService>();
            consumer.DisplayGuids("First Scope - Instance 1");
            
            // Same scope, new consumer - Scoped stays same
            var consumer2 = scope.ServiceProvider.GetRequiredService<ConsumerService>();
            consumer2.DisplayGuids("First Scope - Instance 2");
        }

        // Second scope
        using (var scope = _serviceProvider.CreateScope())
        {
            var consumer = scope.ServiceProvider.GetRequiredService<ConsumerService>();
            consumer.DisplayGuids("Second Scope - New Scope");
        }

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
        _lifetime.StopApplication();

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
```

5. Expected Output

```
=== DI Lifetime Demo ===

First Scope - Instance 1:
  Transient: a7f3e9c1-...
  Scoped: b5d8f2a4-...
  Singleton: c6e1f3b9-...

First Scope - Instance 2:
  Transient: d4g7h2k5-...  (NEW)
  Scoped: b5d8f2a4-...     (SAME)
  Singleton: c6e1f3b9-...  (SAME)

Second Scope - New Scope:
  Transient: e9j4m6n2-...  (NEW)
  Scoped: f2k8p3q7-...     (NEW)
  Singleton: c6e1f3b9-...  (SAME)
```

Key Differences Summary

Lifetime New Instance Best For
Transient Every injection Lightweight, stateless services
Scoped Per scope/request DbContext, per-request state
Singleton Once per app Caching, logging, configuration

Alternative: Without Keyed Services (Simpler)

If you don't need multiple implementations:

```csharp
// Program.cs
services.AddTransient<IGuidService, TransientGuidService>();
services.AddScoped<IGuidService, ScopedGuidService>();
services.AddSingleton<IGuidService, SingletonGuidService>();

// Consumer.cs - uses last registered (Singleton in this case)
// Better: inject each separately
public class ConsumerService
{
    private readonly TransientGuidService _transient;
    private readonly ScopedGuidService _scoped;
    private readonly SingletonGuidService _singleton;
    
    // Constructor injection with concrete types
}
```

This demonstrates how different lifetimes behave in practice. Run the code to see the GUID changes!
