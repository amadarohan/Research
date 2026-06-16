Here's a .NET 10 Web API demonstrating the same leverageability principles, but optimized for HTTP scenarios with controllers, middleware, and background services.

---

The Sample: Order Management API

We'll build a REST API that processes orders from configurable sources with swappable storage, logging, and formatting—all extensible without modifying core business logic.

---

1. Project Structure

```
OrderManagementAPI/
├── Program.cs
├── appsettings.json
├── Controllers/
│   └── OrdersController.cs
├── Core/
│   ├── Abstractions/
│   │   ├── IOrderRepository.cs
│   │   ├── IOrderSource.cs
│   │   ├── IOrderFormatter.cs
│   │   └── INotificationService.cs
│   ├── Models/
│   │   └── Order.cs
│   └── Services/
│       └── OrderProcessingService.cs
├── Implementations/
│   ├── Repositories/
│   │   ├── InMemoryOrderRepository.cs
│   │   └── SqlOrderRepository.cs
│   ├── Sources/
│   │   ├── CsvOrderSource.cs
│   │   └── JsonOrderSource.cs
│   ├── Formatters/
│   │   ├── JsonFormatter.cs
│   │   └── MarkdownFormatter.cs
│   └── Notifications/
│       ├── EmailNotificationService.cs
│       └── SlackNotificationService.cs
├── Middleware/
│   └── RequestLoggingMiddleware.cs
└── Extensions/
    └── ServiceExtensions.cs
```

---

2. Core Abstractions (Extensible Contracts)

```csharp
// Core/Abstractions/IOrderRepository.cs
public interface IOrderRepository
{
    Task<IEnumerable<Order>> GetAllAsync();
    Task<Order?> GetByIdAsync(int id);
    Task AddAsync(Order order);
    Task UpdateAsync(Order order);
    Task DeleteAsync(int id);
}

// Core/Abstractions/IOrderSource.cs
public interface IOrderSource
{
    Task<IEnumerable<Order>> FetchOrdersAsync();
}

// Core/Abstractions/IOrderFormatter.cs
public interface IOrderFormatter
{
    string Format(IEnumerable<Order> orders);
    string Format(Order order);
}

// Core/Abstractions/INotificationService.cs
public interface INotificationService
{
    Task NotifyAsync(string message, NotificationType type);
}

// Core/Models/Order.cs
public class Order
{
    public int Id { get; set; }
    public string CustomerName { get; set; } = string.Empty;
    public decimal TotalAmount { get; set; }
    public DateTime OrderDate { get; set; }
    public OrderStatus Status { get; set; }
}

public enum OrderStatus
{
    Pending,
    Processing,
    Shipped,
    Delivered,
    Cancelled
}

public enum NotificationType
{
    Info,
    Warning,
    Error,
    Success
}
```

---

3. Core Business Service (Closed for Modification)

```csharp
// Core/Services/OrderProcessingService.cs
public class OrderProcessingService
{
    private readonly IOrderRepository _repository;
    private readonly IOrderSource _source;
    private readonly IOrderFormatter _formatter;
    private readonly INotificationService _notification;
    private readonly ILogger<OrderProcessingService> _logger;

    public OrderProcessingService(
        IOrderRepository repository,
        IOrderSource source,
        IOrderFormatter formatter,
        INotificationService notification,
        ILogger<OrderProcessingService> logger)
    {
        _repository = repository;
        _source = source;
        _formatter = formatter;
        _notification = notification;
        _logger = logger;
    }

    public async Task<Order> ImportOrderFromSourceAsync()
    {
        _logger.LogInformation("Importing orders from source...");
        var orders = await _source.FetchOrdersAsync();
        
        var order = orders.FirstOrDefault();
        if (order == null)
            throw new InvalidOperationException("No orders found in source");

        await _repository.AddAsync(order);
        await _notification.NotifyAsync(
            $"New order imported: {order.Id} - {order.CustomerName} (${order.TotalAmount})",
            NotificationType.Success);

        return order;
    }

    public async Task<IEnumerable<Order>> GetAllOrdersAsync()
    {
        return await _repository.GetAllAsync();
    }

    public async Task<string> GetFormattedOrdersAsync()
    {
        var orders = await _repository.GetAllAsync();
        return _formatter.Format(orders);
    }

    public async Task<Order> ProcessOrderAsync(int id)
    {
        var order = await _repository.GetByIdAsync(id);
        if (order == null)
            throw new KeyNotFoundException($"Order {id} not found");

        if (order.Status == OrderStatus.Pending)
        {
            order.Status = OrderStatus.Processing;
            await _repository.UpdateAsync(order);
            
            await _notification.NotifyAsync(
                $"Order {id} is now processing",
                NotificationType.Info);
        }

        return order;
    }
}
```

---

4. Implementations (Swappable via Configuration)

```csharp
// Implementations/Repositories/InMemoryOrderRepository.cs
public class InMemoryOrderRepository : IOrderRepository
{
    private readonly List<Order> _orders = new();
    private int _nextId = 1;

    public Task<IEnumerable<Order>> GetAllAsync() 
        => Task.FromResult(_orders.AsEnumerable());

    public Task<Order?> GetByIdAsync(int id) 
        => Task.FromResult(_orders.FirstOrDefault(o => o.Id == id));

    public Task AddAsync(Order order)
    {
        order.Id = _nextId++;
        _orders.Add(order);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(Order order)
    {
        var existing = _orders.FirstOrDefault(o => o.Id == order.Id);
        if (existing != null)
        {
            existing.CustomerName = order.CustomerName;
            existing.TotalAmount = order.TotalAmount;
            existing.Status = order.Status;
        }
        return Task.CompletedTask;
    }

    public Task DeleteAsync(int id)
    {
        _orders.RemoveAll(o => o.Id == id);
        return Task.CompletedTask;
    }
}

// Implementations/Repositories/SqlOrderRepository.cs
public class SqlOrderRepository : IOrderRepository
{
    private readonly string _connectionString;
    private readonly ILogger<SqlOrderRepository> _logger;

    public SqlOrderRepository(string connectionString, ILogger<SqlOrderRepository> logger)
    {
        _connectionString = connectionString;
        _logger = logger;
    }

    // Dapper/EF Core implementation would go here
    public async Task<IEnumerable<Order>> GetAllAsync()
    {
        _logger.LogInformation("Fetching from SQL database");
        // Simulate DB call
        await Task.Delay(100);
        return new List<Order>();
    }

    // Other methods implemented with actual SQL
    public Task<Order?> GetByIdAsync(int id) => throw new NotImplementedException();
    public Task AddAsync(Order order) => throw new NotImplementedException();
    public Task UpdateAsync(Order order) => throw new NotImplementedException();
    public Task DeleteAsync(int id) => throw new NotImplementedException();
}

// Implementations/Sources/JsonOrderSource.cs
public class JsonOrderSource : IOrderSource
{
    private readonly HttpClient _httpClient;
    private readonly string _endpoint;

    public JsonOrderSource(HttpClient httpClient, IConfiguration config)
    {
        _httpClient = httpClient;
        _endpoint = config["OrderSource:JsonEndpoint"] ?? "https://api.example.com/orders";
    }

    public async Task<IEnumerable<Order>> FetchOrdersAsync()
    {
        var response = await _httpClient.GetStringAsync(_endpoint);
        // Deserialize JSON to orders
        return JsonSerializer.Deserialize<IEnumerable<Order>>(response) 
            ?? Array.Empty<Order>();
    }
}

// Implementations/Formatters/MarkdownFormatter.cs
public class MarkdownFormatter : IOrderFormatter
{
    public string Format(IEnumerable<Order> orders)
    {
        var sb = new StringBuilder();
        sb.AppendLine("| ID | Customer | Amount | Status |");
        sb.AppendLine("|----|----------|--------|--------|");
        foreach (var o in orders)
            sb.AppendLine($"| {o.Id} | {o.CustomerName} | ${o.TotalAmount} | {o.Status} |");
        return sb.ToString();
    }

    public string Format(Order order) 
        => $"**Order #{order.Id}** - {order.CustomerName} (${order.TotalAmount})";
}

// Implementations/Notifications/SlackNotificationService.cs
public class SlackNotificationService : INotificationService
{
    private readonly HttpClient _httpClient;
    private readonly string _webhookUrl;

    public SlackNotificationService(HttpClient httpClient, IConfiguration config)
    {
        _httpClient = httpClient;
        _webhookUrl = config["Slack:WebhookUrl"] ?? throw new ArgumentNullException();
    }

    public async Task NotifyAsync(string message, NotificationType type)
    {
        var emoji = type switch
        {
            NotificationType.Success => "✅",
            NotificationType.Error => "❌",
            NotificationType.Warning => "⚠️",
            _ => "ℹ️"
        };
        
        var payload = new { text = $"{emoji} {message}" };
        await _httpClient.PostAsJsonAsync(_webhookUrl, payload);
    }
}
```

---

5. API Controller (Thin Layer)

```csharp
// Controllers/OrdersController.cs
[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    private readonly OrderProcessingService _service;
    private readonly IOrderFormatter _formatter;

    public OrdersController(OrderProcessingService service, IOrderFormatter formatter)
    {
        _service = service;
        _formatter = formatter;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var orders = await _service.GetAllOrdersAsync();
        return Ok(orders);
    }

    [HttpGet("formatted")]
    public async Task<IActionResult> GetFormatted()
    {
        var formatted = await _service.GetFormattedOrdersAsync();
        return Ok(new { formatted });
    }

    [HttpPost("import")]
    public async Task<IActionResult> ImportFromSource()
    {
        try
        {
            var order = await _service.ImportOrderFromSourceAsync();
            return CreatedAtAction(nameof(GetAll), new { id = order.Id }, order);
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpPut("{id}/process")]
    public async Task<IActionResult> Process(int id)
    {
        try
        {
            var order = await _service.ProcessOrderAsync(id);
            return Ok(order);
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }
}
```

---

6. Middleware (Cross-Cutting Leverage)

```csharp
// Middleware/RequestLoggingMiddleware.cs
public class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        _logger.LogInformation(
            "Request: {Method} {Path} | IP: {IP}",
            context.Request.Method,
            context.Request.Path,
            context.Connection.RemoteIpAddress);

        await _next(context);

        _logger.LogInformation(
            "Response: {StatusCode} for {Method} {Path}",
            context.Response.StatusCode,
            context.Request.Method,
            context.Request.Path);
    }
}
```

---

7. Program.cs (DI Configuration with Leverageability)

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure based on appsettings.json
var config = builder.Configuration;

// ---------- REPOSITORY (Swappable) ----------
var repoType = config["Storage:Type"];
switch (repoType)
{
    case "Sql":
        builder.Services.AddScoped<IOrderRepository>(sp =>
            new SqlOrderRepository(
                config.GetConnectionString("Default")!,
                sp.GetRequiredService<ILogger<SqlOrderRepository>>()));
        break;
    case "InMemory":
    default:
        builder.Services.AddSingleton<IOrderRepository, InMemoryOrderRepository>();
        break;
}

// ---------- ORDER SOURCE (Swappable) ----------
var sourceType = config["OrderSource:Type"];
if (sourceType == "Json")
{
    builder.Services.AddHttpClient<IOrderSource, JsonOrderSource>();
}
else if (sourceType == "Csv")
{
    builder.Services.AddScoped<IOrderSource, CsvOrderSource>();
}
else
{
    // Default to static/mock source
    builder.Services.AddScoped<IOrderSource, MockOrderSource>();
}

// ---------- FORMATTER (Swappable) ----------
var formatterType = config["Formatter:Type"];
if (formatterType == "Markdown")
{
    builder.Services.AddScoped<IOrderFormatter, MarkdownFormatter>();
}
else
{
    builder.Services.AddScoped<IOrderFormatter, JsonFormatter>();
}

// ---------- NOTIFICATION (Swappable) ----------
var notificationType = config["Notification:Type"];
if (notificationType == "Slack")
{
    builder.Services.AddHttpClient<INotificationService, SlackNotificationService>();
}
else if (notificationType == "Email")
{
    builder.Services.AddScoped<INotificationService, EmailNotificationService>();
}
else
{
    // No-op notification for development
    builder.Services.AddScoped<INotificationService, NoOpNotificationService>();
}

// ---------- CORE BUSINESS SERVICE ----------
builder.Services.AddScoped<OrderProcessingService>();

// ---------- MIDDLEWARE ----------
builder.Services.AddTransient<RequestLoggingMiddleware>();

// ---------- HEALTH CHECKS ----------
builder.Services.AddHealthChecks();

var app = builder.Build();

// Configure pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseMiddleware<RequestLoggingMiddleware>();
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();
app.MapHealthChecks("/health");

// Seed sample data if using InMemory
if (repoType == "InMemory")
{
    var repo = app.Services.GetRequiredService<IOrderRepository>();
    await SeedDataAsync(repo);
}

app.Run();

async Task SeedDataAsync(IOrderRepository repo)
{
    var sampleOrders = new[]
    {
        new Order { CustomerName = "Acme Corp", TotalAmount = 1500m, OrderDate = DateTime.UtcNow, Status = OrderStatus.Pending },
        new Order { CustomerName = "Beta Inc", TotalAmount = 2300m, OrderDate = DateTime.UtcNow.AddDays(-1), Status = OrderStatus.Shipped }
    };
    foreach (var order in sampleOrders)
        await repo.AddAsync(order);
}
```

---

8. Configuration (appsettings.json)

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "Storage": {
    "Type": "InMemory"  // Change to "Sql" for real database
  },
  "OrderSource": {
    "Type": "Json",     // Change to "Csv" or "Mock"
    "JsonEndpoint": "https://api.orders.com/latest"
  },
  "Formatter": {
    "Type": "Markdown"  // Change to "Json" for raw JSON
  },
  "Notification": {
    "Type": "Slack",    // Change to "Email" or "NoOp"
    "Slack": {
      "WebhookUrl": "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    }
  },
  "ConnectionStrings": {
    "Default": "Server=localhost;Database=Orders;User Id=sa;Password=YourPassword!;"
  },
  "AllowedHosts": "*"
}
```

---

9. Extension Method for Clean Registration

```csharp
// Extensions/ServiceExtensions.cs
public static class ServiceExtensions
{
    public static IServiceCollection AddSwappableServices(
        this IServiceCollection services, 
        IConfiguration config)
    {
        // Register all services with config-based swapping
        services.AddRepository(config);
        services.AddSource(config);
        services.AddFormatter(config);
        services.AddNotification(config);
        services.AddScoped<OrderProcessingService>();
        
        return services;
    }

    private static IServiceCollection AddRepository(this IServiceCollection services, IConfiguration config)
    {
        var type = config["Storage:Type"];
        return type switch
        {
            "Sql" => services.AddScoped<IOrderRepository>(sp =>
                new SqlOrderRepository(
                    config.GetConnectionString("Default")!,
                    sp.GetRequiredService<ILogger<SqlOrderRepository>>())),
            _ => services.AddSingleton<IOrderRepository, InMemoryOrderRepository>()
        };
    }

    // Similar for Source, Formatter, Notification...
}
```

Then in Program.cs:

```csharp
builder.Services.AddSwappableServices(builder.Configuration);
```

---

Leverageability in Action (Web API)

What you can change Configuration change Zero Code Change?
Database (InMemory → SQL) Storage:Type = "Sql" ✅ Yes
Data Source (JSON → CSV) OrderSource:Type = "Csv" ✅ Yes
Output Format (Markdown → JSON) Formatter:Type = "Json" ✅ Yes
Notification (Slack → Email) Notification:Type = "Email" ✅ Yes
Add new source Create new class + config case ✅ Yes
Add middleware Add to pipeline ✅ Yes
Authentication Add JWT middleware ✅ Yes

---

Advanced Leverageability Features

1. Feature Flags with Environment Variables

```csharp
// Enable/disable features at runtime
if (config.GetValue<bool>("Features:UseCache"))
    services.AddScoped<IOrderRepository, CachedOrderRepository>();
```

2. Decorator Pattern for Cross-Cutting Concerns

```csharp
public class LoggingOrderRepository : IOrderRepository
{
    private readonly IOrderRepository _inner;
    private readonly ILogger _logger;
    // Logs all calls before delegating to inner repository
}
```

3. Dynamic Strategy Selection

```csharp
// Choose formatter based on Accept header at runtime
public class DynamicFormatter : IOrderFormatter
{
    private readonly IEnumerable<IOrderFormatter> _formatters;
    
    public string Format(IEnumerable<Order> orders, string acceptType)
    {
        var formatter = acceptType switch
        {
            "application/json" => _formatters.OfType<JsonFormatter>().First(),
            "text/markdown" => _formatters.OfType<MarkdownFormatter>().First(),
            _ => _formatters.First()
        };
        return formatter.Format(orders);
    }
}
```

---

Testing Leverageability

```csharp
// OrderProcessingServiceTests.cs
public class OrderProcessingServiceTests
{
    [Fact]
    public async Task ImportOrder_CallsRepositoryAndNotifier()
    {
        // Arrange - swap all dependencies with mocks
        var mockRepo = new Mock<IOrderRepository>();
        var mockSource = new Mock<IOrderSource>();
        var mockNotifier = new Mock<INotificationService>();
        var formatter = new MarkdownFormatter();
        var logger = new Mock<ILogger<OrderProcessingService>>();

        mockSource.Setup(s => s.FetchOrdersAsync())
            .ReturnsAsync(new[] { new Order { CustomerName = "Test" } });

        var service = new OrderProcessingService(
            mockRepo.Object,
            mockSource.Object,
            formatter,
            mockNotifier.Object,
            logger.Object);

        // Act
        await service.ImportOrderFromSourceAsync();

        // Assert
        mockRepo.Verify(r => r.AddAsync(It.IsAny<Order>()), Times.Once);
        mockNotifier.Verify(n => n.NotifyAsync(It.IsAny<string>(), NotificationType.Success), Times.Once);
    }
}
```

---

Docker & Deployment Leverage

```dockerfile
# Dockerfile - swap configs via environment
ENV Storage__Type=Sql
ENV OrderSource__Type=Json
ENV Notification__Type=Slack
```

Run with different configurations:

```bash
# Development
docker run -e Storage__Type=InMemory myapi

# Production
docker run -e Storage__Type=Sql -e ConnectionStrings__Default="..." myapi
```

---

Key Takeaways for .NET 10 Web API

1. Configuration-driven — Everything swappable via appsettings.json or env vars
2. DI-first — All dependencies injected, easy to swap implementations
3. Open/Closed — New features add new classes, not modify existing ones
4. Middleware pipeline — Add/remove cross-cutting concerns without touching controllers
5. Health checks — Monitor swapped services at runtime
6. Testing — Every component can be mocked/stubbed independently
7. Cloud-ready — Configuration works with Azure App Configuration, AWS Parameter Store

---

This architecture lets you leverage any part of the system—storage, sources, formatting, notifications, middleware, and even the entire processing pipeline—without rewriting core business logic. Perfect for microservices, SaaS multi-tenancy, and enterprise applications! 🚀
