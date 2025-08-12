# ASP.NET Core Developer Code Challenges Based on "The Pragmatic Programmer"

As your teacher and interviewer, I've created a series of code challenges that progress from beginner to senior levels, all grounded in the principles from "The Pragmatic Programmer". These challenges will help you practice while demonstrating your understanding of pragmatic development concepts.

## Beginner Level Challenges

### 1. DRY Principle Implementation
**Challenge**: Create an ASP.NET Core Web API with two endpoints that share common validation logic. Refactor to follow DRY principle.

**Solution**:
```csharp
// Before (Violating DRY)
[ApiController]
[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    [HttpPost("create")]
    public IActionResult CreateProduct([FromBody] ProductDto product)
    {
        if (string.IsNullOrEmpty(product.Name))
            return BadRequest("Name is required");
        if (product.Price <= 0)
            return BadRequest("Price must be positive");
        // ... implementation
    }

    [HttpPut("update/{id}")]
    public IActionResult UpdateProduct(int id, [FromBody] ProductDto product)
    {
        if (string.IsNullOrEmpty(product.Name))
            return BadRequest("Name is required");
        if (product.Price <= 0)
            return BadRequest("Price must be positive");
        // ... implementation
    }
}

// After (DRY compliant)
public static class ProductValidation
{
    public static IActionResult ValidateProduct(ProductDto product)
    {
        if (string.IsNullOrEmpty(product.Name))
            return BadRequest("Name is required");
        if (product.Price <= 0)
            return BadRequest("Price must be positive");
        return null;
    }
}

[ApiController]
[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    [HttpPost("create")]
    public IActionResult CreateProduct([FromBody] ProductDto product)
    {
        var validationResult = ProductValidation.ValidateProduct(product);
        if (validationResult != null) return validationResult;
        // ... implementation
    }

    [HttpPut("update/{id}")]
    public IActionResult UpdateProduct(int id, [FromBody] ProductDto product)
    {
        var validationResult = ProductValidation.ValidateProduct(product);
        if (validationResult != null) return validationResult;
        // ... implementation
    }
}
```

### 2. Plain Text Configuration
**Challenge**: Create a service that reads configuration from a plain text file instead of appsettings.json.

**Solution**:
```csharp
public class PlainTextConfigurationProvider : ConfigurationProvider
{
    private readonly string _filePath;

    public PlainTextConfigurationProvider(string filePath)
    {
        _filePath = filePath;
    }

    public override void Load()
    {
        var data = new Dictionary<string, string>();
        foreach (var line in File.ReadAllLines(_filePath))
        {
            var parts = line.Split('=');
            if (parts.Length == 2)
            {
                data[parts[0]] = parts[1];
            }
        }
        Data = data;
    }
}

// In Program.cs
var builder = WebApplication.CreateBuilder(args);
builder.Configuration.Add(new PlainTextConfigurationProvider("config.txt"));
```

### 3. Basic Tracer Bullet Implementation
**Challenge**: Implement a "tracer bullet" endpoint that demonstrates a complete but minimal feature flow.

**Solution**:
```csharp
[ApiController]
[Route("api/[controller]")]
public class TracerController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping([FromServices] ILogger<TracerController> logger)
    {
        logger.LogInformation("Tracer bullet hit!");
        return Ok(new 
        {
            Message = "Pong",
            Timestamp = DateTime.UtcNow,
            Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
        });
    }
}
```

## Intermediate Level Challenges

### 4. Orthogonal Service Design
**Challenge**: Create two services where one handles business logic and another handles notifications, demonstrating orthogonality.

**Solution**:
```csharp
public interface INotificationService
{
    Task SendNotification(string message);
}

public class EmailNotificationService : INotificationService
{
    public Task SendNotification(string message)
    {
        // Email implementation
        return Task.CompletedTask;
    }
}

public class OrderService
{
    private readonly INotificationService _notificationService;

    public OrderService(INotificationService notificationService)
    {
        _notificationService = notificationService;
    }

    public async Task PlaceOrder(Order order)
    {
        // Business logic
        await _notificationService.SendNotification($"Order {order.Id} placed");
    }
}

// Changes to notification service don't affect order service and vice versa
```

### 5. Domain-Specific Language (DSL) for Validation
**Challenge**: Create a fluent validation builder that reads like domain language.

**Solution**:
```csharp
public class ProductValidator
{
    private readonly List<string> _errors = new();
    private readonly ProductDto _product;

    public ProductValidator(ProductDto product)
    {
        _product = product;
    }

    public ProductValidator MustHaveName()
    {
        if (string.IsNullOrEmpty(_product.Name))
            _errors.Add("Product must have a name");
        return this;
    }

    public ProductValidator MustHavePositivePrice()
    {
        if (_product.Price <= 0)
            _errors.Add("Price must be positive");
        return this;
    }

    public ValidationResult Validate()
    {
        return new ValidationResult(_errors);
    }
}

// Usage:
var result = new ProductValidator(product)
    .MustHaveName()
    .MustHavePositivePrice()
    .Validate();
```

### 6. Reversibility with Repository Pattern
**Challenge**: Implement a repository pattern that allows switching between different data stores.

**Solution**:
```csharp
public interface IRepository<T>
{
    Task AddAsync(T entity);
    Task<T> GetByIdAsync(int id);
}

public class SqlRepository<T> : IRepository<T>
{
    private readonly DbContext _context;
    
    public SqlRepository(DbContext context)
    {
        _context = context;
    }

    public async Task AddAsync(T entity)
    {
        _context.Set<T>().Add(entity);
        await _context.SaveChangesAsync();
    }

    public async Task<T> GetByIdAsync(int id)
    {
        return await _context.Set<T>().FindAsync(id);
    }
}

public class MongoRepository<T> : IRepository<T>
{
    private readonly IMongoCollection<T> _collection;
    
    public MongoRepository(IMongoDatabase database, string collectionName)
    {
        _collection = database.GetCollection<T>(collectionName);
    }

    public async Task AddAsync(T entity)
    {
        await _collection.InsertOneAsync(entity);
    }

    public async Task<T> GetByIdAsync(int id)
    {
        var filter = Builders<T>.Filter.Eq("Id", id);
        return await _collection.Find(filter).FirstOrDefaultAsync();
    }
}

// Can switch implementations without changing business logic
```

### 7. Prototype for Performance Testing
**Challenge**: Create a prototype endpoint to test performance characteristics.

**Solution**:
```csharp
[ApiController]
[Route("api/prototype")]
public class PrototypeController : ControllerBase
{
    [HttpGet("loadtest")]
    public async Task<IActionResult> LoadTest([FromQuery] int iterations = 1000)
    {
        var results = new List<long>();
        var watch = new Stopwatch();

        for (int i = 0; i < iterations; i++)
        {
            watch.Restart();
            // Prototype code - no error handling, simplified logic
            await Task.Delay(1); // Simulate work
            watch.Stop();
            results.Add(watch.ElapsedMilliseconds);
        }

        return Ok(new
        {
            Average = results.Average(),
            Max = results.Max(),
            Min = results.Min()
        });
    }
}
```

### 8. Text Manipulation for Code Generation
**Challenge**: Create a code generator that produces model classes from a text definition.

**Solution**:
```csharp
public class CodeGenerator
{
    public string GenerateModelClass(string className, Dictionary<string, string> properties)
    {
        var sb = new StringBuilder();
        
        sb.AppendLine($"public class {className}");
        sb.AppendLine("{");
        
        foreach (var prop in properties)
        {
            sb.AppendLine($"    public {prop.Value} {prop.Key} {{ get; set; }}");
        }
        
        sb.AppendLine("}");
        
        return sb.ToString();
    }
}

// Usage:
var generator = new CodeGenerator();
var classCode = generator.GenerateModelClass("Person", new Dictionary<string, string>
{
    ["FirstName"] = "string",
    ["LastName"] = "string",
    ["Age"] = "int"
});
```

## Senior Level Challenges

### 9. Knowledge Portfolio Demonstration
**Challenge**: Create a modular system where new features can be added via plugins loaded at runtime.

**Solution**:
```csharp
public interface IPlugin
{
    string Name { get; }
    void Initialize(IServiceCollection services);
}

public class PluginLoader
{
    public void LoadPlugins(IServiceCollection services, string pluginDirectory)
    {
        foreach (var dll in Directory.GetFiles(pluginDirectory, "*.dll"))
        {
            var assembly = Assembly.LoadFrom(dll);
            var pluginTypes = assembly.GetTypes()
                .Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface);
            
            foreach (var type in pluginTypes)
            {
                if (Activator.CreateInstance(type) is IPlugin plugin)
                {
                    plugin.Initialize(services);
                }
            }
        }
    }
}

// In Program.cs
var builder = WebApplication.CreateBuilder(args);
var pluginLoader = new PluginLoader();
pluginLoader.LoadPlugins(builder.Services, "Plugins");
```

### 10. Advanced Orthogonal CQRS Implementation
**Challenge**: Implement a CQRS pattern with completely separate paths for commands and queries.

**Solution**:
```csharp
// Command side
public interface ICommandHandler<in TCommand>
{
    Task Handle(TCommand command);
}

public class CreateProductCommand
{
    public string Name { get; set; }
    public decimal Price { get; set; }
}

public class CreateProductHandler : ICommandHandler<CreateProductCommand>
{
    private readonly ProductDbContext _context;
    
    public CreateProductHandler(ProductDbContext context)
    {
        _context = context;
    }

    public async Task Handle(CreateProductCommand command)
    {
        var product = new Product(command.Name, command.Price);
        _context.Products.Add(product);
        await _context.SaveChangesAsync();
    }
}

// Query side
public interface IQueryHandler<in TQuery, TResult>
{
    Task<TResult> Handle(TQuery query);
}

public class GetProductByIdQuery
{
    public int Id { get; set; }
}

public class GetProductByIdHandler : IQueryHandler<GetProductByIdQuery, ProductDto>
{
    private readonly ProductReadDbContext _context;
    
    public GetProductByIdHandler(ProductReadDbContext context)
    {
        _context = context;
    }

    public async Task<ProductDto> Handle(GetProductByIdQuery query)
    {
        return await _context.Products
            .Where(p => p.Id == query.Id)
            .Select(p => new ProductDto { Name = p.Name, Price = p.Price })
            .FirstOrDefaultAsync();
    }
}

// Separate databases for read and write
```

### 11. Broken Window Theory in Practice
**Challenge**: Take a codebase with several "broken windows" (code smells) and refactor it.

**Solution**:
```csharp
// Before (Broken windows)
public class OrderService
{
    public void ProcessOrder(Order order)
    {
        // 1. Magic numbers
        if (order.Total > 10000)
        {
            // ...
        }
        
        // 2. Long method
        // 100+ lines of code
        
        // 3. Inconsistent naming
        var prodList = order.Items;
        var customerName = order.Customer.FullName;
        
        // 4. Primitive obsession
        if (order.Status == 1 || order.Status == 3)
        {
            // ...
        }
    }
}

// After (Fixed windows)
public class OrderService
{
    private const decimal LargeOrderThreshold = 10000m;
    
    public void ProcessOrder(Order order)
    {
        ValidateOrder(order);
        ProcessLargeOrderIfApplicable(order);
        UpdateOrderStatus(order);
    }

    private void ValidateOrder(Order order)
    {
        if (order == null) throw new ArgumentNullException(nameof(order));
        // ... validation logic
    }

    private void ProcessLargeOrderIfApplicable(Order order)
    {
        if (order.IsLargeOrder(LargeOrderThreshold))
        {
            // Special processing
        }
    }

    private void UpdateOrderStatus(Order order)
    {
        if (order.Status.IsPending() || order.Status.IsProcessing())
        {
            // Update logic
        }
    }
}

public static class OrderExtensions
{
    public static bool IsLargeOrder(this Order order, decimal threshold)
    {
        return order.Total > threshold;
    }
}

public enum OrderStatus
{
    Pending = 1,
    Processing = 2,
    Completed = 3
}

public static class OrderStatusExtensions
{
    public static bool IsPending(this OrderStatus status) => status == OrderStatus.Pending;
    public static bool IsProcessing(this OrderStatus status) => status == OrderStatus.Processing;
}
```

### 12. Stone Soup Pattern for Feature Rollout
**Challenge**: Implement a feature flag system that allows gradual rollout of new features.

**Solution**:
```csharp
public interface IFeatureManager
{
    bool IsEnabled(string feature);
}

public class AppSettingsFeatureManager : IFeatureManager
{
    private readonly IConfiguration _configuration;
    
    public AppSettingsFeatureManager(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public bool IsEnabled(string feature)
    {
        return _configuration.GetValue<bool>($"Features:{feature}");
    }
}

public class NewFeatureService
{
    private readonly IFeatureManager _featureManager;
    private readonly ILegacyService _legacyService;
    private readonly INewService _newService;
    
    public NewFeatureService(
        IFeatureManager featureManager,
        ILegacyService legacyService,
        INewService newService)
    {
        _featureManager = featureManager;
        _legacyService = legacyService;
        _newService = newService;
    }

    public async Task<Result> Process()
    {
        if (_featureManager.IsEnabled("NewFeature"))
        {
            try
            {
                var result = await _newService.Process();
                // Log success metrics
                return result;
            }
            catch (Exception ex)
            {
                // Fallback to legacy
                return await _legacyService.Process();
            }
        }
        
        return await _legacyService.Process();
    }
}
```

### 13. Boiled Frog Monitoring
**Challenge**: Implement performance monitoring that detects gradual degradation.

**Solution**:
```csharp
public class PerformanceMonitor
{
    private readonly List<double> _responseTimes = new();
    private readonly int _sampleSize;
    private readonly double _threshold;
    
    public PerformanceMonitor(int sampleSize = 100, double threshold = 1.5)
    {
        _sampleSize = sampleSize;
        _threshold = threshold;
    }

    public void RecordResponseTime(double milliseconds)
    {
        _responseTimes.Add(milliseconds);
        
        if (_responseTimes.Count > _sampleSize)
        {
            _responseTimes.RemoveAt(0);
        }
    }

    public bool CheckForDegradation()
    {
        if (_responseTimes.Count < _sampleSize) return false;
        
        var baseline = _responseTimes.Take(_sampleSize / 2).Average();
        var current = _responseTimes.Skip(_sampleSize / 2).Average();
        
        return current > baseline * _threshold;
    }
}

// Middleware to track response times
public class PerformanceMonitoringMiddleware
{
    private readonly RequestDelegate _next;
    private readonly PerformanceMonitor _monitor;
    
    public PerformanceMonitoringMiddleware(RequestDelegate next, PerformanceMonitor monitor)
    {
        _next = next;
        _monitor = monitor;
    }

    public async Task Invoke(HttpContext context)
    {
        var watch = Stopwatch.StartNew();
        await _next(context);
        watch.Stop();
        
        _monitor.RecordResponseTime(watch.ElapsedMilliseconds);
        
        if (_monitor.CheckForDegradation())
        {
            // Alert or log
        }
    }
}
```

### 14. Advanced Debugging Techniques
**Challenge**: Create a diagnostic endpoint that helps debug production issues.

**Solution**:
```csharp
[ApiController]
[Route("api/diagnostics")]
public class DiagnosticsController : ControllerBase
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IConfiguration _configuration;
    
    public DiagnosticsController(IServiceProvider serviceProvider, IConfiguration configuration)
    {
        _serviceProvider = serviceProvider;
        _configuration = configuration;
    }

    [HttpGet("environment")]
    public IActionResult GetEnvironment()
    {
        var env = new
        {
            Environment.MachineName,
            Environment.OSVersion,
            Environment.Version,
            EnvironmentVariables = Environment.GetEnvironmentVariables(),
            Configuration = _configuration.AsEnumerable().ToDictionary(x => x.Key, x => x.Value)
        };
        
        return Ok(env);
    }

    [HttpGet("services")]
    public IActionResult GetRegisteredServices()
    {
        var services = _serviceProvider.GetService<IEnumerable<ServiceDescriptor>>();
        return Ok(services.Select(s => new
        {
            s.ServiceType.Name,
            s.ImplementationType?.Name,
            s.Lifetime
        }));
    }

    [HttpGet("test-db")]
    public async Task<IActionResult> TestDatabase([FromServices] DbContext dbContext)
    {
        try
        {
            var canConnect = await dbContext.Database.CanConnectAsync();
            return Ok(new { Success = canConnect });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { Error = ex.Message, Details = ex.ToString() });
        }
    }
}
```

### 15. Pragmatic Estimation Implementation
**Challenge**: Create an estimation service that learns from past estimates.

**Solution**:
```csharp
public class EstimationService
{
    private readonly List<EstimationRecord> _history = new();
    
    public EstimationResult Estimate(EstimationRequest request)
    {
        var similarItems = _history
            .Where(x => x.Complexity == request.Complexity && 
                       x.Technology == request.Technology)
            .ToList();
            
        var baseEstimate = CalculateBaseEstimate(request);
        var adjustmentFactor = CalculateAdjustmentFactor(similarItems);
        
        var result = new EstimationResult(
            Optimistic: baseEstimate * adjustmentFactor * 0.8,
            MostLikely: baseEstimate * adjustmentFactor,
            Pessimistic: baseEstimate * adjustmentFactor * 1.2);
            
        return result;
    }

    public void RecordActual(EstimationRecord record)
    {
        _history.Add(record);
    }

    private double CalculateBaseEstimate(EstimationRequest request)
    {
        // Simple calculation based on complexity
        return request.Complexity switch
        {
            Complexity.Simple => 1,
            Complexity.Medium => 3,
            Complexity.Complex => 8,
            _ => 5
        };
    }

    private double CalculateAdjustmentFactor(List<EstimationRecord> similarItems)
    {
        if (!similarItems.Any()) return 1.0;
        
        var averageAccuracy = similarItems
            .Average(x => x.ActualDuration / x.EstimatedDuration);
            
        return 1.0 / averageAccuracy;
    }
}

public record EstimationRequest(Complexity Complexity, string Technology);
public record EstimationResult(double Optimistic, double MostLikely, double Pessimistic);
public record EstimationRecord(
    Complexity Complexity, 
    string Technology, 
    double EstimatedDuration, 
    double ActualDuration);

public enum Complexity { Simple, Medium, Complex }
```

## Additional Mastery Challenges

### 16. Domain-Specific Middleware
**Challenge**: Create middleware that understands domain-specific concepts.

**Solution**:
```csharp
public class TenantMiddleware
{
    private readonly RequestDelegate _next;
    
    public TenantMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context, ITenantService tenantService)
    {
        // Extract tenant from domain, header, or path
        var tenantId = context.Request.Headers["X-Tenant"].FirstOrDefault() 
            ?? context.Request.Host.Host.Split('.')[0];
            
        if (!string.IsNullOrEmpty(tenantId))
        {
            tenantService.SetCurrentTenant(tenantId);
        }
        
        await _next(context);
    }
}

// Registration
app.UseMiddleware<TenantMiddleware>();
```

### 17. Pragmatic Logging Strategy
**Challenge**: Implement structured logging with different levels based on context.

**Solution**:
```csharp
public static class LoggerExtensions
{
    public static void LogDomainEvent(this ILogger logger, 
        string eventType, 
        object data,
        [CallerMemberName] string member = "")
    {
        logger.LogInformation("DomainEvent:{EventType} from {Member} with {@Data}", 
            eventType, member, data);
    }

    public static void LogPerformanceWarning(this ILogger logger,
        string operation,
        long milliseconds,
        [CallerMemberName] string member = "")
    {
        if (milliseconds > 500)
        {
            logger.LogWarning("Performance:{Operation} from {Member} took {Milliseconds}ms", 
                operation, member, milliseconds);
        }
        else
        {
            logger.LogDebug("Performance:{Operation} from {Member} took {Milliseconds}ms", 
                operation, member, milliseconds);
        }
    }
}

// Usage:
_logger.LogDomainEvent("OrderCreated", new { OrderId = order.Id });
_logger.LogPerformanceWarning("DatabaseQuery", watch.ElapsedMilliseconds);
```

### 18. Pragmatic Caching Strategy
**Challenge**: Implement a caching decorator with pragmatic trade-offs.

**Solution**:
```csharp
public class CachingDecorator<T> : IRepository<T>
{
    private readonly IRepository<T> _inner;
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _defaultCacheDuration;
    
    public CachingDecorator(IRepository<T> inner, IMemoryCache cache, TimeSpan defaultCacheDuration)
    {
        _inner = inner;
        _cache = cache;
        _defaultCacheDuration = defaultCacheDuration;
    }

    public async Task<T> GetByIdAsync(int id)
    {
        var cacheKey = $"{typeof(T).Name}_{id}";
        
        if (_cache.TryGetValue(cacheKey, out T cachedItem))
        {
            return cachedItem;
        }
        
        var item = await _inner.GetByIdAsync(id);
        
        // Pragmatic caching - don't cache nulls or empty items
        if (item != null)
        {
            _cache.Set(cacheKey, item, _defaultCacheDuration);
        }
        
        return item;
    }

    public async Task AddAsync(T entity)
    {
        await _inner.AddAsync(entity);
        
        // Invalidate cache for this item
        var id = (int)entity.GetType().GetProperty("Id").GetValue(entity);
        var cacheKey = $"{typeof(T).Name}_{id}";
        _cache.Remove(cacheKey);
    }
}
```

These challenges cover the full spectrum of pragmatic programming principles from "The Pragmatic Programmer" while focusing on practical ASP.NET Core implementation. They progress from basic concepts to advanced architectural patterns, giving you opportunities to demonstrate mastery at every level.
