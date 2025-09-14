Of course. As an ASP.NET Core expert, I'll provide 15 code challenges focused on "leverageability"—a key concept meaning to build code that is reusable, maintainable, extensible, and efficient. These challenges will cover middleware, dependency injection, configuration, and more.

---

Challenge 1: Custom Exception Handling Middleware

Problem: Create a global exception handler middleware that catches any unhandled exception, logs it, and returns a consistent, user-friendly JSON response (e.g., { error: "An internal server error has occurred." }) with a 500 status code. This leverages a single point for error management.

Solution:

```csharp
// CustomExceptionMiddleware.cs
public class CustomExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<CustomExceptionMiddleware> _logger;

    public CustomExceptionMiddleware(RequestDelegate next, ILogger<CustomExceptionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext httpContext)
    {
        try
        {
            await _next(httpContext);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unhandled exception occurred.");
            await HandleExceptionAsync(httpContext);
        }
    }

    private static Task HandleExceptionAsync(HttpContext context)
    {
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;

        return context.Response.WriteAsync(new
        {
            error = "An internal server error has occurred."
        }.ToString());
    }
}

// In Program.cs
// app.UseMiddleware<CustomExceptionMiddleware>();
// Or create an extension method for better leverageability:
public static class ExceptionMiddlewareExtensions
{
    public static IApplicationBuilder UseCustomExceptionMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<CustomExceptionMiddleware>();
    }
}
// Then in Program.cs: app.UseCustomExceptionMiddleware();
```

---

Challenge 2: Generic Repository Pattern

Problem: Implement a generic repository interface IRepository<T> and a corresponding Entity Framework Core implementation. This leverages a standard data access pattern across all your entity types.

Solution:

```csharp
// IRepository.cs
public interface IRepository<T> where T : class
{
    Task<T?> GetByIdAsync(int id);
    Task<IEnumerable<T>> GetAllAsync();
    Task AddAsync(T entity);
    void Update(T entity);
    void Delete(T entity);
    Task SaveAsync();
}

// EfRepository.cs
public class EfRepository<T> : IRepository<T> where T : class
{
    private readonly MyDbContext _context;
    private readonly DbSet<T> _entities;

    public EfRepository(MyDbContext context)
    {
        _context = context;
        _entities = _context.Set<T>();
    }

    public async Task<T?> GetByIdAsync(int id) => await _entities.FindAsync(id);
    public async Task<IEnumerable<T>> GetAllAsync() => await _entities.ToListAsync();
    public async Task AddAsync(T entity) => await _entities.AddAsync(entity);
    public void Update(T entity) => _entities.Update(entity);
    public void Delete(T entity) => _entities.Remove(entity);
    public async Task SaveAsync() => await _context.SaveChangesAsync();
}

// In Program.cs, register generically
// builder.Services.AddScoped(typeof(IRepository<>), typeof(EfRepository<>));
```

---

Challenge 3: Action Filter for Logging

Problem: Create an action filter that logs the name of the controller and action being executed, along with the execution time. This leverages cross-cutting concerns without cluttering controller code.

Solution:

```csharp
// LogActionFilter.cs
public class LogActionFilter : IAsyncActionFilter
{
    private readonly ILogger<LogActionFilter> _logger;

    public LogActionFilter(ILogger<LogActionFilter> logger)
    {
        _logger = logger;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var controllerName = context.Controller.GetType().Name;
        var actionName = context.ActionDescriptor.RouteValues["action"];
        
        _logger.LogInformation("Executing {Controller}.{Action}", controllerName, actionName);
        
        var sw = Stopwatch.StartNew();
        var resultContext = await next(); // execute the action
        sw.Stop();
        
        _logger.LogInformation("Executed {Controller}.{Action} in {ElapsedMilliseconds}ms",
            controllerName, actionName, sw.ElapsedMilliseconds);
    }
}

// Register globally in Program.cs
// builder.Services.AddControllers(options => options.Filters.Add<LogActionFilter>());
```

---

Challenge 4: Options Pattern with Validation

Problem: Create a strongly-typed configuration class SmtpSettings for email settings, bind it from configuration, and validate that the Host and Port are provided on startup. This leverages type-safe configuration and early validation.

Solution:

```csharp
// SmtpSettings.cs
public class SmtpSettings
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

// In Program.cs
// Bind and validate
builder.Services.AddOptions<SmtpSettings>()
    .Bind(builder.Configuration.GetSection("SmtpSettings"))
    .ValidateDataAnnotations() // Requires [Required] on properties in SmtpSettings
    .ValidateOnStart(); // .NET 7+ feature for early validation

// Or use a custom validator for more complex rules
builder.Services.AddOptions<SmtpSettings>()
    .Bind(builder.Configuration.GetSection("SmtpSettings"))
    .Validate(settings => 
    {
        return !string.IsNullOrEmpty(settings.Host) && settings.Port > 0;
    }, "SmtpSettings: Host must be provided and Port must be greater than 0.")
    .ValidateOnStart();
```

---

Challenge 5: Custom ProblemDetails Factory

Problem: Customize the default ProblemDetails response for automatic HTTP 400 (Bad Request) responses from ModelState validation to include a custom error code field.

Solution:

```csharp
// CustomProblemDetailsFactory.cs
public class CustomProblemDetailsFactory : ProblemDetailsFactory
{
    public override ProblemDetails CreateProblemDetails(HttpContext httpContext, int? statusCode = null, string? title = null, string? type = null, string? detail = null, string? instance = null)
    {
        var problemDetails = new ProblemDetails
        {
            Status = statusCode,
            Title = title,
            Type = type,
            Detail = detail,
            Instance = instance,
        };

        // Add a custom extension
        problemDetails.Extensions["code"] = "VALIDATION_ERROR";

        return problemDetails;
    }

    // Implement the other required method similarly
    public override ValidationProblemDetails CreateValidationProblemDetails(HttpContext httpContext, ModelStateDictionary modelStateDictionary, int? statusCode = null, string? title = null, string? type = null, string? detail = null, string? instance = null)
    {
        var validationProblemDetails = new ValidationProblemDetails(modelStateDictionary)
        {
            Status = statusCode,
            Title = title,
            Type = type,
            Detail = detail,
            Instance = instance,
        };

        validationProblemDetails.Extensions["code"] = "VALIDATION_ERROR";

        return validationProblemDetails;
    }
}

// In Program.cs, replace the default factory
// builder.Services.AddSingleton<ProblemDetailsFactory, CustomProblemDetailsFactory>();
```

---

Challenge 6: Health Checks with Custom Dependencies

Problem: Create a custom health check that pings your application's database to verify connectivity. Register it with the standard Health Checks API.

Solution:

```csharp
// DatabaseHealthCheck.cs
public class DatabaseHealthCheck : IHealthCheck
{
    private readonly MyDbContext _context;
    public DatabaseHealthCheck(MyDbContext context)
    {
        _context = context;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            // Simple query to test connectivity
            await _context.Database.CanConnectAsync(cancellationToken);
            return HealthCheckResult.Healthy("Database connection is OK.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database connection failed.", ex);
        }
    }
}

// In Program.cs
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("Database");
```

---

Challenge 7: Source Generator for API Endpoints

Problem: Use a source generator (like Microsoft.AspNetCore.Http.Abstractions) to automatically map a minimal API endpoint. (Note: Full source generators are complex; this demonstrates the concept with a simpler example).

Conceptual Solution: While building a full source generator is advanced,you can leverage the MapGroup and helper methods for similar reusability.

```csharp
// ApiRouteBuilder.cs (Leveraging extension methods)
public static class ApiRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapWeatherApi(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/weather")
                       .WithTags("Weather");

        group.MapGet("/forecast", () => {
            // ... endpoint logic
        });
        
        group.MapGet("/summary", () => {
            // ... endpoint logic
        });

        return app;
    }
}

// In Program.cs
// app.MapWeatherApi();
```

---

Challenge 8: Policy-Based Authorization

Problem: Create an authorization policy named "Over18" that only allows users whose DateOfBirth claim indicates they are at least 18 years old.

Solution:

```csharp
// In Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Over18", policy =>
        policy.Requirements.Add(new MinimumAgeRequirement(18)));
});

// MinimumAgeRequirement.cs
public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    public MinimumAgeRequirement(int minimumAge) => MinimumAge = minimumAge;
}

// MinimumAgeHandler.cs
public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MinimumAgeRequirement requirement)
    {
        var dateOfBirthClaim = context.User.FindFirst(c => c.Type == ClaimTypes.DateOfBirth);
        if (dateOfBirthClaim == null)
            return Task.CompletedTask;

        if (DateTime.TryParse(dateOfBirthClaim.Value, out var dateOfBirth))
        {
            var age = DateTime.Today.Year - dateOfBirth.Year;
            if (age >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }
        }
        return Task.CompletedTask;
    }
}

// Register the handler
// builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();

// Use on a controller action: [Authorize(Policy = "Over18")]
```

---

Challenge 9: Custom IModelBinder for a Complex Type

Problem: Create a custom model binder that can parse a query string like "10,20,30,40" into a int[] array for an action parameter.

Solution:

```csharp
// IntArrayModelBinder.cs
public class IntArrayModelBinder : IModelBinder
{
    public Task BindModelAsync(ModelBindingContext bindingContext)
    {
        var valueProviderResult = bindingContext.ValueProvider.GetValue(bindingContext.ModelName);
        if (valueProviderResult == ValueProviderResult.None)
            return Task.CompletedTask;

        var stringValue = valueProviderResult.FirstValue;
        if (string.IsNullOrEmpty(stringValue))
            return Task.CompletedTask;

        try
        {
            var intArray = stringValue.Split(',', StringSplitOptions.RemoveEmptyEntries)
                                      .Select(int.Parse)
                                      .ToArray();
            bindingContext.Result = ModelBindingResult.Success(intArray);
        }
        catch (Exception)
        {
            bindingContext.ModelState.TryAddModelError(bindingContext.ModelName, "Invalid integer list format. Use '1,2,3,4'.");
        }

        return Task.CompletedTask;
    }
}

// IntArrayModelBinderProvider.cs
public class IntArrayModelBinderProvider : IModelBinderProvider
{
    public IModelBinder? GetBinder(ModelBinderProviderContext context)
    {
        if (context.Metadata.ModelType == typeof(int[]))
            return new IntArrayModelBinder();

        return null;
    }
}

// In Program.cs, add the provider to the MVC options
// builder.Services.AddControllers(options => {
//    options.ModelBinderProviders.Insert(0, new IntArrayModelBinderProvider());
// });

// Use in controller: public IActionResult GetValues([ModelBinder(Name = "ids")] int[] ids) { ... }
// Can be called with: /api/values?ids=10,20,30
```

---

Challenge 10: Factory-Based Middleware

Problem: Create middleware that can be instantiated using a factory (implementing IMiddlewareFactory and IMiddleware) for better dependency injection support.

Solution:

```csharp
// Factory-Activated Middleware must implement IMiddleware
public class FactoryActivatedMiddleware : IMiddleware
{
    private readonly ILogger<FactoryActivatedMiddleware> _logger;

    // Dependencies are injected via constructor
    public FactoryActivatedMiddleware(ILogger<FactoryActivatedMiddleware> logger)
    {
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        _logger.LogInformation("Factory Middleware: Before next");
        await next(context);
        _logger.LogInformation("Factory Middleware: After next");
    }
}

// In Program.cs
// 1. Register the middleware with the DI container
builder.Services.AddTransient<FactoryActivatedMiddleware>();

// 2. Use it with the factory method
// app.UseMiddleware<FactoryActivatedMiddleware>();
```

---

Challenge 11: Response Caching with a Custom Key

Problem: Implement a custom ResponseCacheAttribute that creates a cache key based on the user's ID (from claims) in addition to the request path, so cached responses are user-specific.

Solution:

```csharp
// UserSpecificResponseCacheAttribute.cs
public class UserSpecificResponseCacheAttribute : Attribute, IAsyncActionFilter
{
    private readonly int _duration;

    public UserSpecificResponseCacheAttribute(int duration)
    {
        _duration = duration;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var cacheService = context.HttpContext.RequestServices.GetRequiredService<IMemoryCache>();
        var userId = context.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "Anonymous";

        // Build a unique key for this user and path
        var path = context.HttpContext.Request.Path;
        var key = $"cache_{userId}_{path}";

        if (cacheService.TryGetValue(key, out object cachedValue))
        {
            context.Result = new OkObjectResult(cachedValue);
            return;
        }

        var executedContext = await next(); // let the action execute
        if (executedContext.Result is OkObjectResult okResult)
        {
            // Cache the result
            cacheService.Set(key, okResult.Value, TimeSpan.FromSeconds(_duration));
        }
    }
}

// Use on action: [UserSpecificResponseCache(30)]
```

---

Challenge 12: FluentValidation Integration

Problem: Integrate the FluentValidation library into your ASP.NET Core project to leverage its powerful validation syntax and automatically validate models before they reach your actions.

Solution:

```csharp
// 1. Install-Package FluentValidation.AspNetCore

// 2. Create a validator
// CreateProductDtoValidator.cs
public class CreateProductDtoValidator : AbstractValidator<CreateProductDto>
{
    public CreateProductDtoValidator()
    {
        RuleFor(x => x.Name).NotEmpty().Length(2, 100);
        RuleFor(x => x.Price).GreaterThan(0);
        RuleFor(x => x.Category).IsInEnum();
    }
}

// 3. In Program.cs
// builder.Services.AddControllers().AddFluentValidation(fv => {
//     fv.RegisterValidatorsFromAssemblyContaining<CreateProductDtoValidator>();
//     // Optionally disable built-in DataAnnotations validation
//     fv.DisableDataAnnotationsValidation = true;
// });

// The framework will automatically run validation before the action executes.
// ModelState.IsValid will reflect the results.
```

---

Challenge 13: Custom OutputFormatter for CSV

Problem: Create a custom OutputFormatter that can serialize a list of objects into CSV format when the client requests text/csv.

Solution:

```csharp
// CsvOutputFormatter.cs
public class CsvOutputFormatter : TextOutputFormatter
{
    public CsvOutputFormatter()
    {
        SupportedMediaTypes.Add("text/csv");
        SupportedEncodings.Add(Encoding.UTF8);
        SupportedEncodings.Add(Encoding.Unicode);
    }

    protected override bool CanWriteType(Type? type)
    {
        // Check if the type is a collection
        if (type == null) return false;
        return typeof(System.Collections.IEnumerable).IsAssignableFrom(type);
    }

    public override async Task WriteResponseBodyAsync(OutputFormatterWriteContext context, Encoding selectedEncoding)
    {
        var response = context.HttpContext.Response;
        var buffer = new StringBuilder();

        if (context.Object is IEnumerable collection)
        {
            foreach (var item in collection)
            {
                var properties = item.GetType().GetProperties();
                if (buffer.Length == 0)
                {
                    // Write header
                    buffer.AppendLine(string.Join(",", properties.Select(p => p.Name)));
                }
                // Write row
                buffer.AppendLine(string.Join(",", properties.Select(p => p.GetValue(item)?.ToString() ?? "")));
            }
        }

        await response.WriteAsync(buffer.ToString(), selectedEncoding);
    }
}

// In Program.cs
// builder.Services.AddControllers(options => {
//     options.OutputFormatters.Add(new CsvOutputFormatter());
// });
```

---

Challenge 14: Decorator Pattern with DI

Problem: Use the Decorator pattern to add caching to an existing service (e.g., IWeatherService) without modifying its original implementation. Register both the original and decorated service with the DI container.

Solution:

```csharp
// Original Service
public interface IWeatherService { Task<WeatherForecast> GetForecastAsync(string city); }
public class WeatherService : IWeatherService { /*... calls an API ...*/ }

// Decorator
public class CachedWeatherService : IWeatherService
{
    private readonly IWeatherService _innerService;
    private readonly IMemoryCache _cache;

    public CachedWeatherService(IWeatherService innerService, IMemoryCache cache)
    {
        _innerService = innerService;
        _cache = cache;
    }

    public async Task<WeatherForecast> GetForecastAsync(string city)
    {
        var cacheKey = $"weather_{city}";
        if (!_cache.TryGetValue(cacheKey, out WeatherForecast forecast))
        {
            forecast = await _innerService.GetForecastAsync(city);
            _cache.Set(cacheKey, forecast, TimeSpan.FromMinutes(5));
        }
        return forecast;
    }
}

// In Program.cs, register with decorator
// First, register the original service
builder.Services.AddScoped<WeatherService>();
// Then, register the decorator, injecting the original service
builder.Services.Decorate<IWeatherService, CachedWeatherService>();
// Note: .Decorate() is not built-in. Use the Scrutor library:
// Install-Package Scrutor
// builder.Services.AddScoped<IWeatherService, WeatherService>();
// builder.Services.Decorate<IWeatherService, CachedWeatherService>();
```

---

Challenge 15: Dynamic Feature Flags with Endpoint Metadata

Problem: Create a feature flag system that can enable or disable entire MVC controllers or minimal API endpoints based on a configuration setting, without deploying new code.

Solution:

```csharp
// FeatureGateAttribute.cs
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class FeatureGateAttribute : Attribute, IAsyncActionFilter
{
    public string FeatureName { get; }

    public FeatureGateAttribute(string featureName)
    {
        FeatureName = featureName;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var featureManager = context.HttpContext.RequestServices.GetRequiredService<IFeatureManager>();

        if (!await featureManager.IsEnabledAsync(FeatureName))
        {
            context.Result = new NotFoundResult(); // or a specific message
            return;
        }

        await next();
    }
}

// Use on a controller or action: [FeatureGate("BetaFeature")]

// In Program.cs, add feature management
// Install-Package Microsoft.FeatureManagement.AspNetCore
// builder.Services.AddFeatureManagement();

// In appsettings.json
// "FeatureManagement": { "BetaFeature": false }
```

Let me know if you'd like deeper explanations on any of these challenges!