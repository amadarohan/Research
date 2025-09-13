# Understanding Rate Limiting in APIs with ASP.NET Core

Rate limiting is a crucial technique for controlling how often clients can make requests to your API. It helps prevent abuse, protects resources, and ensures fair usage among all consumers.

## What is Rate Limiting?

Rate limiting restricts the number of API calls a client can make within a specific time window. For example:
- 100 requests per minute
- 1000 requests per hour
- 10 requests per second

## Implementing Rate Limiting in ASP.NET Core Minimal API

Here's a complete example of implementing rate limiting in ASP.NET Core 7+:

### 1. First, install the required NuGet package:
```bash
dotnet add package Microsoft.AspNetCore.RateLimiting
```

### 2. Basic Rate Limiting Setup

```csharp
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRateLimiter(rateLimiterOptions =>
{
    rateLimiterOptions.AddFixedWindowLimiter("fixed", options =>
    {
        options.PermitLimit = 10; // Maximum number of permits
        options.Window = TimeSpan.FromSeconds(10); // Time window
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        options.QueueLimit = 5; // Maximum number of queued requests
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseRateLimiter();

app.MapGet("/", () => "Hello World!")
    .RequireRateLimiting("fixed"); // Apply the rate limiter

app.Run();
```

### 3. More Advanced Example with Multiple Policies

```csharp
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRateLimiter(rateLimiterOptions =>
{
    // Fixed window limiter - strict limit
    rateLimiterOptions.AddFixedWindowLimiter("strict", options =>
    {
        options.PermitLimit = 5;
        options.Window = TimeSpan.FromSeconds(10);
    });
    
    // Sliding window limiter - more flexible
    rateLimiterOptions.AddSlidingWindowLimiter("flexible", options =>
    {
        options.PermitLimit = 20;
        options.Window = TimeSpan.FromSeconds(30);
        options.SegmentsPerWindow = 3; // Divides window into segments
    });
    
    // Token bucket limiter - for burst scenarios
    rateLimiterOptions.AddTokenBucketLimiter("burst", options =>
    {
        options.TokenLimit = 10;
        options.TokensPerPeriod = 2;
        options.ReplenishmentPeriod = TimeSpan.FromSeconds(5);
    });
    
    // Concurrency limiter - limits parallel requests
    rateLimiterOptions.AddConcurrencyLimiter("concurrency", options =>
    {
        options.PermitLimit = 5;
        options.QueueLimit = 2;
    });
    
    // Global limiter - applies to all endpoints
    rateLimiterOptions.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        // You can create different limits based on context (IP, user, etc.)
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Request.Headers.Host.ToString(),
            factory: partition => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1)
            });
    });
    
    // Configure rejection response
    rateLimiterOptions.OnRejected = (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        return new ValueTask();
    };
});

var app = builder.Build();

app.UseRateLimiter();

// Apply different limiters to different endpoints
app.MapGet("/public", () => "Public endpoint")
    .RequireRateLimiting("flexible");

app.MapGet("/strict", () => "Strictly limited endpoint")
    .RequireRateLimiting("strict");

app.MapGet("/burst", () => "Burst-friendly endpoint")
    .RequireRateLimiting("burst");

app.MapGet("/concurrent", async () => 
{
    await Task.Delay(1000); // Simulate work
    return "Concurrency limited endpoint";
}).RequireRateLimiting("concurrency");

app.Run();
```

## Key Rate Limiting Algorithms

1. **Fixed Window**: Counts requests in fixed time windows (e.g., per minute)
2. **Sliding Window**: Similar to fixed but divides window into segments for smoother limits
3. **Token Bucket**: Allows bursts up to a maximum capacity, then steady rate
4. **Concurrency**: Limits number of simultaneous requests

## Best Practices

1. **Choose appropriate limits**: Consider your API's capabilities and expected usage
2. **Use different limits for different endpoints**: Critical endpoints might need stricter limits
3. **Provide headers in responses**:
   - `X-RateLimit-Limit`: Maximum requests allowed
   - `X-RateLimit-Remaining`: Remaining requests in window
   - `X-RateLimit-Reset`: When limits reset
4. **Return proper status code**: 429 (Too Many Requests) when limit is exceeded
5. **Consider client identification**: Limit by API key, IP, or user identity

## Customizing Rate Limiting

You can create custom rate limiting logic by implementing `IRateLimiterPolicy`:

```csharp
public class CustomRateLimiterPolicy : IRateLimiterPolicy<string>
{
    public RateLimitPartition<string> GetPartition(HttpContext httpContext)
    {
        // Implement custom logic to determine partition key and limits
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User.Identity?.Name ?? httpContext.Request.Headers["X-Client-Id"],
            factory: partition => new FixedWindowRateLimiterOptions
            {
                PermitLimit = partition == "premium" ? 100 : 10,
                Window = TimeSpan.FromMinutes(1)
            });
    }
}

// Register it:
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy<string, CustomRateLimiterPolicy>("custom");
});
```

This gives you complete control over how rate limits are applied based on your business logic.
