# Building a Mini API in ASP.NET Core with Environment Configuration

In this guide, I'll walk you through creating a minimal API in ASP.NET Core with configuration for different environments (Development, Staging, Production).

## Step 1: Create a new ASP.NET Core project

First, create a new project using the .NET CLI:

```bash
dotnet new webapi -n MiniApiDemo
cd MiniApiDemo
```

## Step 2: Understand the default environment setup

ASP.NET Core uses the `ASPNETCORE_ENVIRONMENT` environment variable to determine the current environment. Common values are:
- `Development`
- `Staging`
- `Production`

## Step 3: Add environment-specific appsettings files

The project already comes with:
- `appsettings.json` - Base configuration
- `appsettings.Development.json` - Development-specific configuration

Let's add more:

```bash
touch appsettings.Staging.json
touch appsettings.Production.json
```

## Step 4: Configure environment-specific settings

Edit each file with appropriate settings:

**appsettings.Development.json**
```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "System": "Information",
      "Microsoft": "Information"
    }
  },
  "ApiSettings": {
    "WelcomeMessage": "Hello from Development!",
    "UseMockData": true
  }
}
```

**appsettings.Staging.json**
```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "System": "Warning",
      "Microsoft": "Warning"
    }
  },
  "ApiSettings": {
    "WelcomeMessage": "Hello from Staging!",
    "UseMockData": false
  }
}
```

**appsettings.Production.json**
```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Warning",
      "System": "Warning",
      "Microsoft": "Warning"
    }
  },
  "ApiSettings": {
    "WelcomeMessage": "Hello from Production!",
    "UseMockData": false
  }
}
```

## Step 5: Create a configuration model

Add a new class `ApiSettings.cs`:

```csharp
namespace MiniApiDemo;

public class ApiSettings
{
    public string WelcomeMessage { get; set; } = string.Empty;
    public bool UseMockData { get; set; }
}
```

## Step 6: Modify Program.cs to use configuration

Update your `Program.cs`:

```csharp
using MiniApiDemo;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure ApiSettings from configuration
builder.Services.Configure<ApiSettings>(builder.Configuration.GetSection("ApiSettings"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Minimal API endpoint that uses environment-specific configuration
app.MapGet("/welcome", (IConfiguration config, IOptions<ApiSettings> apiSettings) =>
{
    var environment = app.Environment.EnvironmentName;
    return Results.Ok(new
    {
        Message = apiSettings.Value.WelcomeMessage,
        Environment = environment,
        UseMockData = apiSettings.Value.UseMockData,
        CurrentTime = config.GetValue<string>("CurrentTime:Formatted")
    });
});

// Another endpoint that shows different behavior per environment
app.MapGet("/environment-check", () =>
{
    if (app.Environment.IsDevelopment())
    {
        return Results.Ok("Running in Development - Debug tools enabled!");
    }
    else if (app.Environment.IsStaging())
    {
        return Results.Ok("Running in Staging - Almost production ready!");
    }
    else if (app.Environment.IsProduction())
    {
        return Results.Ok("Running in Production - Handle with care!");
    }
    
    return Results.Ok("Running in unknown environment");
});

app.Run();
```

## Step 7: Run the application in different environments

You can set the environment in several ways:

### Option 1: Launch profiles (launchSettings.json)
The `Properties/launchSettings.json` file already contains profiles. You can modify or add new ones:

```json
{
  "profiles": {
    "Development": {
      "commandName": "Project",
      "dotnetRunMessages": true,
      "launchBrowser": true,
      "applicationUrl": "https://localhost:5001;http://localhost:5000",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    },
    "Staging": {
      "commandName": "Project",
      "dotnetRunMessages": true,
      "launchBrowser": true,
      "applicationUrl": "https://localhost:5001;http://localhost:5000",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Staging"
      }
    },
    "Production": {
      "commandName": "Project",
      "dotnetRunMessages": true,
      "launchBrowser": true,
      "applicationUrl": "https://localhost:5001;http://localhost:5000",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Production"
      }
    }
  }
}
```

### Option 2: Command line
Run with environment variable:

```bash
# Windows
set ASPNETCORE_ENVIRONMENT=Staging
dotnet run

# Linux/macOS
export ASPNETCORE_ENVIRONMENT=Staging
dotnet run
```

### Option 3: Docker
In your Dockerfile, set the environment variable:

```dockerfile
ENV ASPNETCORE_ENVIRONMENT=Production
```

## Step 8: Test your API

1. Run in Development environment and visit:
   - `https://localhost:5001/welcome`
   - `https://localhost:5001/environment-check`

2. Switch to Staging or Production and see the different responses.

## Additional Tips

1. **Environment-based startup code**: You can conditionally add services based on environment:

```csharp
if (app.Environment.IsDevelopment())
{
    builder.Services.AddSingleton<IDataService, MockDataService>();
}
else
{
    builder.Services.AddSingleton<IDataService, RealDataService>();
}
```

2. **Environment tags in views**: If you're using Razor views, you can use:
```html
<environment include="Development">
    <div class="dev-warning">Development Mode</div>
</environment>
```

3. **Secret Manager for Development**: Use the secret manager for sensitive data in development:
```bash
dotnet user-secrets set "DbPassword" "dev_password"
```

This gives you a solid foundation for building environment-aware ASP.NET Core APIs. The configuration system is very flexible and can be extended with additional configuration providers (Azure Key Vault, environment variables, etc.).
