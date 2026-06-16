Here's a practical .NET Console App demonstrating leverageability (the ability to extend, override, or swap behavior without modifying core code) using Dependency Injection, interfaces, and configuration.

---

The Sample: A Data Processing App

We'll build a console app that processes orders from different sources (CSV, JSON, API). You can easily leverage (extend/swap) the data source, logger, and output formatter—all without changing the core logic.

---

1. Project Structure

```
OrderProcessor/
├── Program.cs              (entry point)
├── Core/
│   ├── IOrderSource.cs
│   ├── IOrderFormatter.cs
│   ├── ILogger.cs
│   └── Order.cs
├── Implementations/
│   ├── CsvOrderSource.cs
│   ├── JsonOrderSource.cs
│   ├── ConsoleLogger.cs
│   └── TableFormatter.cs
├── appsettings.json         (configuration)
└── OrderProcessor.csproj
```

---

2. Core Interfaces (Extensible Contracts)

```csharp
// Core/IOrderSource.cs
public interface IOrderSource
{
    IEnumerable<Order> GetOrders();
}

// Core/IOrderFormatter.cs
public interface IOrderFormatter
{
    string Format(IEnumerable<Order> orders);
}

// Core/ILogger.cs
public interface ILogger
{
    void Log(string message);
}

// Core/Order.cs
public class Order
{
    public int Id { get; set; }
    public string Customer { get; set; }
    public decimal Amount { get; set; }
    public DateTime Date { get; set; }
}
```

---

3. Implementations (Swappable)

```csharp
// Implementations/CsvOrderSource.cs
public class CsvOrderSource : IOrderSource
{
    private readonly string _filePath;
    public CsvOrderSource(string filePath) => _filePath = filePath;

    public IEnumerable<Order> GetOrders()
    {
        // Simulate CSV reading
        return new[]
        {
            new Order { Id = 1, Customer = "Acme", Amount = 100m, Date = DateTime.Today },
            new Order { Id = 2, Customer = "Beta", Amount = 250m, Date = DateTime.Today }
        };
    }
}

// Implementations/JsonOrderSource.cs
public class JsonOrderSource : IOrderSource
{
    private readonly string _json;
    public JsonOrderSource(string json) => _json = json;

    public IEnumerable<Order> GetOrders()
    {
        // Simulate JSON parsing
        return new[]
        {
            new Order { Id = 101, Customer = "Gamma", Amount = 75m, Date = DateTime.Today }
        };
    }
}

// Implementations/ConsoleLogger.cs
public class ConsoleLogger : ILogger
{
    public void Log(string message) => Console.WriteLine($"[LOG] {message}");
}

// Implementations/TableFormatter.cs
public class TableFormatter : IOrderFormatter
{
    public string Format(IEnumerable<Order> orders)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("ID  | Customer | Amount | Date");
        sb.AppendLine("----|----------|--------|----------");
        foreach (var o in orders)
            sb.AppendLine($"{o.Id,-3} | {o.Customer,-8} | {o.Amount,6:C} | {o.Date:d}");
        return sb.ToString();
    }
}
```

---

4. Core Processor (Closed for Modification)

```csharp
// Core/OrderProcessor.cs
public class OrderProcessor
{
    private readonly IOrderSource _source;
    private readonly IOrderFormatter _formatter;
    private readonly ILogger _logger;

    public OrderProcessor(IOrderSource source, IOrderFormatter formatter, ILogger logger)
    {
        _source = source;
        _formatter = formatter;
        _logger = logger;
    }

    public void Process()
    {
        _logger.Log("Fetching orders...");
        var orders = _source.GetOrders();

        _logger.Log($"Found {orders.Count()} orders.");
        var output = _formatter.Format(orders);
        Console.WriteLine(output);

        _logger.Log("Processing complete.");
    }
}
```

---

5. Dependency Injection Setup (Microsoft.Extensions.DependencyInjection)

```csharp
// Program.cs
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;

class Program
{
    static void Main(string[] args)
    {
        var host = Host.CreateDefaultBuilder(args)
            .ConfigureServices((context, services) =>
            {
                // Choose implementation based on configuration
                var sourceType = context.Configuration["OrderSource:Type"];

                if (sourceType == "Csv")
                {
                    var path = context.Configuration["OrderSource:CsvPath"];
                    services.AddSingleton<IOrderSource>(new CsvOrderSource(path));
                }
                else if (sourceType == "Json")
                {
                    var json = context.Configuration["OrderSource:JsonData"];
                    services.AddSingleton<IOrderSource>(new JsonOrderSource(json));
                }
                else
                {
                    // Default fallback
                    services.AddSingleton<IOrderSource, CsvOrderSource>();
                }

                // These can also be swapped via config
                services.AddSingleton<IOrderFormatter, TableFormatter>();
                services.AddSingleton<ILogger, ConsoleLogger>();

                services.AddSingleton<OrderProcessor>();
            })
            .Build();

        var processor = host.Services.GetRequiredService<OrderProcessor>();
        processor.Process();
    }
}
```

---

6. Configuration (appsettings.json)

```json
{
  "OrderSource": {
    "Type": "Json",  // Change to "Csv" to switch data source
    "JsonData": "[{\"Id\":999,\"Customer\":\"Test\",\"Amount\":42.0,\"Date\":\"2026-06-16\"}]"
  }
}
```

---

Leverageability in Action

What you can change How No code change needed?
Data source (CSV ↔ JSON) Change appsettings.json Type value ✅ Yes
Logger (Console → File/DB) Swap ILogger registration ✅ Yes (if using DI)
Output format (Table → XML/CSV) Swap IOrderFormatter registration ✅ Yes
Processing logic Create new class implementing interfaces ✅ Yes (Open/Closed)
Order data model Extend Order without breaking existing consumers ✅ Yes (via inheritance)

---

Key Leverageability Principles Demonstrated

1. Dependency Inversion — Core depends on abstractions, not concretions.
2. Open/Closed Principle — New features (new sources, formatters) don't modify OrderProcessor.
3. Configuration-driven — Behavior changes via appsettings.json or environment variables.
4. Testability — You can inject mocks for unit testing.
5. Runtime Swapping — DI container resolves implementations at startup based on config.

---

Bonus: Custom Extension (Add a New Source)

To add an XML source:

```csharp
public class XmlOrderSource : IOrderSource { /* implement */ }
```

Then in ConfigureServices:

```csharp
case "Xml":
    services.AddSingleton<IOrderSource, XmlOrderSource>();
    break;
```

Zero changes to OrderProcessor or existing sources. That's leverageability!

---

Let me know if you want a full runnable GitHub repo snippet or a more advanced example with IHostedService or MediatR!
