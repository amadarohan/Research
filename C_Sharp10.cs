Of course. This is an excellent way to solidify your mastery of the concepts in "C# 10 in a Nutshell." I have created 21 challenges, one for each chapter you provided, designed to test and deepen your understanding from intermediate to senior level.

The challenges progress from core language features to advanced concurrency and performance patterns. Each challenge includes a clear problem statement and a solution implemented in a modern ASP.NET Core Web API project structure.

---

### **Chapter 1: Introducing C# and .NET**
**Challenge:** Create a simple ASP.NET Core Web API that demonstrates the use of **file-scoped namespaces**, **global using directives** (via `ImplicitUsings`), and a **top-level program**. The API should have a single endpoint that returns the current time and the .NET runtime version the app is using.

**Solution:**
1. Create a new project: `dotnet new webapi -n Chapter1Challenge`
2. `Program.cs` (Top-level statements):
```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
var app = builder.Build();
app.MapControllers();
app.Run();
```
3. `Controllers/TimeController.cs` (File-scoped namespace):
```csharp
namespace Chapter1Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class TimeController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        // Using globally imported System and System.Runtime.InteropServices
        var info = new {
            Time = DateTime.UtcNow,
            Runtime = RuntimeInformation.FrameworkDescription
        };
        return Ok(info);
    }
}
```
4. The `ImplicitUsings` are enabled by default in the `.csproj` file for .NET 6+.

---

### **Chapter 2: C# Language Basics**
**Challenge:** Create an API endpoint that demonstrates the difference between passing a **value type** (`int`), a **reference type** (`StringBuilder`), and using the `ref`, `out`, and `in` modifiers. The endpoint should call a service method that modifies these parameters and return the results.

**Solution:**
`Services/ParameterService.cs`:
```csharp
namespace Chapter2Challenge.Services;

public class ParameterService
{
    public void Demonstrate(int valueType, StringBuilder referenceType, ref int refType, out int outType, in DateTime inType)
    {
        valueType = 100; // Modifies the copy
        referenceType.Append(" Modified"); // Modifies the shared object
        refType *= 2; // Modifies the original variable
        outType = 999; // Required to assign the out parameter
        // inType = DateTime.Now; // ERROR: Cannot assign to a read-only variable
        _ = inType.Day; // Can only read it
    }
}
```
`Controllers/ParameterDemoController.cs`:
```csharp
namespace Chapter2Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class ParameterDemoController : ControllerBase
{
    private readonly ParameterService _service;

    public ParameterDemoController(ParameterService service) => _service = service;

    [HttpGet]
    public IActionResult Get()
    {
        int val = 10;
        var sb = new StringBuilder("Initial");
        int refArg = 10;
        int outArg; // unassigned
        var now = DateTime.Now;

        _service.Demonstrate(val, sb, ref refArg, out outArg, in now);

        return Ok(new {
            ValueType = val, // Still 10
            ReferenceType = sb.ToString(), // "Initial Modified"
            RefType = refArg, // 20
            OutType = outArg, // 999
            InType = now // Unchanged
        });
    }
}
```
Don't forget to register `ParameterService` in `Program.cs`: `builder.Services.AddScoped<ParameterService>();`.

---

### **Chapter 3: Creating Types in C#**
**Challenge:** Model a simple domain with a `readonly struct` for an immutable `Point` and a `class` for a `Person` using `init`-only properties and a `required` modifier (C# 11). Create an endpoint that returns instances of these types.

**Solution:**
`Models/Point.cs`:
```csharp
namespace Chapter3Challenge.Models;

public readonly struct Point
{
    public int X { get; }
    public int Y { get; }
    public Point(int x, int y) => (X, Y) = (x, y);
    // With C# 10, we can use a more concise constructor
    // public Point(int X, int Y) => (this.X, this.Y) = (X, Y);
}
```
`Models/Person.cs`:
```csharp
namespace Chapter3Challenge.Models;

public class Person
{
    public required string FirstName { get; init; } // C# 11 'required'
    public required string LastName { get; init; }
    public int? Age { get; init; }
}
```
`Controllers/TypeDemoController.cs`:
```csharp
namespace Chapter3Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class TypeDemoController : ControllerBase
{
    [HttpGet("point")]
    public Point GetPoint() => new Point(5, 10); // Value type, copied

    [HttpGet("person")]
    public Person GetPerson() => new Person { FirstName = "John", LastName = "Doe" }; // init-only properties
}
```

---

### **Chapter 4: Advanced C#**
**Challenge:** Create an endpoint that demonstrates the classic **closure pitfall with a `for` loop** and then shows the correct fix. The endpoint should return two lists of actions: one with the buggy behavior and one with the correct behavior.

**Solution:**
`Controllers/ClosureController.cs`:
```csharp
namespace Chapter4Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class ClosureController : ControllerBase
{
    [HttpGet("pitfall")]
    public IActionResult DemonstratePitfall()
    {
        List<Action> buggyActions = new();
        List<Action> correctActions = new();

        // The Pitfall: All actions capture the same variable 'i'
        for (int i = 0; i < 3; i++)
        {
            buggyActions.Add(() => Console.Write(i)); // Will all write '3'
        }

        // The Fix: Capture a new variable scoped to the iteration
        for (int i = 0; i < 3; i++)
        {
            int loopScopedI = i; // New variable per iteration
            correctActions.Add(() => Console.Write(loopScopedI)); // Will write 0, 1, 2
        }

        // Execute and capture output
        var buggyOutput = new StringWriter();
        Console.SetOut(buggyOutput);
        foreach (var a in buggyActions) a();
        var buggyResult = buggyOutput.ToString();

        var correctOutput = new StringWriter();
        Console.SetOut(correctOutput);
        foreach (var a in correctActions) a();
        var correctResult = correctOutput.ToString();

        // Restore standard output
        var standardOutput = new StreamWriter(Console.OpenStandardOutput());
        Console.SetOut(standardOutput);

        return Ok(new { BuggyResult = buggyResult, CorrectResult = correctResult });
    }
}
```

---

### **Chapter 5: .NET Overview**
**Challenge:** Create a **multi-targeted class library** (`netstandard2.0` and `net6.0`) that provides a method returning the target framework it was compiled for. Create a Web API that references this library and calls the method, displaying the result.

**Solution:**
1. `dotnet new classlib -n MultiTargetLib -f netstandard2.0`
2. Edit `MultiTargetLib.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>netstandard2.0;net6.0</TargetFrameworks>
  </PropertyGroup>
</Project>
```
3. `MultiTargetLib/PlatformInfoService.cs`:
```csharp
namespace MultiTargetLib;

public class PlatformInfoService
{
    public string GetPlatformInfo()
    {
#if NETSTANDARD2_0
        return "Built for .NET Standard 2.0";
#elif NET6_0
        return "Built for .NET 6";
#else
        return "Built for an unknown target";
#endif
    }
}
```
4. In your main Web API project, add a project reference to `MultiTargetLib`.
5. `Controllers/PlatformController.cs`:
```csharp
namespace Chapter5Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class PlatformController : ControllerBase
{
    private readonly PlatformInfoService _infoService;

    public PlatformController(PlatformInfoService infoService) => _infoService = infoService;

    [HttpGet]
    public string Get() => _infoService.GetPlatformInfo();
}
```
Register the service: `builder.Services.AddScoped<PlatformInfoService>();`.

---

### **Chapter 6: .NET Fundamentals**
**Challenge:** Create an endpoint that hashes a provided string using **SHA256** and returns the hash. Demonstrate proper **culture-invariant** string comparison by checking if a header value matches a secret key.

**Solution:**
`Controllers/SecurityController.cs`:
```csharp
namespace Chapter6Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class SecurityController : ControllerBase
{
    private const string SecretApiKey = "SuperSecretKey123!"; // In real life, use config/secrets

    [HttpGet("hash/{input}")]
    public async Task<IActionResult> HashInput(string input)
    {
        // Hashing for data integrity
        byte[] bytes = Encoding.UTF8.GetBytes(input);
        byte[] hash = await SHA256.HashDataAsync(new MemoryStream(bytes));
        string hashString = Convert.ToHexString(hash); // .NET 5+
        return Ok(new { Input = input, Hash = hashString });
    }

    [HttpGet("validate")]
    public IActionResult ValidateKey()
    {
        // Culture-aware comparison could be problematic for keys. Use Ordinal.
        if (Request.Headers.TryGetValue("X-API-Key", out var headerKey))
        {
            // Use case-sensitive, culture-invariant comparison for security
            bool isValid = string.Equals(headerKey, SecretApiKey, StringComparison.Ordinal);
            return Ok(new { IsValid = isValid });
        }
        return BadRequest("Missing API Key header.");
    }
}
```

---

### **Chapter 7: Collections**
**Challenge:** Create an endpoint that demonstrates the performance difference between a `List<T>` and a `LinkedList<T>` when inserting items in the middle. The endpoint should take a number of iterations and return the time taken for each operation.

**Solution:**
`Controllers/PerformanceController.cs`:
```csharp
namespace Chapter7Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class PerformanceController : ControllerBase
{
    [HttpGet("insertion/{iterations}")]
    public IActionResult CompareInsertion(int iterations = 1000)
    {
        // Test List<T>
        var list = new List<int>();
        var listStopwatch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            list.Insert(list.Count / 2, i); // O(n) operation
        }
        listStopwatch.Stop();

        // Test LinkedList<T>
        var linkedList = new LinkedList<int>();
        var linkedListStopwatch = Stopwatch.StartNew();
        LinkedListNode<int> currentNode = null;
        for (int i = 0; i < iterations; i++)
        {
            if (currentNode == null)
            {
                currentNode = linkedList.AddFirst(i);
            }
            else
            {
                // Simulate finding the middle is still O(n), but insertion itself is O(1)
                // For a true benchmark, we'd need a different setup, but this illustrates the point.
                var middleNode = GetMiddleNode(linkedList);
                currentNode = linkedList.AddAfter(middleNode, i);
            }
        }
        linkedListStopwatch.Stop();

        return Ok(new
        {
            ListTimeMs = listStopwatch.ElapsedMilliseconds,
            LinkedListTimeMs = linkedListStopwatch.ElapsedMilliseconds,
            Message = "List insertion is O(n) per operation. LinkedList insertion is O(1) after finding the node, but finding the node is O(n). For frequent mid-list inserts, LinkedList can be better."
        });
    }

    private LinkedListNode<int> GetMiddleNode(LinkedList<int> list)
    {
        // Naive implementation to find the middle
        int count = list.Count;
        if (count == 0) return null;
        var node = list.First;
        for (int i = 0; i < count / 2; i++)
        {
            node = node.Next;
        }
        return node;
    }
}
```

---

### **Chapter 8: LINQ Queries**
**Challenge:** Create an endpoint that uses **deferred execution**. It should create a LINQ query, then modify the underlying data source *before* enumerating the query, demonstrating that the query uses the latest data. Also, show the pitfall of **multiple enumeration** of an expensive query.

**Solution:**
`Controllers/LinqDemoController.cs`:
```csharp
namespace Chapter8Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class LinqDemoController : ControllerBase
{
    [HttpGet("deferred")]
    public IActionResult DeferredExecution()
    {
        var numbers = new List<int> { 1, 2, 3, 4, 5 };

        // Define the query (deferred - not executed yet)
        var query = numbers.Where(n => n % 2 == 0).Select(n => n * 10);

        // Modify the data source
        numbers.Add(6);
        numbers.Add(7);

        // Now execute the query (it will see the modified data)
        var result = query.ToList(); // Output: [20, 40, 60]

        return Ok(new { Result = result, DataSourceAfterChange = numbers });
    }

    [HttpGet("multiple-enumeration")]
    public IActionResult MultipleEnumeration()
    {
        // Simulate an expensive operation that is part of the query
        int expensiveCalls = 0;

        var numbers = Enumerable.Range(1, 5);
        var expensiveQuery = numbers.Select(n =>
        {
            expensiveCalls++;
            Thread.Sleep(100); // Simulate expensive work
            return n * 2;
        });

        // First enumeration
        var firstPass = expensiveQuery.ToList();
        // Second enumeration - the expensive operation runs again!
        var secondPass = expensiveQuery.ToList();

        return Ok(new {
            ExpensiveCalls = expensiveCalls, // Will be 10, not 5
            FirstPass = firstPass,
            SecondPass = secondPass,
            Message = "Materialize (.ToList()) the query if you need to enumerate it multiple times to avoid this performance hit."
        });
    }
}
```

---

### **Chapter 9: LINQ Operators**
**Challenge:** Create an endpoint that uses `SelectMany` to flatten a hierarchical structure (e.g., a list of departments, each with a list of employees) into a single list of employees. Compare it with a nested `Select` which would return a hierarchical result.

**Solution:**
`Models/Department.cs` & `Models/Employee.cs`:
```csharp
namespace Chapter9Challenge.Models;

public class Department
{
    public string Name { get; set; }
    public List<Employee> Employees { get; set; } = new();
}
public class Employee
{
    public string Name { get; set; }
    public string Title { get; set; }
}
```
`Controllers/FlattenController.cs`:
```csharp
namespace Chapter9Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class FlattenController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        var departments = new List<Department>
        {
            new Department {
                Name = "Engineering",
                Employees = new() { new Employee { Name = "Alice", Title = "Dev" }, new Employee { Name = "Bob", Title = "QA" } }
            },
            new Department {
                Name = "HR",
                Employees = new() { new Employee { Name = "Charlie", Title = "Recruiter" } }
            }
        };

        // Nested Select (Hierarchical)
        var departmentsWithEmployees = departments.Select(d => new { d.Name, Employees = d.Employees });

        // Flattened with SelectMany
        var allEmployees = departments.SelectMany(d => d.Employees).ToList();

        return Ok(new {
            HierarchicalResult = departmentsWithEmployees,
            FlattenedResult = allEmployees
        });
    }
}
```

---

### **Chapter 10: LINQ to XML**
**Challenge:** Create an endpoint that uses **functional construction** to generate an RSS feed (XML) and return it with the correct `Content-Type` header.

**Solution:**
`Controllers/RssController.cs`:
```csharp
namespace Chapter10Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class RssController : ControllerBase
{
    [HttpGet]
    public IActionResult GetRssFeed()
    {
        // Create RSS feed using LINQ to XML functional construction
        XNamespace ns = "http://www.w3.org/2005/Atom";
        var rss = new XElement("rss", new XAttribute("version", "2.0"), new XAttribute(XNamespace.Xmlns + "atom", ns),
            new XElement("channel",
                new XElement("title", "My Awesome Feed"),
                new XElement("link", "https://example.com"),
                new XElement(ns + "link", new XAttribute("href", "https://example.com/rss"), new XAttribute("rel", "self"), new XAttribute("type", "application/rss+xml")),
                new XElement("description", "A sample RSS feed"),
                new XElement("item",
                    new XElement("title", "First Post"),
                    new XElement("link", "https://example.com/first-post"),
                    new XElement("description", "This is the first post."),
                    new XElement("pubDate", DateTime.UtcNow.ToString("R")) // RFC1123 format
                )
            )
        );

        // Return as XML content
        return Content(rss.ToString(), "application/rss+xml");
    }
}
```

---

### **Chapter 11: Other XML and JSON Technologies**
**Challenge:** Create an endpoint that accepts either XML or JSON input (based on the `Content-Type` header), deserializes it into the same C# model, and then returns it as JSON. Use `System.Text.Json` for JSON and `XmlSerializer` for XML.

**Solution:**
`Models/Person.cs`:
```csharp
namespace Chapter11Challenge.Models;

public class Person
{
    public string? Name { get; set; }
    public int? Age { get; set; }
}
```
`Controllers/UniversalInputController.cs`:
```csharp
namespace Chapter11Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class UniversalInputController : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Post()
    {
        Person? person = null;
        var contentType = Request.ContentType;

        if (contentType?.Contains("application/json") == true)
        {
            // Deserialize JSON using System.Text.Json
            person = await JsonSerializer.DeserializeAsync<Person>(Request.Body);
        }
        else if (contentType?.Contains("application/xml") == true || contentType?.Contains("text/xml") == true)
        {
            // Deserialize XML using XmlSerializer
            var serializer = new XmlSerializer(typeof(Person));
            person = (Person?)serializer.Deserialize(Request.Body);
        }
        else
        {
            return BadRequest("Unsupported Content-Type. Please use application/json or application/xml.");
        }

        if (person == null)
        {
            return BadRequest("Failed to deserialize the request body.");
        }

        // Always return JSON
        return Ok(person);
    }
}
```

---

### **Chapter 12: Disposal and Garbage Collection**
**Challenge:** Create a service that implements the **full dispose pattern** (with a finalizer as a backup). The service should hold a reference to a `Timer`. Create an endpoint that uses this service and demonstrates that not disposing of it properly will cause the timer to keep the object alive. Use `WeakReference` to prove the object is still alive.

**Solution:**
`Services/DisposableService.cs`:
```csharp
namespace Chapter12Challenge.Services;

public class DisposableService : IDisposable
{
    private readonly Timer _timer;
    private bool _disposed = false;
    public string Id { get; } = Guid.NewGuid().ToString();

    public DisposableService()
    {
        _timer = new Timer(OnTimerTick, null, 1000, 1000);
        Console.WriteLine($"Service {Id} created.");
    }

    private void OnTimerTick(object? state) => Console.WriteLine($"Timer tick in service {Id}");

    // Public Dispose method
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this); // Prevent finalizer from running
    }

    // Protected implementation of Dispose pattern
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
        {
            // Dispose managed state (managed objects).
            _timer?.Dispose();
            Console.WriteLine($"Service {Id} disposed properly.");
        }

        // Free unmanaged resources (unmanaged objects) and override a finalizer below.
        // Set large fields to null.
        _disposed = true;
    }

    // Finalizer (destructor) - backup for unmanaged resources
    ~DisposableService()
    {
        Console.WriteLine($"Service {Id} was NOT disposed and is being finalized!");
        Dispose(false);
    }
}
```
`Controllers/DisposalDemoController.cs`:
```csharp
namespace Chapter12Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class DisposalDemoController : ControllerBase
{
    private static WeakReference<DisposableService>? _weakRef;

    [HttpGet("create")]
    public IActionResult CreateService()
    {
        var service = new DisposableService();
        _weakRef = new WeakReference<DisposableService>(service);
        // Don't dispose - this is the bug we're demonstrating!
        // service.Dispose();
        return Ok(new { ServiceId = service.Id, Message = "Service created. Check console for timer ticks." });
    }

    [HttpGet("check")]
    public IActionResult CheckService()
    {
        if (_weakRef != null && _weakRef.TryGetTarget(out var service))
        {
            return Ok(new { IsAlive = true, ServiceId = service.Id, Message = "Service is still alive (GC hasn't collected it) because the timer holds a reference." });
        }
        return Ok(new { IsAlive = false, Message = "Service was collected by GC." });
    }

    [HttpGet("collect")]
    public IActionResult ForceGc()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        return Ok("Forced GC and finalization.");
    }
}
```
Register as transient or let it leak: `builder.Services.AddTransient<DisposableService>();`.

---

### **Chapter 13: Diagnostics**
**Challenge:** Create a custom **`[Timed]` attribute** using .NET Middleware or Action Filters that logs the execution time of any endpoint it is applied to. Use `ILogger` to log the timing information.

**Solution:**
`Filters/TimedActionFilter.cs`:
```csharp
namespace Chapter13Challenge.Filters;

public class TimedActionFilter : IActionFilter
{
    private readonly ILogger<TimedActionFilter> _logger;
    private Stopwatch? _stopwatch;

    public TimedActionFilter(ILogger<TimedActionFilter> logger) => _logger = logger;

    public void OnActionExecuting(ActionExecutingContext context)
    {
        _stopwatch = Stopwatch.StartNew();
    }

    public void OnActionExecuted(ActionExecutedContext context)
    {
        _stopwatch!.Stop();
        var actionName = context.ActionDescriptor.DisplayName;
        var elapsedMs = _stopwatch.ElapsedMilliseconds;
        _logger.LogInformation("Action {ActionName} executed in {ElapsedMs} ms.", actionName, elapsedMs);
    }
}
```
`Controllers/DiagnosticsController.cs`:
```csharp
namespace Chapter13Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class DiagnosticsController : ControllerBase
{
    [HttpGet("fast")]
    [ServiceFilter(typeof(TimedActionFilter))] // Apply the filter
    public IActionResult FastEndpoint() => Ok("This was fast!");

    [HttpGet("slow")]
    [ServiceFilter(typeof(TimedActionFilter))] // Apply the filter
    public async Task<IActionResult> SlowEndpoint()
    {
        await Task.Delay(new Random().Next(100, 1000)); // Simulate work
        return Ok("This was slow...");
    }
}
```
Register the filter in `Program.cs`: `builder.Services.AddScoped<TimedActionFilter>();`.

---

### **Chapter 14: Concurrency and Asynchrony**
**Challenge:** Create an endpoint that demonstrates a **deadlock** caused by misusing `.Result` on an async method called from a SynchronizationContext (like the ASP.NET request context). Then, show the fix using `ConfigureAwait(false)`.

**Solution:**
`Services/AsyncService.cs`:
```csharp
namespace Chapter14Challenge.Services;

public class AsyncService
{
    public async Task<string> GetDataAsync()
    {
        await Task.Delay(100); // Simulate async I/O
        return "Data from async method";
    }
}
```
`Controllers/DeadlockController.cs`:
```csharp
namespace Chapter14Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class DeadlockController : ControllerBase
{
    private readonly AsyncService _service;

    public DeadlockController(AsyncService service) => _service = service;

    [HttpGet("deadlock")]
    public string GetDataDeadlock()
    {
        // This will deadlock in an ASP.NET context!
        // The request context is captured by the await in GetDataAsync.
        // .Result blocks the request thread waiting for the result.
        // The async method tries to resume on the request context, which is blocked.
        return _service.GetDataAsync().Result; // BAD! DO NOT DO THIS.
    }

    [HttpGet("safe")]
    public async Task<string> GetDataSafe()
    {
        // The correct way: await the task.
        return await _service.GetDataAsync();
    }

    // Fix inside the service method would be to use ConfigureAwait(false):
    // public async Task<string> GetDataAsync()
    // {
    //     await Task.Delay(100).ConfigureAwait(false); // Avoid capturing context
    //     return "Data from async method";
    // }
    // Then even .Result might not deadlock (but it's still bad practice).
}
```
Register the service: `builder.Services.AddScoped<AsyncService>();`.

---

### **Chapter 15: Streams and I/O**
**Challenge:** Create an endpoint that accepts a file upload, **compresses it** using `BrotliStream`, saves the compressed version to disk, and returns the compression ratio.

**Solution:**
`Controllers/CompressionController.cs`:
```csharp
namespace Chapter15Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class CompressionController : ControllerBase
{
    private readonly IWebHostEnvironment _environment;

    public CompressionController(IWebHostEnvironment environment) => _environment = environment;

    [HttpPost]
    [RequestSizeLimit(10_000_000)] // Allow 10MB files
    public async Task<IActionResult> UploadAndCompress(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("No file uploaded.");

        var originalSize = file.Length;
        var compressedFileName = Path.GetFileNameWithoutExtension(file.FileName) + ".br";
        var compressedFilePath = Path.Combine(_environment.WebRootPath, "compressed", compressedFileName);

        Directory.CreateDirectory(Path.GetDirectoryName(compressedFilePath)!);

        using (var originalStream = file.OpenReadStream())
        using (var compressedStream = new FileStream(compressedFilePath, FileMode.Create))
        using (var brotliStream = new BrotliStream(compressedStream, CompressionLevel.Optimal))
        {
            await originalStream.CopyToAsync(brotliStream);
        }

        var compressedSize = new FileInfo(compressedFilePath).Length;
        var ratio = (double)compressedSize / originalSize;

        return Ok(new
        {
            OriginalSize = originalSize,
            CompressedSize = compressedSize,
            CompressionRatio = ratio,
            SavedBytes = originalSize - compressedSize
        });
    }
}
```

---

### **Chapter 17: Assemblies**
**Challenge:** Implement a simple **plugin system** using a `CustomAssemblyLoadContext`. Create a main API that loads a .dll (plugin) from a specified folder at runtime and executes a method from a known interface within that plugin.

**Solution:**
1. `IPlugin.cs` (Shared Interface Library - `netstandard2.0`):
```csharp
// In a separate 'SharedPluginInterface' project
namespace SharedPluginInterface;
public interface IPlugin
{
    string GetMessage();
}
```
2. `HelloPlugin.cs` (The Plugin - references the interface library):
```csharp
// In a separate 'HelloPlugin' project
namespace HelloPlugin;
public class HelloPlugin : SharedPluginInterface.IPlugin
{
    public string GetMessage() => "Hello from the loaded plugin!";
}
```
3. `Controllers/PluginController.cs` (Main API):
```csharp
namespace Chapter17Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class PluginController : ControllerBase
{
    private readonly IWebHostEnvironment _env;

    public PluginController(IWebHostEnvironment env) => _env = env;

    [HttpGet("{pluginName}")]
    public IActionResult LoadPlugin(string pluginName)
    {
        var pluginsFolder = Path.Combine(_env.ContentRootPath, "Plugins");
        var pluginPath = Path.Combine(pluginsFolder, pluginName, $"{pluginName}.dll");

        if (!File.Exists(pluginPath))
            return NotFound($"Plugin {pluginName} not found.");

        // Create a custom load context to isolate the plugin
        var alc = new PluginLoadContext(pluginPath);
        Assembly assembly = alc.LoadFromAssemblyPath(pluginPath);

        // Find the type that implements IPlugin
        Type? pluginType = assembly.ExportedTypes.FirstOrDefault(t => typeof(SharedPluginInterface.IPlugin).IsAssignableFrom(t));
        if (pluginType == null)
            return BadRequest("No valid IPlugin implementation found.");

        // Create an instance and call the method
        var plugin = (SharedPluginInterface.IPlugin)Activator.CreateInstance(pluginType)!;
        string result = plugin.GetMessage();

        // Unload the context if possible (.NET Core+)
        alc.Unload(); // This is a hint to the GC, unloading is not immediate.

        return Ok(result);
    }
}

// Simple AssemblyLoadContext
public class PluginLoadContext : AssemblyLoadContext
{
    private readonly AssemblyDependencyResolver _resolver;
    public PluginLoadContext(string pluginPath) : base(isCollectible: true) => _resolver = new AssemblyDependencyResolver(pluginPath);
    protected override Assembly? Load(AssemblyName assemblyName)
    {
        string? assemblyPath = _resolver.ResolveAssemblyToPath(assemblyName);
        return assemblyPath != null ? LoadFromAssemblyPath(assemblyPath) : null;
    }
}
```

---

### **Chapter 18: Reflection and Metadata**
**Challenge:** Create an endpoint that uses **reflection** to inspect itself. It should return a list of all controllers in the application, their routes, and the HTTP methods of their actions.

**Solution:**
`Controllers/ReflectionController.cs`:
```csharp
namespace Chapter18Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class ReflectionController : ControllerBase
{
    private readonly IActionDescriptorCollectionProvider _actionDescriptorProvider;

    public ReflectionController(IActionDescriptorCollectionProvider actionDescriptorProvider)
    {
        _actionDescriptorProvider = actionDescriptorProvider;
    }

    [HttpGet("routes")]
    public IActionResult GetRoutes()
    {
        var routes = _actionDescriptorProvider.ActionDescriptors.Items
            .Select(ad =>
            {
                var action = ad as ControllerActionDescriptor;
                if (action == null) return null;

                var httpMethods = action.EndpointMetadata
                    .OfType<HttpMethodMetadata>()
                    .SelectMany(m => m.HttpMethods)
                    .Distinct();

                return new
                {
                    Controller = action.ControllerName,
                    Action = action.ActionName,
                    Route = action.AttributeRouteInfo?.Template ?? $"{action.ControllerName}/{action.ActionName}",
                    Methods = httpMethods,
                    Parameters = action.Parameters.Select(p => new { Name = p.Name, Type = p.ParameterType.Name })
                };
            })
            .Where(info => info != null);

        return Ok(routes);
    }
}
```

---

### **Chapter 19: Dynamic Programming**
**Challenge:** Create an endpoint that uses the `dynamic` keyword to interoperate with a JSON object whose structure is not known at compile time. The endpoint should accept any JSON, add a property `ProcessedAt` dynamically, and return the modified object.

**Solution:**
`Controllers/DynamicController.cs`:
```csharp
namespace Chapter19Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class DynamicController : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> ProcessDynamicJson()
    {
        // Read the request body as a JsonDocument to handle any structure
        using JsonDocument document = await JsonDocument.ParseAsync(Request.Body);
        // Convert to a dynamic object for easy manipulation
        dynamic dynamicObject = ConvertToDynamic(document.RootElement);

        // Add a property dynamically
        dynamicObject.ProcessedAt = DateTime.UtcNow;

        // Return the modified dynamic object (serialized back to JSON)
        return Ok(dynamicObject);
    }

    private dynamic ConvertToDynamic(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var expando = new ExpandoObject();
                var dict = (IDictionary<string, object>)expando;
                foreach (var property in element.EnumerateObject())
                {
                    dict[property.Name] = ConvertToDynamic(property.Value);
                }
                return expando;
            case JsonValueKind.Array:
                return element.EnumerateArray().Select(ConvertToDynamic).ToList();
            case JsonValueKind.String:
                return element.GetString();
            case JsonValueKind.Number:
                return element.GetInt64(); // or GetDouble()
            case JsonValueKind.True:
                return true;
            case JsonValueKind.False:
                return false;
            case JsonValueKind.Null:
                return null;
            default:
                return null;
        }
    }
}
```

---

### **Chapter 20: Cryptography**
**Challenge:** Create a secure endpoint that demonstrates **symmetric encryption** (AES) and **asymmetric encryption** (RSA). It should generate an AES key, encrypt it with a pre-existing RSA public key, and then demonstrate decrypting it with the RSA private key. Store the RSA keys as environment variables.

**Solution:**
`Controllers/CryptoController.cs`:
```csharp
namespace Chapter20Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class CryptoController : ControllerBase
{
    private readonly IConfiguration _config;

    public CryptoController(IConfiguration config) => _config = config;

    [HttpGet("encrypt")]
    public IActionResult EncryptMessage(string message)
    {
        // 1. Generate a random AES key and IV
        using Aes aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();

        // 2. Encrypt the message with AES
        byte[] encryptedMessage;
        using (var encryptor = aes.CreateEncryptor())
        using (var ms = new MemoryStream())
        {
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(message);
            }
            encryptedMessage = ms.ToArray();
        }

        // 3. Get RSA public key from config
        string publicKeyXml = _config["RSA_PublicKey"];
        using RSA rsa = RSA.Create();
        rsa.FromXmlString(publicKeyXml);

        // 4. Encrypt the AES key with RSA
        byte[] encryptedAesKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.Pkcs1);

        return Ok(new
        {
            EncryptedMessage = Convert.ToBase64String(encryptedMessage),
            EncryptedAesKey = Convert.ToBase64String(encryptedAesKey),
            IV = Convert.ToBase64String(aes.IV)
        });
    }

    [HttpPost("decrypt")]
    public IActionResult DecryptMessage([FromBody] EncryptedPayload payload)
    {
        // 1. Get RSA private key from config (THIS SHOULD BE ON A VERY SECURE SERVER)
        string privateKeyXml = _config["RSA_PrivateKey"];
        using RSA rsa = RSA.Create();
        rsa.FromXmlString(privateKeyXml);

        // 2. Decrypt the AES key using RSA private key
        byte[] decryptedAesKey = rsa.Decrypt(Convert.FromBase64String(payload.EncryptedAesKey), RSAEncryptionPadding.Pkcs1);

        // 3. Decrypt the message using the decrypted AES key and provided IV
        using Aes aes = Aes.Create();
        aes.Key = decryptedAesKey;
        aes.IV = Convert.FromBase64String(payload.IV);

        string decryptedMessage;
        using (var decryptor = aes.CreateDecryptor())
        using (var ms = new MemoryStream(Convert.FromBase64String(payload.EncryptedMessage)))
        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
        using (var sr = new StreamReader(cs))
        {
            decryptedMessage = sr.ReadToEnd();
        }

        return Ok(new { DecryptedMessage = decryptedMessage });
    }

    public class EncryptedPayload
    {
        public string EncryptedMessage { get; set; }
        public string EncryptedAesKey { get; set; }
        public string IV { get; set; }
    }
}
```
*Note: Storing RSA keys in environment variables is a simplified example. For production, use a proper secrets manager like Azure Key Vault or HashiCorp Vault.*

---

### **Chapter 21: Advanced Threading**
**Challenge:** Implement the **Producer/Consumer pattern** using `BlockingCollection<T>` and `CancellationToken`. Create one endpoint to start a producer and a consumer task, and another endpoint to signal cancellation, gracefully shutting down the pattern.

**Solution:**
`Services/ProducerConsumerService.cs`:
```csharp
namespace Chapter21Challenge.Services;

public class ProducerConsumerService : IHostedService, IDisposable
{
    private readonly BlockingCollection<string> _queue = new BlockingCollection<string>(boundedCapacity: 10);
    private readonly ILogger<ProducerConsumerService> _logger;
    private Task? _producerTask;
    private Task? _consumerTask;
    private CancellationTokenSource? _cts;

    public ProducerConsumerService(ILogger<ProducerConsumerService> logger) => _logger = logger;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _producerTask = Task.Run(Produce, _cts.Token);
        _consumerTask = Task.Run(Consume, _cts.Token);
        _logger.LogInformation("Producer/Consumer service started.");
        return Task.CompletedTask;
    }

    private async Task Produce()
    {
        int itemNumber = 0;
        while (!_cts!.IsCancellationRequested)
        {
            var newItem = $"Item {itemNumber++}";
            // Add will block if the collection is full (backpressure)
            _queue.Add(newItem, _cts.Token);
            _logger.LogInformation("Produced: {Item}", newItem);
            await Task.Delay(500, _cts.Token); // Simulate work
        }
    }

    private async Task Consume()
    {
        foreach (var item in _queue.GetConsumingEnumerable(_cts!.Token))
        {
            _logger.LogInformation("Consumed: {Item}", item);
            await Task.Delay(1000, _cts.Token); // Simulate slower consumption
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel(); // Signal cancellation
        _logger.LogInformation("Stopping Producer/Consumer service...");

        // Wait for tasks to complete gracefully
        if (_producerTask != null) await _producerTask;
        if (_consumerTask != null) await _consumerTask;

        _queue.Dispose();
        _logger.LogInformation("Producer/Consumer service stopped.");
    }

    public void Dispose() => _queue?.Dispose();
}
```
`Controllers/ThreadingController.cs`:
```csharp
namespace Chapter21Challenge.Controllers;

[ApiController]
[Route("[controller]")]
public class ThreadingController : ControllerBase
{
    private readonly ProducerConsumerService _service;

    public ThreadingController(ProducerConsumerService service) => _service = service;

    [HttpPost("start")]
    public IActionResult StartService() => Ok("Service is already running as a hosted service.");

    [HttpPost("stop")]
    public async Task<IActionResult> StopService()
    {
        await _service.StopAsync(new CancellationToken());
        return Ok("Stop signal sent.");
    }
}
```
Register as a hosted service in `Program.cs`: `builder.Services.AddHostedService<ProducerConsumerService>();`.

---

These challenges cover a vast range of crucial .NET concepts. Mastering them will undoubtedly solidify your path to becoming a senior .NET developer. Good luck
