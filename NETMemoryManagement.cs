Here are 15 code challenges covering .NET memory management concepts, categorized into Beginner, Intermediate, and Senior levels. Each challenge includes a problem statement, solution, and explanation, with extra focus on memory leaks.

---

### **Beginner Level**

#### **Challenge 1: Value vs. Reference Types**
**Problem**:  
Create a program that demonstrates the difference between value types (struct) and reference types (class) in terms of copying behavior.  
```csharp
// Define a struct (value type) and a class (reference type)
struct PointStruct { public int X, Y; }
class PointClass { public int X, Y; }

// Assign and modify instances to observe behavior
PointStruct a = new PointStruct { X = 1, Y = 2 };
PointStruct b = a; // Copy by value
b.X = 10;         // Does NOT affect 'a'

PointClass c = new PointClass { X = 1, Y = 2 };
PointClass d = c; // Copy by reference
d.X = 10;         // Affects 'c'
```

**Explanation**:  
Value types (`struct`) are copied by value, so modifying `b` does not affect `a`. Reference types (`class`) are copied by reference, so modifying `d` also changes `c`.

---

#### **Challenge 2: String Interning**
**Problem**:  
Demonstrate how string interning reduces memory usage for duplicate strings.  
```csharp
string s1 = "Hello";
string s2 = "Hello";
string s3 = new string("Hello".ToCharArray());

Console.WriteLine(object.ReferenceEquals(s1, s2)); // True (interned)
Console.WriteLine(object.ReferenceEquals(s1, s3)); // False (not interned)

s3 = string.Intern(s3); // Force interning
Console.WriteLine(object.ReferenceEquals(s1, s3)); // True (now interned)
```

**Explanation**:  
Literal strings are automatically interned, but dynamically created strings are not unless explicitly interned with `string.Intern`.

---

#### **Challenge 3: Boxing Overhead**
**Problem**:  
Show how boxing a value type (`int`) allocates heap memory.  
```csharp
int number = 42;
object boxed = number; // Boxing allocates heap memory
int unboxed = (int)boxed; // Unboxing
```

**Explanation**:  
Boxing converts a value type to a reference type, causing a heap allocation. Avoid this in performance-critical code.

---

#### **Challenge 4: Basic GC Trigger**
**Problem**:  
Force a garbage collection and log the generations collected.  
```csharp
GC.Collect(0); // Collect only Gen 0
Console.WriteLine($"Gen 0 collections: {GC.CollectionCount(0)}");
```

**Explanation**:  
`GC.Collect` triggers garbage collection for a specific generation. Avoid using this in production.

---

#### **Challenge 5: Finalizer Basics**
**Problem**:  
Create a class with a finalizer and observe its behavior during GC.  
```csharp
class ResourceHolder {
    ~ResourceHolder() { Console.WriteLine("Finalizer called!"); }
}

new ResourceHolder(); // No reference
GC.Collect();
GC.WaitForPendingFinalizers();
```

**Explanation**:  
Finalizers are called when the object is garbage-collected. They delay memory reclamation and add overhead.

---

### **Intermediate Level**

#### **Challenge 6: Memory Leak via Event Handlers**
**Problem**:  
Create a memory leak by not unsubscribing event handlers.  
```csharp
class Publisher {
    public event EventHandler Event;
}
class Subscriber {
    public Subscriber(Publisher pub) { pub.Event += HandleEvent; }
    void HandleEvent(object sender, EventArgs e) { }
}

var pub = new Publisher();
var sub = new Subscriber(pub);
sub = null; // Leak: Publisher still holds a reference to Subscriber
GC.Collect();
Console.WriteLine("Subscriber not collected due to event reference.");
```

**Fix**:  
Unsubscribe the event in `Subscriber`’s destructor or implement `IDisposable`.

---

#### **Challenge 7: Large Object Heap (LOH) Fragmentation**
**Problem**:  
Simulate LOH fragmentation by allocating and releasing large arrays.  
```csharp
byte[][] chunks = new byte[100][];
for (int i = 0; i < 100; i++) {
    chunks[i] = new byte[85_000]; // LOH allocation
    if (i % 2 == 0) chunks[i] = null; // Release every other
}
// Fragmentation: Free gaps are too small for new 85KB allocations
```

**Fix**:  
Use `ArrayPool<byte>` to reuse arrays and avoid fragmentation.

---

#### **Challenge 8: WeakReference for Caching**
**Problem**:  
Implement a cache using `WeakReference` to allow GC reclaiming.  
```csharp
var cache = new WeakReference<List<string>>(new List<string>());
if (cache.TryGetTarget(out var data)) {
    data.Add("CachedItem");
} else {
    cache.SetTarget(new List<string>());
}
```

**Explanation**:  
`WeakReference` lets the GC reclaim the cache if memory pressure is high.

---

#### **Challenge 9: IDisposable Pattern**
**Problem**:  
Implement `IDisposable` correctly for a class holding unmanaged resources.  
```csharp
class UnmanagedResource : IDisposable {
    private IntPtr handle = Marshal.AllocHGlobal(100);
    private bool disposed = false;

    public void Dispose() {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    protected virtual void Dispose(bool disposing) {
        if (!disposed) {
            Marshal.FreeHGlobal(handle);
            disposed = true;
        }
    }
    ~UnmanagedResource() { Dispose(false); }
}
```

**Explanation**:  
The `IDisposable` pattern ensures deterministic cleanup of unmanaged resources.

---

#### **Challenge 10: Stack vs. Heap Allocation**
**Problem**:  
Use `ref struct` to ensure stack-only allocation.  
```csharp
ref struct StackOnlyStruct {
    public int Value;
    public void Print() => Console.WriteLine(Value);
}
// Error if attempted to box: object obj = new StackOnlyStruct();
```

**Explanation**:  
`ref struct` prevents heap allocation, useful for high-performance scenarios.

---

### **Senior Level**

#### **Challenge 11: Pinvoke and Memory Leaks**
**Problem**:  
Demonstrate a memory leak in P/Invoke due to unmanaged handle leakage.  
```csharp
[DllImport("kernel32.dll")]
static extern IntPtr CreateFile(/* params */);

IntPtr fileHandle = CreateFile(/* ... */);
// Leak: Forgot to call CloseHandle(fileHandle)
```

**Fix**:  
Wrap the handle in `SafeHandle` or call `CloseHandle` in `Dispose`.

---

#### **Challenge 12: Span<T> for Zero-Allocation**
**Problem**:  
Process a string without allocations using `Span<char>`.  
```csharp
string input = "Hello, World!";
Span<char> span = input.AsSpan();
for (int i = 0; i < span.Length; i++) {
    span[i] = char.ToUpper(span[i]);
}
```

**Explanation**:  
`Span<T>` avoids heap allocations for substrings or slices.

---

#### **Challenge 13: ConditionalWeakTable for Lifetime Management**
**Problem**:  
Use `ConditionalWeakTable` to attach metadata to objects without preventing GC.  
```csharp
var table = new ConditionalWeakTable<object, string>();
var key = new object();
table.Add(key, "Metadata");
key = null; // GC can collect 'key'; metadata is automatically removed
```

**Explanation**:  
`ConditionalWeakTable` couples lifetimes without strong references.

---

#### **Challenge 14: Diagnose Memory Leak with WinDbg**
**Problem**:  
Simulate a leak and analyze it with WinDbg commands.  
```csharp
static List<byte[]> leak = new List<byte[]>();
for (int i = 0; i < 1000; i++) leak.Add(new byte[10_000]);
```

**WinDbg Commands**:  
```
!dumpheap -stat
!gcroot -all <address_of_leaked_object>
```

---

#### **Challenge 15: Data-Oriented Design (SoA)**
**Problem**:  
Rewrite an `Array-of-Structs` to `Struct-of-Arrays` for cache efficiency.  
```csharp
// Before (AoS):
struct Entity { float X, Y, Z; }
Entity[] entities = new Entity[1000];

// After (SoA):
struct Entities {
    float[] X = new float[1000];
    float[] Y = new float[1000];
    float[] Z = new float[1000];
}
```

**Explanation**:  
SoA improves cache locality when processing specific fields (e.g., all `X` values).

---

### **Bonus: Memory Leak Challenges**
#### **Leak 1: Static Collection**
```csharp
static List<object> _staticList = new List<object>();
_staticList.Add(new object()); // Never removed
```
**Fix**: Clear the collection when no longer needed.

#### **Leak 2: Timer Callbacks**
```csharp
var timer = new Timer(_ => Console.WriteLine("Tick"), null, 0, 1000);
// Leak: Timer holds callback references. Dispose it!
```

#### **Leak 3: Thread Static Fields**
```csharp
[ThreadStatic] static List<object> _threadData;
_threadData = new List<object>(); // Lives until thread dies
```

---

These challenges cover key concepts from the book, with extra emphasis on memory leaks. Mastery of these will solidify your understanding of .NET memory management. Let me know if you'd like additional challenges on specific topics!






Of course. Here are 10 additional code challenges focused specifically on identifying, creating, and fixing various types of memory leaks in .NET, ranging from classic pitfalls to more subtle and complex scenarios.

---

### **Memory Leak Challenge 1: The Event Handler Leak (The Classic)**

**Problem**: This is one of the most common causes of managed memory leaks. A publisher's event holds a strong reference to a subscriber's event handler method, which in turn holds a reference to the subscriber object itself. If the subscriber is not properly unsubscribed, it will never be garbage collected.

```csharp
// Leaky Code
public class EventPublisher
{
    public event EventHandler SomethingHappened;
    public void RaiseEvent() => SomethingHappened?.Invoke(this, EventArgs.Empty);
}

public class EventSubscriber
{
    public EventSubscriber(EventPublisher publisher)
    {
        // This creates a strong reference from publisher -> this subscriber
        publisher.SomethingHappened += Publisher_SomethingHappened;
    }

    private void Publisher_SomethingHappened(object sender, EventArgs e)
    {
        Console.WriteLine("Something happened!");
    }
}

// Usage that causes a leak
var publisher = new EventPublisher();
var subscriber = new EventSubscriber(publisher);

// Even if we null the subscriber, the publisher's event still references it!
subscriber = null;
GC.Collect();
// The EventSubscriber instance will NOT be collected due to the event reference.
```

**Your Task**: Rewrite the `EventSubscriber` class to prevent the leak. Implement a mechanism to unsubscribe from the event.

**Solution & Explanation**:
```csharp
public class EventSubscriber : IDisposable
{
    private EventPublisher _publisher;

    public EventSubscriber(EventPublisher publisher)
    {
        _publisher = publisher;
        _publisher.SomethingHappened += Publisher_SomethingHappened;
    }

    private void Publisher_SomethingHappened(object sender, EventArgs e) { }

    public void Dispose()
    {
        // Critical: Remove the reference so the subscriber can be collected.
        if (_publisher != null)
        {
            _publisher.SomethingHappened -= Publisher_SomethingHappened;
            _publisher = null;
        }
    }
}

// Usage
using (var subscriber = new EventSubscriber(publisher))
{
    // work with subscriber
} // Dispose is called automatically, unsubscribing the event.
// Now the subscriber can be garbage collected.
```

---

### **Memory Leak Challenge 2: The Static Collection Leak**

**Problem**: Static fields have a lifetime that lasts for the entire `AppDomain`. Any object added to a static collection will be rooted and never collected.

```csharp
// Leaky Code
public static class Cache
{
    // DANGER: Static collection roots everything added to it.
    public static List<object> GlobalCache = new List<object>();
}

public class SomeData
{
    public string Name { get; set; }
}

// Usage that causes a leak
var data = new SomeData { Name = "Leaky Data" };
Cache.GlobalCache.Add(data);

data = null; // The SomeData object is still held by the static list!
GC.Collect();
// The SomeData instance will NEVER be collected.
```

**Your Task**: Design a better caching mechanism that does not permanently leak memory. Use a `WeakReference` or a conditional weak table.

**Solution & Explanation**:
```csharp
public static class BetterCache
{
    // Use WeakReference to hold the objects. The GC can collect them if memory is needed.
    private static List<WeakReference<object>> _weakCache = new List<WeakReference<object>>();

    public static void Add(object item)
    {
        _weakCache.Add(new WeakReference<object>(item));
    }

    public static IEnumerable<object> GetAliveItems()
    {
        // Clean up dead references and return only alive objects.
        var aliveItems = new List<object>();
        for (int i = _weakCache.Count - 1; i >= 0; i--)
        {
            if (_weakCache[i].TryGetTarget(out object target))
            {
                aliveItems.Add(target);
            }
            else
            {
                _weakCache.RemoveAt(i); // Clean up the dead reference
            }
        }
        return aliveItems;
    }
}
```

---

### **Memory Leak Challenge 3: The Timer Leak**

**Problem**: .NET Timers (`System.Threading.Timer`, `System.Timers.Timer`) hold references to their callback delegates. If the timer is not disposed, it will keep the callback (and any captured objects) alive.

```csharp
// Leaky Code
public class Service
{
    private Timer _timer;

    public Service()
    {
        _timer = new Timer(OnTimerTick, null, 1000, 1000);
    }

    private void OnTimerTick(object state)
    {
        // Do some work
        Console.WriteLine("Tick");
    }
}

// Usage
var service = new Service();
service = null; // The Timer is still active and running, preventing the Service object from being collected!
```

**Your Task**: Modify the `Service` class to properly manage the timer's lifecycle and prevent the leak.

**Solution & Explanation**:
```csharp
public class Service : IDisposable
{
    private Timer _timer;
    private bool _disposed = false;

    public Service()
    {
        _timer = new Timer(OnTimerTick, null, 1000, 1000);
    }

    private void OnTimerTick(object state) { }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed resources (like the Timer)
                _timer?.Dispose(); // This stops the timer and removes the callback reference.
                _timer = null;
            }
            _disposed = true;
        }
    }
}
// Usage: Use 'using' or call Dispose() when done with the Service.
```

---

### **Memory Leak Challenge 4: The Thread-Leak via ThreadStatic**

**Problem**: While `[ThreadStatic]` data is isolated per thread, it lives for the lifetime of that thread. If a thread is part of a thread pool (which is long-lived), any data stored in its `[ThreadStatic]` field will also live for a very long time, effectively leaking it.

```csharp
// Leaky Code
public class RequestContext
{
    [ThreadStatic]
    private static RequestContext _current;

    public static RequestContext Current => _current ??= new RequestContext();
    public string RequestId { get; } = Guid.NewGuid().ToString();
    // ... other large data
}

// Usage in an ASP.NET-like scenario
Task.Run(() =>
{
    var context = RequestContext.Current; // Created and stored for this thread pool thread
    // Do work
});
// The thread returns to the pool. The RequestContext object remains allocated,
// tied to that thread's [ThreadStatic] storage, for the lifetime of the thread.
```

**Your Task**: Propose a safer alternative to store thread-specific data that can be cleaned up.

**Solution & Explanation**:
```csharp
// Use AsyncLocal<T> for async contexts or a slot-based approach that you can clear.
public class RequestContext : IDisposable
{
    private static AsyncLocal<RequestContext> _current = new AsyncLocal<RequestContext>();

    public static RequestContext Current => _current.Value;
    public string RequestId { get; } = Guid.NewGuid().ToString();

    public RequestContext()
    {
        _current.Value = this;
    }

    public void Dispose()
    {
        // Crucial: Clear the context when the request is done.
        if (_current.Value == this)
        {
            _current.Value = null;
        }
    }
}

// Usage in a middleware:
// using (var context = new RequestContext()) { await _next(); }
```

---

### **Memory Leak Challenge 5: The Unmanaged Resource Leak**

**Problem**: This is not a *managed* leak but a true, classic unmanaged leak. Failing to release unmanaged handles (files, network sockets, GDI handles, allocated memory) will cause the *process's* memory usage to grow indefinitely, even though the .NET GC is working fine.

```csharp
// Leaky Code (P/Invoke example)
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr CreateFile(string lpFileName, /* ... parameters ... */ );

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool CloseHandle(IntPtr hObject);

public class FileWorker
{
    private IntPtr _fileHandle;

    public void OpenFile(string path)
    {
        _fileHandle = CreateFile(path, /* ... */ );
        // If we forget to call CloseHandle later, the OS handle is leaked.
    }
    // Missing a Dispose method or finalizer to call CloseHandle!
}
```

**Your Task**: Implement the `IDisposable` pattern with a finalizer to guarantee the unmanaged handle is released.

**Solution & Explanation**:
```csharp
public class FileWorker : IDisposable
{
    private IntPtr _fileHandle;
    private bool _disposed = false;

    public void OpenFile(string path)
    {
        _fileHandle = CreateFile(path, /* ... */ );
    }

    // Finalizer (safety net in case Dispose isn't called)
    ~FileWorker()
    {
        Dispose(false);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (_fileHandle != IntPtr.Zero)
            {
                CloseHandle(_fileHandle); // Release the unmanaged resource.
                _fileHandle = IntPtr.Zero;
            }
            _disposed = true;
        }
    }
}
// The only correct way to use this is with a 'using' statement.
```

---

### **Memory Leak Challenge 6: The Cached Delegates Leak**

**Problem**: Caching delegates that capture instance methods (e.g., `someInstance.SomeMethod`) implicitly captures the `this` reference. If the cache is long-lived, it will root all the captured instances.

```csharp
// Leaky Code
public static class OperationCache
{
    public static Dictionary<string, Func<int, int>> Operations = new Dictionary<string, Func<int, int>>();
}

public class ExpensiveCalculator
{
    private int _baseValue = 42; // Captured in the delegate

    public ExpensiveCalculator()
    {
        // This lambda captures 'this', so the entire ExpensiveCalculator instance is rooted by the static cache.
        OperationCache.Operations["expensiveOp"] = (x) => x + _baseValue;
    }
}

// Usage
var calculator = new ExpensiveCalculator(); // Instance is now cached forever
calculator = null;
GC.Collect();
// The ExpensiveCalculator is NOT collected because the static dictionary holds a delegate that references it.
```

**Your Task**: Refactor the code to avoid capturing the instance in the static cache. Hint: Make the method static and pass state as a parameter.

**Solution & Explanation**:
```csharp
public static class OperationCache
{
    public static Dictionary<string, Func<int, int, int>> Operations = new Dictionary<string, Func<int, int, int>>();
}

public class ExpensiveCalculator
{
    // The operation is now static and takes the state as a parameter.
    private static int ExpensiveOperationImpl(int x, int baseValue) => x + baseValue;

    public ExpensiveCalculator()
    {
        // Register a delegate that does NOT capture 'this'
        OperationCache.Operations["expensiveOp"] = (x, b) => ExpensiveOperationImpl(x, b);
        // Alternatively, just register the static method directly:
        // OperationCache.Operations["expensiveOp"] = ExpensiveOperationImpl;
    }

    public int Calculate(int x)
    {
        // You must now pass the state (baseValue) explicitly.
        return OperationCache.Operations["expensiveOp"](x, 42);
    }
}
// Now the delegate in the cache is static and roots no instances.
```

---

### **Memory Leak Challenge 7: The "Mid-Life Crisis" Leak (Behavioral)**

**Problem**: This isn't a true leak but a behavior that causes excessive memory usage and Gen 2 collections. Objects that live just long enough to get promoted to Gen 2 but then die immediately are very expensive to collect and waste memory.

```csharp
// Code that causes "Mid-Life Crisis"
public class DataProcessor
{
    public void ProcessData(byte[] data)
    {
        // Create a cache entry that is supposed to be short-lived for this process
        var cacheEntry = new CacheEntry { Data = data, ProcessedAt = DateTime.UtcNow };

        // ... some long-running processing ...
        Task.Delay(100).Wait(); // Simulate work

        // The cacheEntry is no longer needed but is already in Gen 1/2 by the time we finish.
    }
}

public class CacheEntry
{
    public byte[] Data { get; set; }
    public DateTime ProcessedAt { get; set; }
}
// If ProcessData is called frequently, Gen 2 fills up with dead CacheEntry objects.
```

**Your Task**: Propose a strategy to prevent these short-lived-but-long-lasting objects from getting promoted to higher generations.

**Solution & Explanation**:
```csharp
// 1. Use object pooling for the CacheEntry to avoid allocations.
public class CacheEntryPool
{
    private readonly ConcurrentBag<CacheEntry> _pool = new ConcurrentBag<CacheEntry>();

    public CacheEntry Rent(byte[] data)
    {
        if (!_pool.TryTake(out var entry))
        {
            entry = new CacheEntry();
        }
        entry.Data = data;
        entry.ProcessedAt = DateTime.UtcNow;
        return entry;
    }

    public void Return(CacheEntry entry)
    {
        entry.Data = null; // Release the large array reference
        _pool.Add(entry);
    }
}

// 2. In the processor, ensure the object is cleaned up and returned to the pool quickly.
public class DataProcessor
{
    private CacheEntryPool _pool = new CacheEntryPool();

    public void ProcessData(byte[] data)
    {
        var cacheEntry = _pool.Rent(data);
        try
        {
            // ... processing ...
            Task.Delay(100).Wait();
        }
        finally
        {
            // RETURN THE OBJECT TO THE POOL IMMEDIATELY AFTER USE.
            // This prevents it from aging into Gen 2.
            _pool.Return(cacheEntry);
        }
    }
}
```

---

### **Memory Leak Challenge 8: The Dependency Injection (DI) Container Leak**

**Problem**: DI Containers (like the one in ASP.NET Core) typically hold references to services for the lifetime of the container (often the application's lifetime). If you mistakenly register a short-lived service as a Singleton, the container roots it forever, along with any dependencies it might have.

```csharp
// Leaky Registration in Startup.cs (ASP.NET Core)
public void ConfigureServices(IServiceCollection services)
{
    // DANGER: This HttpService has a dependency on a DbContext.
    // Registering it as Singleton means the DbContext (and any cached data) is also a singleton and never released.
    services.AddSingleton<HttpService>();

    // The HttpService might be designed to be short-lived but is now forced to be permanent.
}

public class HttpService
{
    private readonly MyDbContext _context;
    public HttpService(MyDbContext context) => _context = context; // DbContext is now a singleton!
}
```

**Your Task**: Identify the leak and correct the service lifetime registration.

**Solution & Explanation**:
```csharp
// The correct lifetime is almost certainly Scoped or Transient.
public void ConfigureServices(IServiceCollection services)
{
    // Transient: New instance every time it's requested.
    services.AddTransient<HttpService>();

    // Or more commonly, Scoped: One instance per HTTP request.
    services.AddScoped<HttpService>();
}
// Now the HttpService and its DbContext are released at the end of the request.
```

---

### **Memory Leak Challenge 9: The "Rooted Object Graph" Leak**

**Problem**: A single rooted object can hold an entire complex graph of objects alive. This can be hard to spot with tools if the root is legitimate (like a static field) but the scale of the graph is unintentionally huge.

```csharp
// Leaky Code
public static class AppState
{
    public static UserSession CurrentSession { get; set; }
}

public class UserSession
{
    public User User { get; set; }
    public List<Order> OrderHistory { get; set; } = new List<Order>();
    // ... many other properties ...
}

public class User { /* ... large object graph ... */ }
public class Order { /* ... large object graph ... */ }

// Usage
var session = new UserSession
{
    User = LoadUserFromDatabase(), // Returns a large object
    OrderHistory = LoadOrders() // Returns a list of 10,000 large objects
};
AppState.CurrentSession = session; // Roots the entire massive graph forever.

// Later, the user logs out, but we forget to clear the session.
// AppState.CurrentSession = null; // FORGOTTEN!
// The entire user/order graph is permanently leaked.
```

**Your Task**: Propose a strategy to manage this kind of application state without causing a permanent leak.

**Solution & Explanation**:
```csharp
// 1. Avoid statics for mutable state. Use a factory or request-based storage.
// 2. If you must use a static, provide a clear method to clean up.
public static class AppState
{
    private static UserSession _currentSession;
    public static UserSession CurrentSession => _currentSession;

    public static void Login(UserSession session)
    {
        _currentSession = session;
    }

    public static void Logout()
    {
        // CRITICAL: Clear the reference to allow the entire graph to be collected.
        _currentSession = null;
    }
}

// 3. Use WeakReference if the state should be available but not prevent collection.
public static class WeakAppState
{
    private static WeakReference<UserSession> _weakSession = new WeakReference<UserSession>(null);

    public static bool TryGetSession(out UserSession session)
    {
        return _weakSession.TryGetTarget(out session);
    }

    public static void SetSession(UserSession session)
    {
        _weakSession.SetTarget(session);
    }
    // No need to logout; the GC will clear it naturally.
}
```

---

### **Memory Leak Challenge 10: The "Captured Closure in a Loop" Leak**

**Problem**: A common mistake is capturing the loop variable in a closure for a long-running task or timer. This can cause the closure to capture unintended state and root it.

```csharp
// Leaky Code
public void ProcessItems(List<Item> items)
{
    for (int i = 0; i < items.Count; i++)
    {
        // The lambda captures the variable 'i', and due to how C# captures loop variables,
        // it effectively captures the entire iteration context.
        Task.Run(() => Console.WriteLine(items[i].Name));
    }
    // If the tasks are long-running, they hold references to the 'items' list and
    // the specific 'item' at the captured index for much longer than expected.
}
// In older C# versions, 'i' was captured in a way that shared the same variable,
// leading to all tasks seeing the final value of 'i'. This is mostly fixed by modern
// compilers, but the lifetime issue remains.
```

**Your Task**: Fix the loop to avoid capturing the loop variable and ensure tasks only hold references to the specific data they need.

**Solution & Explanation**:
```csharp
public void ProcessItems(List<Item> items)
{
    foreach (var item in items) // 'item' is a new variable each iteration
    {
        // Copy the current item to a local variable inside the loop.
        // This breaks the capture of the loop variable.
        var currentItem = item;
        Task.Run(() => Console.WriteLine(currentItem.Name));
        // Now the lambda only captures 'currentItem', which is a specific object,
        // not the entire loop context.
    }
}
// For maximum safety, if the item is large, consider passing only the needed data (e.g., item.Id or item.Name).
```
