# ASP.NET Core Minimal API File Handling Challenges

Here are code challenges covering the requested subjects plus additional file-related challenges, with solutions for each.

## 1. Secure File Deletion

### Intermediate Challenge:
**Implement an API endpoint that securely deletes a file by overwriting its content before deletion to prevent recovery.**

```csharp
// Secure File Deletion - Intermediate Solution
app.MapDelete("/files/secure-delete/{filename}", async (string filename, IWebHostEnvironment env) =>
{
    var filePath = Path.Combine(env.ContentRootPath, "Files", filename);
    
    if (!File.Exists(filePath))
        return Results.NotFound();
    
    try
    {
        // Overwrite file content multiple times before deletion
        await SecureDeleteFile(filePath, overwritePasses: 3);
        return Results.Ok($"File {filename} securely deleted");
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error securely deleting file: {ex.Message}");
    }
});

async Task SecureDeleteFile(string filePath, int overwritePasses)
{
    var fileInfo = new FileInfo(filePath);
    var fileLength = fileInfo.Length;
    
    using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
    {
        var random = new Random();
        var buffer = new byte[fileLength];
        
        for (int i = 0; i < overwritePasses; i++)
        {
            random.NextBytes(buffer);
            stream.Position = 0;
            await stream.WriteAsync(buffer);
            await stream.FlushAsync();
        }
    }
    
    File.Delete(filePath);
}
```

### Senior Challenge:
**Create a secure file deletion service that handles large files efficiently (chunked overwriting) and provides progress reporting.**

```csharp
// Secure File Deletion - Senior Solution
app.MapDelete("/files/secure-delete-large/{filename}", async (string filename, IWebHostEnvironment env) =>
{
    var filePath = Path.Combine(env.ContentRootPath, "Files", filename);
    
    if (!File.Exists(filePath))
        return Results.NotFound();
    
    try
    {
        var progress = new Progress<double>(p => Console.WriteLine($"Progress: {p:P}"));
        await SecureDeleteLargeFile(filePath, progress);
        return Results.Ok($"File {filename} securely deleted");
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error securely deleting file: {ex.Message}");
    }
});

async Task SecureDeleteLargeFile(string filePath, IProgress<double> progress, int bufferSize = 4096)
{
    var fileInfo = new FileInfo(filePath);
    var fileLength = fileInfo.Length;
    var random = new Random();
    var buffer = new byte[bufferSize];
    var passes = 3;
    
    for (int pass = 0; pass < passes; pass++)
    {
        using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            long totalBytesWritten = 0;
            
            while (totalBytesWritten < fileLength)
            {
                random.NextBytes(buffer);
                var bytesToWrite = (int)Math.Min(buffer.Length, fileLength - totalBytesWritten);
                await stream.WriteAsync(buffer, 0, bytesToWrite);
                totalBytesWritten += bytesToWrite;
                
                progress?.Report((double)totalBytesWritten / fileLength);
            }
            
            await stream.FlushAsync();
        }
    }
    
    File.Delete(filePath);
}
```

## 2. Fault-Tolerant File Writing

### Intermediate Challenge:
**Implement a file writing endpoint that uses a temporary file and atomic move operation to ensure file integrity.**

```csharp
// Fault-Tolerant Writing - Intermediate Solution
app.MapPost("/files/write-safe", async (IWebHostEnvironment env, HttpRequest request) =>
{
    var fileName = request.Headers["X-File-Name"].ToString();
    if (string.IsNullOrEmpty(fileName))
        return Results.BadRequest("File name header is required");
    
    var filePath = Path.Combine(env.ContentRootPath, "Files", fileName);
    var tempPath = filePath + ".tmp";
    
    try
    {
        // Write to temp file first
        using (var tempStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write))
        {
            await request.Body.CopyToAsync(tempStream);
            await tempStream.FlushAsync();
        }
        
        // Atomic move operation
        if (File.Exists(filePath))
            File.Delete(filePath);
        File.Move(tempPath, filePath);
        
        return Results.Ok("File written successfully");
    }
    catch (Exception ex)
    {
        // Clean up temp file if something went wrong
        if (File.Exists(tempPath))
            File.Delete(tempPath);
        return Results.Problem($"Error writing file: {ex.Message}");
    }
});
```

### Senior Challenge:
**Implement a file writing system with transaction logging that can recover interrupted writes by using a transaction log.**

```csharp
// Fault-Tolerant Writing - Senior Solution
app.MapPost("/files/write-transactional", async (IWebHostEnvironment env, HttpRequest request) =>
{
    var fileName = request.Headers["X-File-Name"].ToString();
    if (string.IsNullOrEmpty(fileName))
        return Results.BadRequest("File name header is required");
    
    var filePath = Path.Combine(env.ContentRootPath, "Files", fileName);
    var tempPath = filePath + ".tmp";
    var logPath = filePath + ".log";
    
    try
    {
        // Start transaction (write to log)
        await File.WriteAllTextAsync(logPath, $"START|{DateTime.UtcNow:o}|{fileName}");
        
        // Write to temp file
        using (var tempStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write))
        {
            await request.Body.CopyToAsync(tempStream);
            await tempStream.FlushAsync();
        }
        
        // Commit transaction
        await File.AppendAllTextAsync(logPath, $"\nCOMMIT|{DateTime.UtcNow:o}");
        
        // Atomic move operation
        if (File.Exists(filePath))
            File.Delete(filePath);
        File.Move(tempPath, filePath);
        
        // Clean up log
        File.Delete(logPath);
        
        return Results.Ok("File written successfully");
    }
    catch (Exception ex)
    {
        // Check if we need to recover
        if (File.Exists(logPath))
        {
            var logContent = await File.ReadAllTextAsync(logPath);
            if (logContent.Contains("START") && !logContent.Contains("COMMIT"))
            {
                // Recovery needed
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
                File.Delete(logPath);
            }
        }
        return Results.Problem($"Error writing file: {ex.Message}");
    }
});
```

## 3. Resumable File Download

### Intermediate Challenge:
**Implement a file download endpoint that supports the Range header for resumable downloads.**

```csharp
// Resumable Download - Intermediate Solution
app.MapGet("/files/download/{filename}", async (string filename, IWebHostEnvironment env, HttpRequest request, HttpResponse response) =>
{
    var filePath = Path.Combine(env.ContentRootPath, "Files", filename);
    
    if (!File.Exists(filePath))
        return Results.NotFound();
    
    var fileInfo = new FileInfo(filePath);
    var length = fileInfo.Length;
    
    response.Headers.ContentDisposition = $"attachment; filename=\"{filename}\"";
    response.Headers.ContentType = "application/octet-stream";
    response.Headers.ContentLength = length;
    response.Headers.AcceptRanges = "bytes";
    
    var rangeHeader = request.Headers.Range.ToString();
    if (!string.IsNullOrEmpty(rangeHeader) && rangeHeader.StartsWith("bytes="))
    {
        var range = RangeHeaderValue.Parse(rangeHeader).Ranges.First();
        var start = range.From ?? 0;
        var end = range.To ?? length - 1;
        
        response.StatusCode = StatusCodes.Status206PartialContent;
        response.Headers.ContentRange = $"bytes {start}-{end}/{length}";
        
        await using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        fileStream.Seek(start, SeekOrigin.Begin);
        
        await fileStream.CopyToAsync(response.Body, (int)(end - start + 1));
    }
    else
    {
        await using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        await fileStream.CopyToAsync(response.Body);
    }
    
    return Results.Empty;
});
```

### Senior Challenge:
**Implement a resumable download system that maintains download state and can resume even after server restart.**

```csharp
// Resumable Download - Senior Solution
app.MapGet("/files/download-resumable/{downloadId}", async (string downloadId, IWebHostEnvironment env, HttpRequest request, HttpResponse response) =>
{
    var statePath = Path.Combine(env.ContentRootPath, "Downloads", $"{downloadId}.state");
    var filePath = Path.Combine(env.ContentRootPath, "Files", $"{downloadId}.data");
    
    if (!File.Exists(filePath))
        return Results.NotFound("File not found");
    
    if (!File.Exists(statePath))
    {
        // Initialize new download
        await File.WriteAllTextAsync(statePath, "0");
    }
    
    var fileInfo = new FileInfo(filePath);
    var length = fileInfo.Length;
    var bytesDownloaded = long.Parse(await File.ReadAllTextAsync(statePath));
    
    response.Headers.ContentDisposition = $"attachment; filename=\"{downloadId}.data\"";
    response.Headers.ContentType = "application/octet-stream";
    response.Headers.ContentLength = length - bytesDownloaded;
    response.Headers.AcceptRanges = "bytes";
    response.Headers.ContentRange = $"bytes {bytesDownloaded}-{length - 1}/{length}";
    response.StatusCode = StatusCodes.Status206PartialContent;
    
    await using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
    fileStream.Seek(bytesDownloaded, SeekOrigin.Begin);
    
    var buffer = new byte[8192];
    int bytesRead;
    long totalRead = bytesDownloaded;
    
    while ((bytesRead = await fileStream.ReadAsync(buffer)) > 0)
    {
        await response.Body.WriteAsync(buffer.AsMemory(0, bytesRead));
        totalRead += bytesRead;
        await File.WriteAllTextAsync(statePath, totalRead.ToString());
    }
    
    // Clean up state file when download completes
    if (totalRead == length)
    {
        File.Delete(statePath);
    }
    
    return Results.Empty;
});
```

## Additional File Handling Challenges

### 4. File Versioning System

**Challenge:** Implement a file storage system that maintains previous versions of files when they're updated.

```csharp
// File Versioning Solution
app.MapPost("/files/versioned-upload", async (IWebHostEnvironment env, HttpRequest request) =>
{
    var fileName = request.Headers["X-File-Name"].ToString();
    if (string.IsNullOrEmpty(fileName))
        return Results.BadRequest("File name header is required");
    
    var filesDir = Path.Combine(env.ContentRootPath, "Files");
    var versionsDir = Path.Combine(env.ContentRootPath, "Versions");
    Directory.CreateDirectory(versionsDir);
    
    var filePath = Path.Combine(filesDir, fileName);
    var versionPattern = $"{fileName}.v*";
    
    try
    {
        // If file exists, create a versioned copy first
        if (File.Exists(filePath))
        {
            var versionFiles = Directory.GetFiles(versionsDir, versionPattern);
            var nextVersion = versionFiles.Length + 1;
            var versionPath = Path.Combine(versionsDir, $"{fileName}.v{nextVersion}");
            File.Copy(filePath, versionPath);
        }
        
        // Write the new file
        using (var fileStream = new FileStream(filePath, FileMode.Create))
        {
            await request.Body.CopyToAsync(fileStream);
        }
        
        return Results.Ok(new { 
            message = "File uploaded successfully",
            versions = Directory.GetFiles(versionsDir, versionPattern).Length
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error uploading file: {ex.Message}");
    }
});
```

### 5. File Encryption/Decryption API

**Challenge:** Create endpoints to encrypt and decrypt files using AES encryption.

```csharp
// File Encryption Solution
app.MapPost("/files/encrypt", async (IWebHostEnvironment env, HttpRequest request) =>
{
    var fileName = request.Headers["X-File-Name"].ToString();
    var password = request.Headers["X-Password"].ToString();
    
    if (string.IsNullOrEmpty(fileName) || string.IsNullOrEmpty(password))
        return Results.BadRequest("File name and password headers are required");
    
    var filePath = Path.Combine(env.ContentRootPath, "Files", fileName);
    var encryptedPath = filePath + ".enc";
    
    if (!File.Exists(filePath))
        return Results.NotFound();
    
    try
    {
        using (var aes = Aes.Create())
        {
            var key = new Rfc2898DeriveBytes(password, aes.IV, 10000);
            aes.Key = key.GetBytes(32);
            
            using (var inputStream = File.OpenRead(filePath))
            using (var outputStream = File.Create(encryptedPath))
            {
                // Write IV first
                await outputStream.WriteAsync(aes.IV);
                
                using (var cryptoStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    await inputStream.CopyToAsync(cryptoStream);
                }
            }
        }
        
        return Results.Ok(new { 
            message = "File encrypted successfully",
            encryptedFile = fileName + ".enc"
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error encrypting file: {ex.Message}");
    }
});

app.MapPost("/files/decrypt", async (IWebHostEnvironment env, HttpRequest request) =>
{
    var fileName = request.Headers["X-File-Name"].ToString();
    var password = request.Headers["X-Password"].ToString();
    
    if (string.IsNullOrEmpty(fileName) || string.IsNullOrEmpty(password))
        return Results.BadRequest("File name and password headers are required");
    
    var filePath = Path.Combine(env.ContentRootPath, "Files", fileName);
    var decryptedPath = filePath.Replace(".enc", "");
    
    if (!File.Exists(filePath))
        return Results.NotFound();
    
    try
    {
        using (var aes = Aes.Create())
        {
            using (var inputStream = File.OpenRead(filePath))
            {
                // Read IV first
                var iv = new byte[aes.IV.Length];
                await inputStream.ReadAsync(iv);
                
                var key = new Rfc2898DeriveBytes(password, iv, 10000);
                aes.Key = key.GetBytes(32);
                aes.IV = iv;
                
                using (var outputStream = File.Create(decryptedPath))
                using (var cryptoStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    await cryptoStream.CopyToAsync(outputStream);
                }
            }
        }
        
        return Results.Ok(new { 
            message = "File decrypted successfully",
            decryptedFile = Path.GetFileName(decryptedPath)
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error decrypting file: {ex.Message}");
    }
});
```

### 6. File Metadata Indexing

**Challenge:** Create an API that indexes file metadata (size, creation date, hash) and allows searching.

```csharp
// File Metadata Indexing Solution
var fileIndex = new ConcurrentDictionary<string, FileMetadata>();

app.MapPost("/files/index", async (IWebHostEnvironment env) =>
{
    var filesDir = Path.Combine(env.ContentRootPath, "Files");
    var files = Directory.GetFiles(filesDir);
    
    foreach (var filePath in files)
    {
        var fileInfo = new FileInfo(filePath);
        using var stream = File.OpenRead(filePath);
        var hash = await ComputeSha256Hash(stream);
        
        fileIndex[Path.GetFileName(filePath)] = new FileMetadata(
            fileInfo.Name,
            fileInfo.Length,
            fileInfo.CreationTimeUtc,
            hash
        );
    }
    
    return Results.Ok(new { count = fileIndex.Count });
});

app.MapGet("/files/search", (string nameContains = null, long? minSize = null, long? maxSize = null) =>
{
    var query = fileIndex.Values.AsQueryable();
    
    if (!string.IsNullOrEmpty(nameContains))
        query = query.Where(f => f.Name.Contains(nameContains, StringComparison.OrdinalIgnoreCase));
    
    if (minSize.HasValue)
        query = query.Where(f => f.Size >= minSize.Value);
    
    if (maxSize.HasValue)
        query = query.Where(f => f.Size <= maxSize.Value);
    
    return Results.Ok(query.ToList());
});

async Task<string> ComputeSha256Hash(Stream stream)
{
    using var sha256 = SHA256.Create();
    stream.Position = 0;
    var hashBytes = await sha256.ComputeHashAsync(stream);
    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
}

record FileMetadata(string Name, long Size, DateTime CreatedAt, string Sha256Hash);
```

### 7. File Change Monitoring

**Challenge:** Implement a system that monitors a directory for changes and provides an API to query recent changes.

```csharp
// File Change Monitoring Solution
var fileChanges = new ConcurrentQueue<FileChangeEvent>();
var watcher = new FileSystemWatcher();

app.MapGet("/files/changes", () => fileChanges.ToArray());

app.MapGet("/files/start-monitoring", (IWebHostEnvironment env) =>
{
    var filesDir = Path.Combine(env.ContentRootPath, "Files");
    
    watcher.Path = filesDir;
    watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size;
    watcher.Filter = "*.*";
    watcher.IncludeSubdirectories = false;
    
    watcher.Changed += (sender, e) => 
        fileChanges.Enqueue(new FileChangeEvent(e.FullPath, "Changed", DateTime.UtcNow));
    watcher.Created += (sender, e) => 
        fileChanges.Enqueue(new FileChangeEvent(e.FullPath, "Created", DateTime.UtcNow));
    watcher.Deleted += (sender, e) => 
        fileChanges.Enqueue(new FileChangeEvent(e.FullPath, "Deleted", DateTime.UtcNow));
    watcher.Renamed += (sender, e) => 
        fileChanges.Enqueue(new FileChangeEvent(e.FullPath, $"Renamed from {e.OldName}", DateTime.UtcNow));
    
    watcher.EnableRaisingEvents = true;
    
    return Results.Ok("Monitoring started");
});

app.MapGet("/files/stop-monitoring", () =>
{
    watcher.EnableRaisingEvents = false;
    return Results.Ok("Monitoring stopped");
});

record FileChangeEvent(string FilePath, string ChangeType, DateTime Timestamp);
```

### 8. File Compression API

**Challenge:** Create endpoints to compress and decompress files using GZip.

```csharp
// File Compression Solution
app.MapPost("/files/compress", async (IWebHostEnvironment env, HttpRequest request) =>
{
    var fileName = request.Headers["X-File-Name"].ToString();
    if (string.IsNullOrEmpty(fileName))
        return Results.BadRequest("File name header is required");
    
    var filePath = Path.Combine(env.ContentRootPath, "Files", fileName);
    var compressedPath = filePath + ".gz";
    
    if (!File.Exists(filePath))
        return Results.NotFound();
    
    try
    {
        await using var inputStream = File.OpenRead(filePath);
        await using var outputStream = File.Create(compressedPath);
        await using var gzipStream = new GZipStream(outputStream, CompressionLevel.Optimal);
        
        await inputStream.CopyToAsync(gzipStream);
        
        return Results.Ok(new { 
            message = "File compressed successfully",
            compressedFile = fileName + ".gz",
            originalSize = inputStream.Length,
            compressedSize = outputStream.Length
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error compressing file: {ex.Message}");
    }
});

app.MapPost("/files/decompress", async (IWebHostEnvironment env, HttpRequest request) =>
{
    var fileName = request.Headers["X-File-Name"].ToString();
    if (string.IsNullOrEmpty(fileName))
        return Results.BadRequest("File name header is required");
    
    if (!fileName.EndsWith(".gz"))
        return Results.BadRequest("File must have .gz extension");
    
    var filePath = Path.Combine(env.ContentRootPath, "Files", fileName);
    var decompressedPath = Path.ChangeExtension(filePath, null);
    
    if (!File.Exists(filePath))
        return Results.NotFound();
    
    try
    {
        await using var inputStream = File.OpenRead(filePath);
        await using var gzipStream = new GZipStream(inputStream, CompressionMode.Decompress);
        await using var outputStream = File.Create(decompressedPath);
        
        await gzipStream.CopyToAsync(outputStream);
        
        return Results.Ok(new { 
            message = "File decompressed successfully",
            decompressedFile = Path.GetFileName(decompressedPath)
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error decompressing file: {ex.Message}");
    }
});
```

### 9. File Upload with Virus Scanning

**Challenge:** Implement a file upload endpoint that scans files for viruses using a mock scanning service.

```csharp
// File Upload with Virus Scanning Solution
app.MapPost("/files/upload-safe", async (IWebHostEnvironment env, HttpRequest request) =>
{
    var fileName = request.Headers["X-File-Name"].ToString();
    if (string.IsNullOrEmpty(fileName))
        return Results.BadRequest("File name header is required");
    
    var filePath = Path.Combine(env.ContentRootPath, "Files", fileName);
    var tempPath = Path.Combine(env.ContentRootPath, "Temp", fileName);
    
    Directory.CreateDirectory(Path.GetDirectoryName(tempPath)!);
    
    try
    {
        // Save to temp location first
        await using (var tempStream = File.Create(tempPath))
        {
            await request.Body.CopyToAsync(tempStream);
        }
        
        // Scan for viruses (mock service)
        var scanResult = await ScanForViruses(tempPath);
        if (scanResult.IsMalicious)
        {
            File.Delete(tempPath);
            return Results.BadRequest($"File rejected: {scanResult.Details}");
        }
        
        // Move to final location
        if (File.Exists(filePath))
            File.Delete(filePath);
        File.Move(tempPath, filePath);
        
        return Results.Ok(new { 
            message = "File uploaded and scanned successfully",
            fileName,
            scanResult
        });
    }
    catch (Exception ex)
    {
        if (File.Exists(tempPath))
            File.Delete(tempPath);
        return Results.Problem($"Error uploading file: {ex.Message}");
    }
});

async Task<ScanResult> ScanForViruses(string filePath)
{
    // Mock scanning - in real app this would call a virus scanning service
    await Task.Delay(100); // Simulate scanning delay
    
    var fileExtension = Path.GetExtension(filePath).ToLower();
    var random = new Random();
    
    // 5% chance of being flagged as malicious for demonstration
    if (random.Next(100) < 5)
    {
        return new ScanResult(true, "File matches known malware signature");
    }
    
    // Flag certain extensions as suspicious
    if (new[] { ".exe", ".dll", ".bat", ".ps1" }.Contains(fileExtension))
    {
        return new ScanResult(false, "Potentially risky file type");
    }
    
    return new ScanResult(false, "File appears clean");
}

record ScanResult(bool IsMalicious, string Details);
```

### 10. Distributed File Locking System

**Challenge:** Implement a file locking mechanism that works across multiple server instances using a shared database.

```csharp
// Distributed File Locking Solution
app.MapPost("/files/lock", async (string filename, IWebHostEnvironment env, AppDbContext db) =>
{
    var filePath = Path.Combine(env.ContentRootPath, "Files", filename);
    
    if (!File.Exists(filePath))
        return Results.NotFound();
    
    var existingLock = await db.FileLocks.FindAsync(filename);
    if (existingLock != null)
    {
        if (existingLock.ExpiresAt > DateTime.UtcNow)
            return Results.Conflict($"File is locked by {existingLock.LockedBy} until {existingLock.ExpiresAt}");
        
        // Clean up expired lock
        db.FileLocks.Remove(existingLock);
    }
    
    var fileLock = new FileLock
    {
        FileName = filename,
        LockedBy = Environment.MachineName,
        LockedAt = DateTime.UtcNow,
        ExpiresAt = DateTime.UtcNow.AddMinutes(5)
    };
    
    db.FileLocks.Add(fileLock);
    await db.SaveChangesAsync();
    
    return Results.Ok(new { 
        message = "File locked successfully",
        expiresAt = fileLock.ExpiresAt
    });
});

app.MapPost("/files/unlock", async (string filename, AppDbContext db) =>
{
    var fileLock = await db.FileLocks.FindAsync(filename);
    if (fileLock == null)
        return Results.NotFound("No active lock found");
    
    if (fileLock.LockedBy != Environment.MachineName)
        return Results.Forbid();
    
    db.FileLocks.Remove(fileLock);
    await db.SaveChangesAsync();
    
    return Results.Ok("File unlocked successfully");
});

app.MapPost("/files/write-with-lock", async (string filename, IWebHostEnvironment env, AppDbContext db, HttpRequest request) =>
{
    // Try to acquire lock
    var lockResult = await app.PostAsJsonAsync($"/files/lock?filename={filename}", new {});
    
    if (lockResult.StatusCode == StatusCodes.Status409Conflict)
    {
        var content = await lockResult.Content.ReadAsStringAsync();
        return Results.Conflict(content);
    }
    
    try
    {
        var filePath = Path.Combine(env.ContentRootPath, "Files", filename);
        await using var fileStream = File.Create(filePath);
        await request.Body.CopyToAsync(fileStream);
        
        return Results.Ok("File written successfully with lock");
    }
    finally
    {
        // Release lock
        await app.DeleteAsync($"/files/unlock?filename={filename}");
    }
});

// Database context and model
class AppDbContext : DbContext
{
    public DbSet<FileLock> FileLocks { get; set; }
    
    protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite("Data Source=filelocks.db");
}

class FileLock
{
    public string FileName { get; set; }
    public string LockedBy { get; set; }
    public DateTime LockedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    
    [Key]
    public string FileName { get; set; }
}
```

These challenges cover a wide range of file handling scenarios in ASP.NET Core Minimal APIs, from basic operations to advanced distributed systems concerns. Each solution includes error handling and demonstrates best practices for file operations in web applications.
