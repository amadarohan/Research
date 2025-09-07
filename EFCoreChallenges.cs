# Entity Framework Core Mastery Challenges

Here are 15 intermediate to senior-level code challenges that will help you master Entity Framework Core concepts from the document. These challenges cover change tracking, relationships, query performance, concurrency, and advanced patterns.

## Challenge 1: Change Tracking and Entity States

**Problem**: Create a method that demonstrates the difference between `Update()` and `Attach()` methods in a disconnected scenario. The method should show how each approach affects the generated SQL.

**Solution**:
```csharp
public class ChangeTrackingService
{
    private readonly AppDbContext _context;

    public ChangeTrackingService(AppDbContext context)
    {
        _context = context;
    }

    public void DemonstrateUpdateVsAttach()
    {
        // Create a disconnected entity
        var author = new Author { AuthorId = 1, Name = "Updated Name", Bio = "Original Bio" };
        
        // Scenario 1: Using Update() - marks all properties as modified
        _context.Authors.Update(author);
        Console.WriteLine($"After Update - State: {_context.Entry(author).State}");
        _context.SaveChanges(); // Will update ALL columns
        _context.ChangeTracker.Clear();
        
        // Scenario 2: Using Attach() + manual modification
        var author2 = new Author { AuthorId = 1, Name = "Updated Name", Bio = "Original Bio" };
        _context.Authors.Attach(author2);
        Console.WriteLine($"After Attach - State: {_context.Entry(author2).State}");
        
        // Mark only Name as modified
        _context.Entry(author2).Property(a => a.Name).IsModified = true;
        Console.WriteLine($"After marking Name modified - State: {_context.Entry(author2).State}");
        _context.SaveChanges(); // Will update only Name column
    }
}
```

## Challenge 2: Many-to-Many with Payload Configuration

**Problem**: Implement a many-to-many relationship between Books and Authors with a payload (Order property) to track the author order for each book.

**Solution**:
```csharp
// Entity Classes
public class Book
{
    public int BookId { get; set; }
    public string Title { get; set; }
    public ICollection<BookAuthor> AuthorsLink { get; set; }
}

public class Author
{
    public int AuthorId { get; set; }
    public string Name { get; set; }
    public ICollection<BookAuthor> BooksLink { get; set; }
}

public class BookAuthor
{
    public int BookId { get; set; }
    public Book Book { get; set; }
    
    public int AuthorId { get; set; }
    public Author Author { get; set; }
    
    public byte Order { get; set; } // Payload property
}

// DbContext Configuration
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<BookAuthor>()
        .HasKey(ba => new { ba.BookId, ba.AuthorId });
    
    modelBuilder.Entity<BookAuthor>()
        .HasOne(ba => ba.Book)
        .WithMany(b => b.AuthorsLink)
        .HasForeignKey(ba => ba.BookId);
    
    modelBuilder.Entity<BookAuthor>()
        .HasOne(ba => ba.Author)
        .WithMany(a => a.BooksLink)
        .HasForeignKey(ba => ba.AuthorId);
}

// Service method to add authors with order
public void AddAuthorsToBook(int bookId, Dictionary<int, byte> authorOrders)
{
    var book = _context.Books
        .Include(b => b.AuthorsLink)
        .FirstOrDefault(b => b.BookId == bookId);
    
    if (book != null)
    {
        // Clear existing authors
        book.AuthorsLink.Clear();
        
        // Add authors with specified order
        foreach (var authorOrder in authorOrders)
        {
            var author = _context.Authors.Find(authorOrder.Key);
            if (author != null)
            {
                book.AuthorsLink.Add(new BookAuthor
                {
                    Book = book,
                    Author = author,
                    Order = authorOrder.Value
                });
            }
        }
        
        _context.SaveChanges();
    }
}
```

## Challenge 3: Solving N+1 Query Problem

**Problem**: Identify and fix N+1 query issues in a method that loads books and their reviews.

**Solution**:
```csharp
// Problematic method with N+1 issue
public List<Book> GetBooksWithReviewsBad()
{
    var books = _context.Books.ToList(); // 1 query
    
    foreach (var book in books)
    {
        // N queries (one for each book)
        _context.Entry(book)
            .Collection(b => b.Reviews)
            .Load();
    }
    
    return books;
}

// Fixed method with eager loading
public List<Book> GetBooksWithReviewsGood()
{
    return _context.Books
        .Include(b => b.Reviews) // Single query with join
        .ToList();
}

// Even better: Projection to DTO for read-only scenario
public List<BookReviewDto> GetBooksWithReviewsBest()
{
    return _context.Books
        .Select(b => new BookReviewDto
        {
            BookId = b.BookId,
            Title = b.Title,
            Reviews = b.Reviews.Select(r => new ReviewDto
            {
                ReviewId = r.ReviewId,
                Comment = r.Comment,
                Rating = r.Rating
            }).ToList()
        })
        .AsNoTracking() // No change tracking needed for read-only
        .ToList();
}
```

## Challenge 4: Optimistic Concurrency Implementation

**Problem**: Implement optimistic concurrency control using a timestamp/rowversion property.

**Solution**:
```csharp
// Entity with concurrency token
public class Product
{
    public int ProductId { get; set; }
    public string Name { get; set; }
    public decimal Price { get; set; }
    
    [Timestamp]
    public byte[] RowVersion { get; set; }
}

// Service method handling concurrency conflicts
public async Task<UpdateResult> UpdateProductPrice(int productId, decimal newPrice)
{
    try
    {
        var product = await _context.Products.FindAsync(productId);
        if (product == null)
            return UpdateResult.NotFound;
        
        product.Price = newPrice;
        await _context.SaveChangesAsync();
        
        return UpdateResult.Success;
    }
    catch (DbUpdateConcurrencyException ex)
    {
        // Handle concurrency conflict
        var entry = ex.Entries.Single();
        var databaseValues = await entry.GetDatabaseValuesAsync();
        
        if (databaseValues == null)
        {
            return UpdateResult.Deleted; // Entity was deleted
        }
        
        // You can implement different resolution strategies:
        // 1. Client wins - force the update
        // entry.OriginalValues.SetValues(databaseValues);
        // await _context.SaveChangesAsync();
        
        // 2. Database wins - discard changes
        // entry.CurrentValues.SetValues(databaseValues);
        
        // 3. Custom merge logic
        var dbProduct = (Product)databaseValues.ToObject();
        var currentProduct = (Product)entry.Entity;
        
        // Custom merge strategy - in this case, take the higher price
        currentProduct.Price = Math.Max(currentProduct.Price, dbProduct.Price);
        
        // Update original values to match database
        entry.OriginalValues.SetValues(databaseValues);
        
        // Retry the save
        await _context.SaveChangesAsync();
        
        return UpdateResult.Merged;
    }
}

public enum UpdateResult { Success, NotFound, Deleted, Merged }
```

## Challenge 5: Complex Query with Projection

**Problem**: Create an optimized query that projects data into a DTO with data from multiple related entities.

**Solution**:
```csharp
public class BookDetailDto
{
    public int BookId { get; set; }
    public string Title { get; set; }
    public decimal Price { get; set; }
    public string PublisherName { get; set; }
    public List<AuthorDto> Authors { get; set; }
    public double AverageRating { get; set; }
    public int ReviewCount { get; set; }
}

public class AuthorDto
{
    public int AuthorId { get; set; }
    public string Name { get; set; }
    public byte Order { get; set; }
}

public IQueryable<BookDetailDto> GetBookDetails()
{
    return _context.Books
        .Select(b => new BookDetailDto
        {
            BookId = b.BookId,
            Title = b.Title,
            Price = b.Price,
            PublisherName = b.Publisher.Name,
            Authors = b.AuthorsLink
                .OrderBy(ba => ba.Order)
                .Select(ba => new AuthorDto
                {
                    AuthorId = ba.Author.AuthorId,
                    Name = ba.Author.Name,
                    Order = ba.Order
                }).ToList(),
            AverageRating = b.Reviews.Average(r => (double?)r.Rating) ?? 0,
            ReviewCount = b.Reviews.Count
        })
        .AsNoTracking();
}

// Usage with filtering and paging
public PaginatedResult<BookDetailDto> GetBooksByCategory(int categoryId, int page, int pageSize)
{
    var query = GetBookDetails()
        .Where(b => b.CategoryId == categoryId)
        .OrderBy(b => b.Title);
    
    var totalCount = query.Count();
    var items = query
        .Skip((page - 1) * pageSize)
        .Take(pageSize)
        .ToList();
    
    return new PaginatedResult<BookDetailDto>(items, totalCount, page, pageSize);
}
```

## Challenge 6: Batch Processing with Bulk Operations

**Problem**: Implement efficient batch operations for large data sets without loading all entities into memory.

**Solution**:
```csharp
public async Task BulkUpdatePrices(decimal percentageIncrease)
{
    // For small to medium batches, use ExecuteSqlRaw
    var multiplier = 1 + (percentageIncrease / 100);
    var rowsAffected = await _context.Database.ExecuteSqlRawAsync(
        "UPDATE Products SET Price = Price * {0} WHERE CategoryId = {1}",
        multiplier, 5);
    
    Console.WriteLine($"Updated {rowsAffected} products");
}

// For very large operations, consider using a library like EF Core.BulkExtensions
// or raw ADO.NET with batches

public async Task<int> ProcessLargeDatasetInBatches(Func<Product, bool> processingFunc)
{
    int processedCount = 0;
    int batchSize = 1000;
    int skip = 0;
    
    List<Product> batch;
    do
    {
        // Get batch of products
        batch = await _context.Products
            .OrderBy(p => p.ProductId)
            .Skip(skip)
            .Take(batchSize)
            .AsNoTracking()
            .ToListAsync();
        
        foreach (var product in batch)
        {
            if (processingFunc(product))
            {
                // For updates, you might use a different approach
                // like collecting IDs and doing bulk update
                processedCount++;
            }
        }
        
        skip += batchSize;
    } while (batch.Count == batchSize);
    
    return processedCount;
}
```

## Challenge 7: Global Query Filters

**Problem**: Implement soft delete pattern using global query filters and ensure they work correctly with includes.

**Solution**:
```csharp
// Entity with soft delete
public class Product
{
    public int ProductId { get; set; }
    public string Name { get; set; }
    public bool IsDeleted { get; set; }
    public DateTime? DeletedAt { get; set; }
}

// DbContext configuration
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<Product>()
        .HasQueryFilter(p => !p.IsDeleted);
}

// Service methods
public void SoftDeleteProduct(int productId)
{
    var product = _context.Products.Find(productId);
    if (product != null)
    {
        product.IsDeleted = true;
        product.DeletedAt = DateTime.UtcNow;
        _context.SaveChanges();
    }
}

// Method to temporarily ignore the filter
public Product GetProductWithIncludes(int productId, bool includeDeleted = false)
{
    var query = _context.Products.AsQueryable();
    
    if (includeDeleted)
    {
        query = query.IgnoreQueryFilters();
    }
    
    return query
        .Include(p => p.Category)
        .FirstOrDefault(p => p.ProductId == productId);
}

// Method to get all products including deleted (for admin purposes)
public List<Product> GetAllProducts(bool includeDeleted = false)
{
    var query = _context.Products.AsQueryable();
    
    if (includeDeleted)
    {
        query = query.IgnoreQueryFilters();
    }
    
    return query.ToList();
}
```

## Challenge 8: Complex Migration with Data Transformation

**Problem**: Create a migration that involves schema changes and data transformation.

**Solution**:
```csharp
// Migration file (partial)
public partial class SplitNameColumn : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Add new columns
        migrationBuilder.AddColumn<string>(
            name: "FirstName",
            table: "Authors",
            nullable: true);
            
        migrationBuilder.AddColumn<string>(
            name: "LastName",
            table: "Authors",
            nullable: true);
        
        // Data transformation: Split existing Name into FirstName and LastName
        migrationBuilder.Sql(@"
            UPDATE Authors 
            SET FirstName = SUBSTRING(Name, 1, CHARINDEX(' ', Name) - 1),
                LastName = SUBSTRING(Name, CHARINDEX(' ', Name) + 1, LEN(Name))
            WHERE CHARINDEX(' ', Name) > 0
        ");
        
        // For names without spaces, put everything in FirstName
        migrationBuilder.Sql(@"
            UPDATE Authors 
            SET FirstName = Name,
                LastName = ''
            WHERE CHARINDEX(' ', Name) = 0 OR Name IS NULL
        ");
        
        // Make new columns required and drop old column
        migrationBuilder.AlterColumn<string>(
            name: "FirstName",
            table: "Authors",
            nullable: false);
            
        migrationBuilder.AlterColumn<string>(
            name: "LastName",
            table: "Authors",
            nullable: false);
            
        migrationBuilder.DropColumn(
            name: "Name",
            table: "Authors");
    }
    
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        // Reverse the changes
        migrationBuilder.AddColumn<string>(
            name: "Name",
            table: "Authors",
            nullable: true);
            
        migrationBuilder.Sql(@"
            UPDATE Authors 
            SET Name = CONCAT(FirstName, ' ', LastName)
        ");
        
        migrationBuilder.DropColumn(
            name: "FirstName",
            table: "Authors");
            
        migrationBuilder.DropColumn(
            name: "LastName",
            table: "Authors");
    }
}
```

## Challenge 9: Implementing a Repository Pattern with Unit of Work

**Problem**: Create a generic repository and unit of work pattern that works with EF Core.

**Solution**:
```csharp
public interface IRepository<T> where T : class
{
    Task<T> GetByIdAsync(int id);
    IQueryable<T> GetAll();
    void Add(T entity);
    void Update(T entity);
    void Delete(T entity);
    Task<bool> ExistsAsync(int id);
}

public class Repository<T> : IRepository<T> where T : class
{
    private readonly AppDbContext _context;
    private readonly DbSet<T> _dbSet;

    public Repository(AppDbContext context)
    {
        _context = context;
        _dbSet = context.Set<T>();
    }

    public async Task<T> GetByIdAsync(int id) => await _dbSet.FindAsync(id);

    public IQueryable<T> GetAll() => _dbSet.AsQueryable();

    public void Add(T entity) => _dbSet.Add(entity);

    public void Update(T entity) => _dbSet.Update(entity);

    public void Delete(T entity) => _dbSet.Remove(entity);

    public async Task<bool> ExistsAsync(int id) => await GetByIdAsync(id) != null;
}

public interface IUnitOfWork : IDisposable
{
    IRepository<Book> Books { get; }
    IRepository<Author> Authors { get; }
    IRepository<Publisher> Publishers { get; }
    Task<int> CommitAsync();
}

public class UnitOfWork : IUnitOfWork
{
    private readonly AppDbContext _context;
    
    public UnitOfWork(AppDbContext context)
    {
        _context = context;
        Books = new Repository<Book>(context);
        Authors = new Repository<Author>(context);
        Publishers = new Repository<Publisher>(context);
    }
    
    public IRepository<Book> Books { get; }
    public IRepository<Author> Authors { get; }
    public IRepository<Publisher> Publishers { get; }
    
    public async Task<int> CommitAsync() => await _context.SaveChangesAsync();
    
    public void Dispose() => _context.Dispose();
}

// Usage in service
public class BookService
{
    private readonly IUnitOfWork _unitOfWork;
    
    public BookService(IUnitOfWork unitOfWork)
    {
        _unitOfWork = unitOfWork;
    }
    
    public async Task<Book> AddBookWithAuthor(Book book, int authorId)
    {
        var author = await _unitOfWork.Authors.GetByIdAsync(authorId);
        if (author == null)
            throw new ArgumentException("Author not found");
        
        book.AuthorsLink = new List<BookAuthor>
        {
            new BookAuthor { Book = book, Author = author, Order = 1 }
        };
        
        _unitOfWork.Books.Add(book);
        await _unitOfWork.CommitAsync();
        
        return book;
    }
}
```

## Challenge 10: Advanced Raw SQL with Dynamic Queries

**Problem**: Create a method that builds dynamic SQL queries safely to avoid SQL injection.

**Solution**:
```csharp
public class DynamicQueryService
{
    private readonly AppDbContext _context;
    
    public DynamicQueryService(AppDbContext context)
    {
        _context = context;
    }
    
    public async Task<List<Book>> SearchBooksAsync(BookSearchCriteria criteria)
    {
        var query = "SELECT * FROM Books WHERE 1 = 1";
        var parameters = new List<object>();
        var paramIndex = 0;
        
        if (!string.IsNullOrEmpty(criteria.Title))
        {
            query += $" AND Title LIKE {{{paramIndex}}}";
            parameters.Add($"%{criteria.Title}%");
            paramIndex++;
        }
        
        if (criteria.MinPrice.HasValue)
        {
            query += $" AND Price >= {{{paramIndex}}}";
            parameters.Add(criteria.MinPrice.Value);
            paramIndex++;
        }
        
        if (criteria.MaxPrice.HasValue)
        {
            query += $" AND Price <= {{{paramIndex}}}";
            parameters.Add(criteria.MaxPrice.Value);
            paramIndex++;
        }
        
        if (criteria.CategoryIds?.Any() == true)
        {
            var categoryParams = new List<string>();
            foreach (var categoryId in criteria.CategoryIds)
            {
                categoryParams.Add($"{{{paramIndex}}}");
                parameters.Add(categoryId);
                paramIndex++;
            }
            
            query += $" AND CategoryId IN ({string.Join(",", categoryParams)})";
        }
        
        // Add ordering
        query += criteria.SortBy switch
        {
            "price" => " ORDER BY Price",
            "title" => " ORDER BY Title",
            "published" => " ORDER BY PublishedDate DESC",
            _ => " ORDER BY Title"
        };
        
        return await _context.Books
            .FromSqlRaw(query, parameters.ToArray())
            .AsNoTracking()
            .ToListAsync();
    }
}

public class BookSearchCriteria
{
    public string Title { get; set; }
    public decimal? MinPrice { get; set; }
    public decimal? MaxPrice { get; set; }
    public List<int> CategoryIds { get; set; }
    public string SortBy { get; set; } = "title";
}
```

## Challenge 11: Implementing Value Objects with Owned Types

**Problem**: Implement value objects using EF Core's owned types feature.

**Solution**:
```csharp
// Value objects
public class Money
{
    public decimal Amount { get; private set; }
    public string Currency { get; private set; }
    
    private Money() { } // For EF Core
    
    public Money(decimal amount, string currency)
    {
        if (amount < 0) throw new ArgumentException("Amount cannot be negative");
        if (string.IsNullOrEmpty(currency)) throw new ArgumentException("Currency is required");
        
        Amount = amount;
        Currency = currency;
    }
    
    public Money ConvertTo(string targetCurrency, decimal exchangeRate)
    {
        return new Money(Amount * exchangeRate, targetCurrency);
    }
}

public class Address
{
    public string Street { get; private set; }
    public string City { get; private set; }
    public string ZipCode { get; private set; }
    public string Country { get; private set; }
    
    private Address() { } // For EF Core
    
    public Address(string street, string city, string zipCode, string country)
    {
        Street = street;
        City = city;
        ZipCode = zipCode;
        Country = country;
    }
}

// Entity using value objects
public class Order
{
    public int OrderId { get; set; }
    public DateTime OrderDate { get; set; }
    
    // Owned types
    public Address ShippingAddress { get; set; }
    public Address BillingAddress { get; set; }
    public Money TotalAmount { get; set; }
}

// DbContext configuration
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<Order>(entity =>
    {
        entity.OwnsOne(o => o.ShippingAddress, address =>
        {
            address.Property(a => a.Street).HasColumnName("ShippingStreet");
            address.Property(a => a.City).HasColumnName("ShippingCity");
            address.Property(a => a.ZipCode).HasColumnName("ShippingZipCode");
            address.Property(a => a.Country).HasColumnName("ShippingCountry");
        });
        
        entity.OwnsOne(o => o.BillingAddress, address =>
        {
            address.Property(a => a.Street).HasColumnName("BillingStreet");
            address.Property(a => a.City).HasColumnName("BillingCity");
            address.Property(a => a.ZipCode).HasColumnName("BillingZipCode");
            address.Property(a => a.Country).HasColumnName("BillingCountry");
        });
        
        entity.OwnsOne(o => o.TotalAmount, money =>
        {
            money.Property(m => m.Amount).HasColumnName("TotalAmount");
            money.Property(m => m.Currency).HasColumnName("Currency");
        });
    });
}
```

## Challenge 12: Implementing Domain Events Pattern

**Problem**: Implement a domain events pattern to handle side effects after saving changes.

**Solution**:
```csharp
public interface IDomainEvent
{
    DateTime OccurredOn { get; }
}

public abstract class Entity
{
    private List<IDomainEvent> _domainEvents = new List<IDomainEvent>();
    
    public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();
    
    public void AddDomainEvent(IDomainEvent eventItem) => _domainEvents.Add(eventItem);
    
    public void RemoveDomainEvent(IDomainEvent eventItem) => _domainEvents.Remove(eventItem);
    
    public void ClearDomainEvents() => _domainEvents.Clear();
}

// Domain events
public record BookPriceChangedEvent(int BookId, decimal OldPrice, decimal NewPrice) : IDomainEvent
{
    public DateTime OccurredOn { get; } = DateTime.UtcNow;
}

public record LowStockEvent(int ProductId, int CurrentStock) : IDomainEvent
{
    public DateTime OccurredOn { get; } = DateTime.UtcNow;
}

// Entity with domain events
public class Book : Entity
{
    public int BookId { get; set; }
    public string Title { get; set; }
    
    private decimal _price;
    public decimal Price
    {
        get => _price;
        set
        {
            if (_price != value)
            {
                var oldPrice = _price;
                _price = value;
                AddDomainEvent(new BookPriceChangedEvent(BookId, oldPrice, value));
            }
        }
    }
}

// DbContext that dispatches domain events
public class AppDbContext : DbContext
{
    private readonly IDomainEventDispatcher _domainEventDispatcher;
    
    public AppDbContext(DbContextOptions<AppDbContext> options, 
                       IDomainEventDispatcher domainEventDispatcher)
        : base(options)
    {
        _domainEventDispatcher = domainEventDispatcher;
    }
    
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        // Get entities with domain events
        var entitiesWithEvents = ChangeTracker.Entries<Entity>()
            .Select(e => e.Entity)
            .Where(e => e.DomainEvents.Any())
            .ToArray();
        
        // Save changes first
        var result = await base.SaveChangesAsync(cancellationToken);
        
        // Dispatch domain events after saving
        foreach (var entity in entitiesWithEvents)
        {
            var events = entity.DomainEvents.ToArray();
            entity.ClearDomainEvents();
            
            foreach (var domainEvent in events)
            {
                await _domainEventDispatcher.Dispatch(domainEvent);
            }
        }
        
        return result;
    }
}

// Domain event dispatcher
public interface IDomainEventDispatcher
{
    Task Dispatch(IDomainEvent domainEvent);
}

public class DomainEventDispatcher : IDomainEventDispatcher
{
    private readonly IServiceProvider _serviceProvider;
    
    public DomainEventDispatcher(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }
    
    public async Task Dispatch(IDomainEvent domainEvent)
    {
        var handlerType = typeof(IDomainEventHandler<>).MakeGenericType(domainEvent.GetType());
        
        using var scope = _serviceProvider.CreateScope();
        var handlers = scope.ServiceProvider.GetServices(handlerType);
        
        foreach (var handler in handlers)
        {
            var method = handlerType.GetMethod("Handle");
            await (Task)method.Invoke(handler, new object[] { domainEvent });
        }
    }
}

// Event handlers
public interface IDomainEventHandler<T> where T : IDomainEvent
{
    Task Handle(T domainEvent);
}

public class PriceChangeNotificationHandler : IDomainEventHandler<BookPriceChangedEvent>
{
    public async Task Handle(BookPriceChangedEvent domainEvent)
    {
        // Send notification, update cache, etc.
        Console.WriteLine($"Price changed for book {domainEvent.BookId}: " +
                         $"{domainEvent.OldPrice} -> {domainEvent.NewPrice}");
        await Task.CompletedTask;
    }
}
```

## Challenge 13: Implementing CQRS Pattern with EF Core

**Problem**: Implement a simple CQRS pattern with separate query and command handlers.

**Solution**:
```csharp
// Queries
public record GetBookQuery(int BookId) : IRequest<BookDto>;
public record SearchBooksQuery(string SearchTerm, int Page, int PageSize) : IRequest<PaginatedResult<BookDto>>;

// Commands
public record CreateBookCommand(string Title, decimal Price, int[] AuthorIds) : IRequest<int>;
public record UpdateBookPriceCommand(int BookId, decimal NewPrice) : IRequest;

// Query handlers
public class GetBookQueryHandler : IRequestHandler<GetBookQuery, BookDto>
{
    private readonly AppDbContext _context;
    private readonly IMapper _mapper;
    
    public GetBookQueryHandler(AppDbContext context, IMapper mapper)
    {
        _context = context;
        _mapper = mapper;
    }
    
    public async Task<BookDto> Handle(GetBookQuery request, CancellationToken cancellationToken)
    {
        var book = await _context.Books
            .Include(b => b.AuthorsLink)
            .ThenInclude(ba => ba.Author)
            .AsNoTracking()
            .FirstOrDefaultAsync(b => b.BookId == request.BookId, cancellationToken);
        
        return _mapper.Map<BookDto>(book);
    }
}

public class SearchBooksQueryHandler : IRequestHandler<SearchBooksQuery, PaginatedResult<BookDto>>
{
    private readonly AppDbContext _context;
    private readonly IMapper _mapper;
    
    public SearchBooksQueryHandler(AppDbContext context, IMapper mapper)
    {
        _context = context;
        _mapper = mapper;
    }
    
    public async Task<PaginatedResult<BookDto>> Handle(SearchBooksQuery request, CancellationToken cancellationToken)
    {
        var query = _context.Books
            .Where(b => b.Title.Contains(request.SearchTerm))
            .OrderBy(b => b.Title);
        
        var totalCount = await query.CountAsync(cancellationToken);
        var books = await query
            .Skip((request.Page - 1) * request.PageSize)
            .Take(request.PageSize)
            .AsNoTracking()
            .ToListAsync(cancellationToken);
        
        var bookDtos = _mapper.Map<List<BookDto>>(books);
        
        return new PaginatedResult<BookDto>(bookDtos, totalCount, request.Page, request.PageSize);
    }
}

// Command handlers
public class CreateBookCommandHandler : IRequestHandler<CreateBookCommand, int>
{
    private readonly AppDbContext _context;
    
    public CreateBookCommandHandler(AppDbContext context)
    {
        _context = context;
    }
    
    public async Task<int> Handle(CreateBookCommand request, CancellationToken cancellationToken)
    {
        var book = new Book
        {
            Title = request.Title,
            Price = request.Price,
            AuthorsLink = new List<BookAuthor>()
        };
        
        byte order = 1;
        foreach (var authorId in request.AuthorIds)
        {
            var author = await _context.Authors.FindAsync(authorId);
            if (author != null)
            {
                book.AuthorsLink.Add(new BookAuthor
                {
                    Author = author,
                    Order = order++
                });
            }
        }
        
        _context.Books.Add(book);
        await _context.SaveChangesAsync(cancellationToken);
        
        return book.BookId;
    }
}

public class UpdateBookPriceCommandHandler : IRequestHandler<UpdateBookPriceCommand>
{
    private readonly AppDbContext _context;
    
    public UpdateBookPriceCommandHandler(AppDbContext context)
    {
        _context = context;
    }
    
    public async Task Handle(UpdateBookPriceCommand request, CancellationToken cancellationToken)
    {
        var book = await _context.Books.FindAsync(request.BookId);
        if (book != null)
        {
            book.Price = request.NewPrice;
            await _context.SaveChangesAsync(cancellationToken);
        }
    }
}

// Mediatr registration in Startup.cs
services.AddMediatR(typeof(Startup));
```

## Challenge 14: Implementing Multi-Tenancy with EF Core

**Problem**: Implement a multi-tenancy solution using EF Core's global query filters.

**Solution**:
```csharp
public interface ITenantProvider
{
    int GetTenantId();
}

public class HttpContextTenantProvider : ITenantProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    
    public HttpContextTenantProvider(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    
    public int GetTenantId()
    {
        // Extract tenant ID from HTTP context (header, claim, subdomain, etc.)
        var tenantIdHeader = _httpContextAccessor.HttpContext.Request.Headers["X-Tenant-Id"];
        if (int.TryParse(tenantIdHeader, out int tenantId))
        {
            return tenantId;
        }
        
        throw new UnauthorizedAccessException("Tenant ID not specified or invalid");
    }
}

// Tenant-aware entities
public interface ITenantEntity
{
    int TenantId { get; set; }
}

public class Product : ITenantEntity
{
    public int ProductId { get; set; }
    public string Name { get; set; }
    public decimal Price { get; set; }
    public int TenantId { get; set; }
}

public class Order : ITenantEntity
{
    public int OrderId { get; set; }
    public DateTime OrderDate { get; set; }
    public decimal TotalAmount { get; set; }
    public int TenantId { get; set; }
    
    public ICollection<OrderItem> OrderItems { get; set; }
}

// DbContext with multi-tenancy
public class AppDbContext : DbContext
{
    private readonly ITenantProvider _tenantProvider;
    
    public AppDbContext(DbContextOptions<AppDbContext> options, ITenantProvider tenantProvider)
        : base(options)
    {
        _tenantProvider = tenantProvider;
    }
    
    public DbSet<Product> Products { get; set; }
    public DbSet<Order> Orders { get; set; }
    public DbSet<OrderItem> OrderItems { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Apply global query filter for multi-tenancy
        modelBuilder.Entity<Product>().HasQueryFilter(p => p.TenantId == _tenantProvider.GetTenantId());
        modelBuilder.Entity<Order>().HasQueryFilter(o => o.TenantId == _tenantProvider.GetTenantId());
        modelBuilder.Entity<OrderItem>().HasQueryFilter(oi => oi.Order.TenantId == _tenantProvider.GetTenantId());
    }
    
    public override int SaveChanges()
    {
        // Set tenant ID on new entities
        var tenantId = _tenantProvider.GetTenantId();
        
        foreach (var entry in ChangeTracker.Entries<ITenantEntity>()
            .Where(e => e.State == EntityState.Added))
        {
            entry.Entity.TenantId = tenantId;
        }
        
        return base.SaveChanges();
    }
}

// Service to temporarily disable tenant filter for cross-tenant operations (admin only)
public class AdminService
{
    private readonly AppDbContext _context;
    private readonly ITenantProvider _tenantProvider;
    
    public AdminService(AppDbContext context, ITenantProvider tenantProvider)
    {
        _context = context;
        _tenantProvider = tenantProvider;
    }
    
    public async Task<List<Product>> GetAllProductsAcrossTenants()
    {
        // Only allow if user is admin
        if (!IsAdminUser()) throw new UnauthorizedAccessException("Admin access required");
        
        return await _context.Products
            .IgnoreQueryFilters() // Disable tenant filter
            .AsNoTracking()
            .ToListAsync();
    }
    
    private bool IsAdminUser()
    {
        // Check if current user has admin role
        return true; // Implementation depends on your auth system
    }
}
```

## Challenge 15: Advanced Performance Monitoring and Diagnostics

**Problem**: Implement performance monitoring and diagnostics for EF Core operations.

**Solution**:
```csharp
public class EFCorePerformanceMonitor : IDisposable
{
    private readonly Stopwatch _stopwatch;
    private readonly string _operationName;
    private readonly ILogger<EFCorePerformanceMonitor> _logger;
    
    public EFCorePerformanceMonitor(string operationName, ILogger<EFCorePerformanceMonitor> logger)
    {
        _operationName = operationName;
        _logger = logger;
        _stopwatch = Stopwatch.StartNew();
    }
    
    public void Dispose()
    {
        _stopwatch.Stop();
        _logger.LogInformation("EF Core operation '{OperationName}' took {ElapsedMilliseconds}ms", 
            _operationName, _stopwatch.ElapsedMilliseconds);
    }
}

// Interceptor for logging SQL commands
public class SqlCommandInterceptor : DbCommandInterceptor
{
    private readonly ILogger<SqlCommandInterceptor> _logger;
    
    public SqlCommandInterceptor(ILogger<SqlCommandInterceptor> logger)
    {
        _logger = logger;
    }
    
    public override InterceptionResult<DbDataReader> ReaderExecuting(
        DbCommand command, 
        CommandEventData eventData, 
        InterceptionResult<DbDataReader> result)
    {
        LogCommand(command);
        return base.ReaderExecuting(command, eventData, result);
    }
    
    public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
        DbCommand command, 
        CommandEventData eventData, 
        InterceptionResult<DbDataReader> result, 
        CancellationToken cancellationToken = default)
    {
        LogCommand(command);
        return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
    }
    
    private void LogCommand(DbCommand command)
    {
        _logger.LogDebug("Executing SQL command: {CommandText}", command.CommandText);
        
        if (command.Parameters.Count > 0)
        {
            var parameters = string.Join(", ", 
                command.Parameters.Cast<DbParameter>()
                    .Select(p => $"{p.ParameterName}={p.Value}"));
            
            _logger.LogDebug("Parameters: {Parameters}", parameters);
        }
    }
}

// DbContext with performance monitoring
public class MonitoredDbContext : DbContext
{
    private readonly ILogger<MonitoredDbContext> _logger;
    
    public MonitoredDbContext(DbContextOptions<MonitoredDbContext> options, 
                             ILogger<MonitoredDbContext> logger)
        : base(options)
    {
        _logger = logger;
    }
    
    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        using (new EFCorePerformanceMonitor("SaveChanges", _logger))
        {
            return base.SaveChanges(acceptAllChangesOnSuccess);
        }
    }
    
    public override async Task<int> SaveChangesAsync(
        bool acceptAllChangesOnSuccess, 
        CancellationToken cancellationToken = default)
    {
        using (new EFCorePerformanceMonitor("SaveChangesAsync", _logger))
        {
            return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
        }
    }
}

// Service for query performance analysis
public class QueryAnalyzerService
{
    private readonly AppDbContext _context;
    private readonly ILogger<QueryAnalyzerService> _logger;
    
    public QueryAnalyzerService(AppDbContext context, ILogger<QueryAnalyzerService> logger)
    {
        _context = context;
        _logger = logger;
    }
    
    public async Task AnalyzeQueryPerformance<T>(IQueryable<T> query, string queryName)
    {
        var sql = query.ToQueryString();
        _logger.LogInformation("Query '{QueryName}': {Sql}", queryName, sql);
        
        using (var monitor = new EFCorePerformanceMonitor(queryName, _logger))
        {
            var result = await query.ToListAsync();
            _logger.LogInformation("Query '{QueryName}' returned {Count} rows", queryName, result.Count);
        }
        
        // You could add more analysis here, like:
        // - Explain plan analysis (if supported by database)
        // - Index usage analysis
        // - Memory usage analysis
    }
}

// Registration in Startup.cs
services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));
    options.AddInterceptors(new SqlCommandInterceptor(loggerFactory.CreateLogger<SqlCommandInterceptor>()));
    options.EnableSensitiveDataLogging(); // Only in development!
    options.EnableDetailedErrors(); // Only in development!
    options.LogTo(Console.WriteLine, LogLevel.Information); // Simple logging
    options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking); // Default to no tracking
});
```

These challenges cover a wide range of advanced EF Core concepts and patterns. Mastering them will give you deep expertise in Entity Framework Core and prepare you for complex real-world scenarios.
