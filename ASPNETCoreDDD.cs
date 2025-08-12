# ASP.NET Core & DDD Code Challenges

Here are 5 Domain-Driven Design (DDD) code challenges across three skill levels (Beginner, Intermediate, Senior) that will help you prepare for your interview, each with solutions that teach important DDD concepts.

## Beginner Challenges

### 1. Basic Value Object Implementation
**Challenge**: Create an `Email` value object that enforces validation rules (must contain @, proper domain format, etc.) and implements proper equality comparison.

```csharp
// Solution
public record Email
{
    public string Value { get; }

    public Email(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Email cannot be empty");
        
        if (!value.Contains('@') || !value.Contains('.'))
            throw new ArgumentException("Invalid email format");
            
        Value = value.ToLower();
    }

    public static implicit operator string(Email email) => email.Value;
    
    protected virtual IEnumerable<object> GetEqualityComponents()
    {
        yield return Value;
    }
}
```

**Key Concepts Taught**:
- Value objects are immutable
- Validation in the constructor
- Proper equality implementation
- Implicit conversion for usability

### 2. Simple Aggregate Root
**Challenge**: Create a `ShoppingCart` aggregate root that maintains invariants (like not allowing negative quantities).

```csharp
// Solution
public class ShoppingCart : AggregateRoot
{
    private readonly List<CartItem> _items = new();
    public IReadOnlyCollection<CartItem> Items => _items.AsReadOnly();
    
    public void AddItem(Guid productId, int quantity, decimal unitPrice)
    {
        if (quantity <= 0)
            throw new ArgumentException("Quantity must be positive");
            
        var existingItem = _items.FirstOrDefault(i => i.ProductId == productId);
        
        if (existingItem != null)
        {
            existingItem.IncreaseQuantity(quantity);
        }
        else
        {
            _items.Add(new CartItem(productId, quantity, unitPrice));
        }
    }
    
    public void RemoveItem(Guid productId, int quantityToRemove)
    {
        var item = _items.FirstOrDefault(i => i.ProductId == productId);
        if (item == null) return;
        
        item.DecreaseQuantity(quantityToRemove);
        
        if (item.Quantity <= 0)
        {
            _items.Remove(item);
        }
    }
}

public class CartItem : Entity
{
    public Guid ProductId { get; }
    public int Quantity { get; private set; }
    public decimal UnitPrice { get; }
    
    public CartItem(Guid productId, int quantity, decimal unitPrice)
    {
        ProductId = productId;
        Quantity = quantity;
        UnitPrice = unitPrice;
    }
    
    public void IncreaseQuantity(int quantity)
    {
        Quantity += quantity;
    }
    
    public void DecreaseQuantity(int quantity)
    {
        if (quantity > Quantity)
            throw new InvalidOperationException("Cannot remove more items than exist in cart");
            
        Quantity -= quantity;
    }
}
```

**Key Concepts Taught**:
- Aggregate root responsibility
- Maintaining invariants
- Encapsulation of collection modification
- Entity vs Aggregate Root

## Intermediate Challenges

### 3. Domain Event Implementation
**Challenge**: Implement domain events for an `Order` aggregate that emits events when status changes (Created, Paid, Shipped).

```csharp
// Solution
public class Order : AggregateRoot
{
    private readonly List<IDomainEvent> _domainEvents = new();
    public OrderStatus Status { get; private set; }
    public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();
    
    public Order()
    {
        Status = OrderStatus.Created;
        _domainEvents.Add(new OrderCreatedEvent(Id));
    }
    
    public void MarkAsPaid()
    {
        if (Status != OrderStatus.Created)
            throw new InvalidOperationException("Only created orders can be paid");
            
        Status = OrderStatus.Paid;
        _domainEvents.Add(new OrderPaidEvent(Id));
    }
    
    public void MarkAsShipped()
    {
        if (Status != OrderStatus.Paid)
            throw new InvalidOperationException("Only paid orders can be shipped");
            
        Status = OrderStatus.Shipped;
        _domainEvents.Add(new OrderShippedEvent(Id));
    }
    
    public void ClearDomainEvents()
    {
        _domainEvents.Clear();
    }
}

public interface IDomainEvent
{
    DateTime OccurredOn { get; }
}

public record OrderCreatedEvent(Guid OrderId) : IDomainEvent
{
    public DateTime OccurredOn { get; } = DateTime.UtcNow;
}

public record OrderPaidEvent(Guid OrderId) : IDomainEvent
{
    public DateTime OccurredOn { get; } = DateTime.UtcNow;
}

public record OrderShippedEvent(Guid OrderId) : IDomainEvent
{
    public DateTime OccurredOn { get; } = DateTime.UtcNow;
}
```

**Key Concepts Taught**:
- Domain events pattern
- State transition validation
- Event sourcing basics
- Temporal aspect of domain events

### 4. Repository Pattern with Specification
**Challenge**: Implement a generic repository with specification pattern for an `IProductRepository` that can query products by various criteria.

```csharp
// Solution
public interface ISpecification<T>
{
    Expression<Func<T, bool>> Criteria { get; }
    List<Expression<Func<T, object>>> Includes { get; }
    List<string> IncludeStrings { get; }
}

public class ProductSpecification : ISpecification<Product>
{
    public Expression<Func<Product, bool>> Criteria { get; }
    public List<Expression<Func<Product, object>>> Includes { get; } = new();
    public List<string> IncludeStrings { get; } = new();
    
    public ProductSpecification(
        Expression<Func<Product, bool>> criteria = null,
        List<Expression<Func<Product, object>>> includes = null,
        List<string> includeStrings = null)
    {
        Criteria = criteria;
        Includes = includes ?? new();
        IncludeStrings = includeStrings ?? new();
    }
    
    public static ProductSpecification ByCategory(Guid categoryId)
    {
        return new ProductSpecification(p => p.CategoryId == categoryId);
    }
    
    public static ProductSpecification ActiveProducts()
    {
        return new ProductSpecification(p => p.IsActive);
    }
}

public interface IProductRepository
{
    Task<IEnumerable<Product>> GetAsync(ISpecification<Product> spec);
    Task<Product> GetByIdAsync(Guid id);
    Task AddAsync(Product product);
    Task UpdateAsync(Product product);
}

public class ProductRepository : IProductRepository
{
    private readonly AppDbContext _context;
    
    public ProductRepository(AppDbContext context)
    {
        _context = context;
    }
    
    public async Task<IEnumerable<Product>> GetAsync(ISpecification<Product> spec)
    {
        return await ApplySpecification(spec).ToListAsync();
    }
    
    public async Task<Product> GetByIdAsync(Guid id)
    {
        return await _context.Products.FindAsync(id);
    }
    
    public async Task AddAsync(Product product)
    {
        await _context.Products.AddAsync(product);
    }
    
    public async Task UpdateAsync(Product product)
    {
        _context.Products.Update(product);
        await Task.CompletedTask;
    }
    
    private IQueryable<Product> ApplySpecification(ISpecification<Product> spec)
    {
        var query = _context.Products.AsQueryable();
        
        if (spec.Criteria != null)
        {
            query = query.Where(spec.Criteria);
        }
        
        // Handle includes
        query = spec.Includes.Aggregate(query, 
            (current, include) => current.Include(include));
            
        // Handle string-based includes (for nested properties)
        query = spec.IncludeStrings.Aggregate(query,
            (current, include) => current.Include(include));
            
        return query;
    }
}
```

**Key Concepts Taught**:
- Repository pattern implementation
- Specification pattern for flexible queries
- Separation of query logic from domain
- EF Core includes with specifications

## Senior Challenge

### 5. CQRS with MediatR and Unit of Work
**Challenge**: Implement a CQRS pattern for a "Place Order" command that:
1. Validates inventory
2. Creates order
3. Updates inventory
4. Publishes domain events
All in a single transaction (Unit of Work).

```csharp
// Solution
public class PlaceOrderCommand : IRequest<Result<Guid>>
{
    public Guid CustomerId { get; set; }
    public List<OrderItemDto> Items { get; set; }
}

public class PlaceOrderCommandHandler : IRequestHandler<PlaceOrderCommand, Result<Guid>>
{
    private readonly IOrderRepository _orderRepository;
    private readonly IProductRepository _productRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IMediator _mediator;
    
    public PlaceOrderCommandHandler(
        IOrderRepository orderRepository,
        IProductRepository productRepository,
        IUnitOfWork unitOfWork,
        IMediator mediator)
    {
        _orderRepository = orderRepository;
        _productRepository = productRepository;
        _unitOfWork = unitOfWork;
        _mediator = mediator;
    }
    
    public async Task<Result<Guid>> Handle(PlaceOrderCommand request, CancellationToken cancellationToken)
    {
        using var transaction = await _unitOfWork.BeginTransactionAsync();
        
        try
        {
            // 1. Validate inventory
            var inventoryValidation = await ValidateInventory(request.Items);
            if (!inventoryValidation.Success)
            {
                return Result<Guid>.Failure(inventoryValidation.Error);
            }
            
            // 2. Create order
            var order = new Order(request.CustomerId);
            foreach (var item in request.Items)
            {
                order.AddItem(item.ProductId, item.Quantity, item.UnitPrice);
            }
            
            await _orderRepository.AddAsync(order);
            
            // 3. Update inventory
            await UpdateInventory(request.Items);
            
            // Save changes
            await _unitOfWork.CommitAsync(transaction);
            
            // 4. Dispatch domain events
            await DispatchDomainEvents(order);
            
            return Result<Guid>.Success(order.Id);
        }
        catch (Exception ex)
        {
            await _unitOfWork.RollbackAsync(transaction);
            return Result<Guid>.Failure($"Failed to place order: {ex.Message}");
        }
    }
    
    private async Task<Result> ValidateInventory(List<OrderItemDto> items)
    {
        foreach (var item in items)
        {
            var product = await _productRepository.GetByIdAsync(item.ProductId);
            if (product == null)
            {
                return Result.Failure($"Product {item.ProductId} not found");
            }
            
            if (product.StockQuantity < item.Quantity)
            {
                return Result.Failure($"Insufficient stock for product {product.Name}");
            }
        }
        
        return Result.Success();
    }
    
    private async Task UpdateInventory(List<OrderItemDto> items)
    {
        foreach (var item in items)
        {
            var product = await _productRepository.GetByIdAsync(item.ProductId);
            product.ReduceStock(item.Quantity);
            await _productRepository.UpdateAsync(product);
        }
    }
    
    private async Task DispatchDomainEvents(Order order)
    {
        foreach (var domainEvent in order.DomainEvents)
        {
            await _mediator.Publish(domainEvent);
        }
        
        order.ClearDomainEvents();
    }
}

// Infrastructure
public class UnitOfWork : IUnitOfWork
{
    private readonly AppDbContext _context;
    
    public UnitOfWork(AppDbContext context)
    {
        _context = context;
    }
    
    public async Task<IDbContextTransaction> BeginTransactionAsync()
    {
        return await _context.Database.BeginTransactionAsync();
    }
    
    public async Task CommitAsync(IDbContextTransaction transaction)
    {
        try
        {
            await _context.SaveChangesAsync();
            await transaction.CommitAsync();
        }
        catch
        {
            await RollbackAsync(transaction);
            throw;
        }
    }
    
    public async Task RollbackAsync(IDbContextTransaction transaction)
    {
        await transaction.RollbackAsync();
    }
}
```

**Key Concepts Taught**:
- CQRS pattern implementation
- Transaction management with Unit of Work
- Domain event dispatching
- Complex business process coordination
- Error handling and rollback strategies
- MediatR pipeline usage

These challenges cover the spectrum of DDD concepts you're likely to encounter in an interview, from basic value objects to complex transactional operations. The solutions demonstrate not just how to implement patterns, but also how to handle real-world concerns like validation, transactions, and error handling.
