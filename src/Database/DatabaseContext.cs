using Microsoft.EntityFrameworkCore;
using src.Entity;

namespace src.Database
{
    public class DatabaseContext : DbContext
    {

        public DbSet<Cart> Cart { get; set; }
        public DbSet<CartDetails> CartDetails { get; set; }
        public DbSet<Category> Category { get; set; }
        public DbSet<Order> Order { get; set; }
        public DbSet<Payment> Payment { get; set; }
        public DbSet<Product> Product { get; set; }
        public DbSet<SubCategory> SubCategory { get; set; }
        public DbSet<User> User { get; set; }

        public DatabaseContext(DbContextOptions options) : base(options) { }


    }
}