// This file is your Database Configuration file. It tells Entity Framework (EF) Core:

// What tables to create (Users table)
// How the tables should behave (email must be unique)
// How to connect to the database (via the options parameter)

using Microsoft.EntityFrameworkCore;
using firstAPIs.Models;

namespace firstAPIs.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }
    
    public DbSet<User> Users { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        // Make email unique
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Email)
            .IsUnique();
    }
}