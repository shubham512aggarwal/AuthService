﻿using AuthService.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Database
{
    public class AuthDbContext : DbContext
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users => Set<User>();
    }
}
