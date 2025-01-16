using Microsoft.EntityFrameworkCore;
using ApiV1Coop.Models;

namespace ApiV1Coop
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<Usuario> Usuarios { get; set; }

        public DbSet<Session> Sessions { get; set; }
    }
}
