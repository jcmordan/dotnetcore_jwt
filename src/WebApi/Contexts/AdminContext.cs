using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebApi.Models;

namespace WebApi.Contexts
{
    public class AdminContext : IdentityDbContext<User>
    {
        public AdminContext (DbContextOptions options) : base (options)
        {
        }
    }
}