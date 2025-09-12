using Microsoft.AspNetCore.Identity;

namespace AspNetCoreIdentityApp.Repository.Models
{
    public class User:IdentityUser
    {
        public int? TurkuazUserId { get; set; }
        public string? City { get; set; }
        public DateTime? BirthDate { get; set; }
        public byte? Gender { get; set; }
    }
}
