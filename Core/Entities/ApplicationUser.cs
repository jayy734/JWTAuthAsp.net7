using Microsoft.AspNetCore.Identity;
using System.Diagnostics.Eventing.Reader;

namespace JWTAuthAspNet7WebApi.Core.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool isDeleted { get; set; } = false; //default is false
       
    }
}
