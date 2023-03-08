using AspNetCore.Identity.MongoDbCore.Models;
using MongoDbGenericRepository.Attributes;

namespace AspAuthRoles.Models
{
    [CollectionName("users")]
    public class ApplicationUser: MongoIdentityUser<Guid>
    {
        public string FullName { get; set; } = string.Empty;
    }
}
