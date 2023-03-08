using AspNetCore.Identity.MongoDbCore.Models;
using MongoDbGenericRepository.Attributes;

namespace AspAuthRoles.Models
{
    [CollectionName("roles")]
    public class ApplicationRole: MongoIdentityRole<Guid>
    {
    }
}
