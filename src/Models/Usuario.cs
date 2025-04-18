using Microsoft.AspNetCore.Identity;

namespace Aplication.Models
{
    public class Usuario : IdentityUser
    {
        public string Nombre { get; set; }
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}