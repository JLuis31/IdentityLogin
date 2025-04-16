using Microsoft.AspNetCore.Identity;

namespace Aplication.Models
{
    public class Usuario : IdentityUser
    {
        public string Nombre { get; set; }
    }
}