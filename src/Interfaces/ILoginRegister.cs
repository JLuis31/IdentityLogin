using Aplication.Models;

namespace Aplication.Intrfaces
{
    public interface ILoginRegister
    {
        Task<dynamic> Login(string email, string password);
        Task<dynamic> Register(UsuarioRegisterDto registro);
        Task<bool> UsuarioExistente(string email);
        Task<string> GenerarToken(Usuario usuario, IList<string> roles);
        Task<string> GenerarRefreshToken(string email);

        Task<dynamic> ObtenerUsuarioEmail(string email);
        Task<dynamic> ObtenerUsuario();

        Task<dynamic> EliminarUsuario(string email);
    }
}