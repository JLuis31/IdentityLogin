using Aplication.Intrfaces;
using Aplication.Data;
using Microsoft.EntityFrameworkCore;
using Aplication.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http.HttpResults;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using Azure.Core;

namespace Aplication.Repositorios
{
    public class LoginRegister : ILoginRegister
    {
        private readonly AppDbContext _context;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<Usuario> _userManager;
        private readonly SignInManager<Usuario> _signInManager;
        private readonly JwtSettings _jwtSettings;

        public LoginRegister(AppDbContext context, RoleManager<IdentityRole> roleManager, UserManager<Usuario> userManager, SignInManager<Usuario> signInManager, JwtSettings jwtSettings)
        {

            _roleManager = roleManager;
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtSettings = jwtSettings;
        }

        public async Task<dynamic> Login(string email, string password)
        {
            var usuarioExistente = await _userManager.FindByEmailAsync(email);
            var contraseñaValida = await _userManager.CheckPasswordAsync(usuarioExistente, password);
            if (usuarioExistente == null || usuarioExistente.Id == null)
            {
                return new { message = "El usuario no existe" };
            }
            if (!contraseñaValida)
            {
                return new { message = "La contraseña es incorrecta" };
            }
            var resultado = await _signInManager.PasswordSignInAsync(email, password, isPersistent: false, lockoutOnFailure: false);
            if (resultado.Succeeded)
            {
                var roles = await _userManager.GetRolesAsync(usuarioExistente);
                var token = await GenerarToken(usuarioExistente, roles);
                var refreshToken = await GenerarRefreshToken(email);
                return new { token = token, refreshToken = refreshToken };
            }
            else
            {
                return new { message = "Error al iniciar sesión" };
            }

        }

        public Task<string> GenerarToken(Usuario usuario, IList<string> roles)
        {

            var claims = new List<Claim>
            {
             new Claim(JwtRegisteredClaimNames.Sub, usuario.Id),
             new Claim(JwtRegisteredClaimNames.UniqueName, usuario.Nombre),
             new Claim(JwtRegisteredClaimNames.Email, usuario.Email),
             new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var rol in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, rol));
            }



            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.Now.AddSeconds(_jwtSettings.DurationInMinutes),
                signingCredentials: creds
            );
            return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(token));

        }

        public async Task<string> GenerarRefreshToken(string email)
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
            }

            var refreshToken = Convert.ToBase64String(randomNumber);

            // Buscar al usuario en la base de datos
            var usuario = await _userManager.Users.FirstOrDefaultAsync(c => c.Email == email);
            if (usuario != null)
            {
                // Guardar el Refresh Token y su fecha de expiración
                usuario.RefreshToken = refreshToken;
                usuario.RefreshTokenExpiryTime = DateTime.UtcNow.AddSeconds(30); // Expira en 7 días
                await _userManager.UpdateAsync(usuario);
            }

            return refreshToken;

        }

        public async Task<dynamic> RefreshToken(string email, string refreshToken)
        {
            var usuario = await _userManager.Users.FirstOrDefaultAsync(c => c.Email == email);
            if (usuario != null && usuario.RefreshToken == refreshToken && usuario.RefreshTokenExpiryTime > DateTime.UtcNow)
            {
                var roles = await _userManager.GetRolesAsync(usuario);
                var token = await GenerarToken(usuario, roles);
                return new { token = token };
            }
            else
            {
                return new { message = "Refresh token inválido o expirado" };
            }
        }
        public async Task<dynamic> RegistrarUsuarioDesdeGoogleAsync(string email, string nombre, ExternalLoginInfo info)
        {
            // Generamos el refresh token
            var refreshToken = await GenerarRefreshToken(email);

            // Creamos el usuario con los datos proporcionados
            var user = new Usuario
            {
                UserName = email,
                Email = email,
                Nombre = nombre,
                RefreshToken = refreshToken,
            };

            // Intentamos crear el usuario
            var createResult = await _userManager.CreateAsync(user);
            string token = string.Empty;

            if (createResult.Succeeded)
            {
                // Vinculamos el login de Google al usuario
                await _userManager.AddLoginAsync(user, info);

                // Determinamos si el usuario es el primer usuario para asignarle el rol de Admin
                var esPrimerUsuario = !await _userManager.Users.AnyAsync(u => u.Id != user.Id);
                var rolAsignado = esPrimerUsuario ? "Admin" : "User";

                // Comprobamos si el rol existe, si no lo creamos
                var rolExistente = await _roleManager.FindByNameAsync(rolAsignado);
                if (rolExistente == null)
                {
                    rolExistente = new IdentityRole(rolAsignado);
                    await _roleManager.CreateAsync(rolExistente);
                }

                // Asignamos el rol al usuario
                await _userManager.AddToRoleAsync(user, rolAsignado);

                // Generamos el token de acceso
                token = await GenerarToken(user, new List<string> { rolAsignado });
            }

            // Retornamos los datos del usuario y los tokens
            return new
            {
                email = user.Email,
                nombre = user.Nombre,
                refreshToken = user.RefreshToken,
                accestoken = token
            };
        }

        public async Task<dynamic> Register(UsuarioRegisterDto registro)
        {
            var existente = await UsuarioExistente(registro.Email);
            if (existente)
            {
                return new { message = "El usuario ya existe" };
            }
            else
            {

                var Usuario = new Usuario
                {
                    Nombre = registro.Nombre,
                    Email = registro.Email,
                    UserName = registro.Email,
                    NormalizedUserName = registro.Email.ToUpper(),
                    RefreshToken = "1",
                    RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7) // Expira en 7 días
                };

                await _userManager.CreateAsync(Usuario, registro.Password);

                var esPrimerUsuario = !await _userManager.Users.AnyAsync(u => u.Id != Usuario.Id);
                var rolAsignado = esPrimerUsuario ? "Admin" : "User";


                var rolExistente = await _roleManager.FindByNameAsync(rolAsignado);
                if (rolExistente == null)
                {
                    rolExistente = new IdentityRole(rolAsignado);
                    await _roleManager.CreateAsync(rolExistente);
                }

                await _userManager.AddToRoleAsync(Usuario, rolAsignado);

                return new { message = "Usuario registrado correctamente" };
            }
        }

        public async Task<dynamic> ObtenerUsuario()
        {
            var usuarios = await _userManager.Users.ToListAsync();
            var usuariosDto = new List<ObtenerusuarioDto>();
            foreach (var usuario in usuarios)
            {
                var usuarioDto = new ObtenerusuarioDto
                {
                    Id = usuario.Id,
                    Nombre = usuario.Nombre,
                    Email = usuario.Email
                };
                usuariosDto.Add(usuarioDto);
            }

            return usuariosDto;
        }

        public async Task<dynamic> ObtenerUsuarioEmail(string email)
        {
            if (email == null)
            {
                return new { message = "El email no ha sido proporcionado" };
            }
            var usuarioEmail = await _userManager.Users.FirstOrDefaultAsync(c => c.Email == email);
            return usuarioEmail;
        }

        public async Task<bool> UsuarioExistente(string email)
        {
            var Usuario = await _userManager.Users.FirstOrDefaultAsync(c => c.Email == email);
            if (Usuario != null)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public async Task<dynamic> EliminarUsuario(string email)
        {
            var usuario = await _userManager.Users.FirstOrDefaultAsync(c => c.Email == email);
            if (usuario != null)
            {
                await _userManager.DeleteAsync(usuario);
                return new { message = "Usuario eliminado correctamente" };
            }
            else
            {
                return new { message = "El usuario no existe" };
            }
        }

        public async Task<IList<string>> ObtenerRolesUsuario(string email)
        {
            var usuario = await _userManager.Users.FirstOrDefaultAsync(c => c.Email == email);
            if (usuario == null)
                return new List<string>();

            return await _userManager.GetRolesAsync(usuario);
        }
    }
}