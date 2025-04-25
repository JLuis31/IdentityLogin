using System.Security.Claims;
using Aplication.DTOs;
using Aplication.Intrfaces;
using Aplication.Models;
using AutoMapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace Aplication.Controllers
{
    [Route("api/Auth")]
    [ApiController]


    public class LoginRegisterController : ControllerBase
    {
        private readonly ILoginRegister _loginRegister;
        private readonly SignInManager<Usuario> _signInManager;
        private readonly UserManager<Usuario> _userManager;
        private readonly IMapper _mapper;
        public LoginRegisterController(UserManager<Usuario> _UserManager, SignInManager<Usuario> signInManager, ILoginRegister loginRegister, IMapper mapper)
        {
            _userManager = _UserManager;
            _loginRegister = loginRegister;
            _signInManager = signInManager;
            _mapper = mapper;
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromForm] LoginDto login)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest("Invalid data.");
            }


            dynamic result = await _loginRegister.Login(login.Email, login.Password);

            if (result.GetType().GetProperty("message") != null)
            {
                if (result.message.StartsWith("El usuario no existe") || result.message.StartsWith("La contraseña es incorrecta"))
                {
                    return BadRequest(result.message);
                }
                else if (result.message.StartsWith("Error al iniciar sesión"))
                {
                    return BadRequest(result.message);
                }
            }

            if (result.GetType().GetProperty("token") != null)
            {
                return Ok(new { token = result.token, refreshToken = result.refreshToken });
            }

            return BadRequest("Error desconocido.");
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromForm] UsuarioRegisterDto registro)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Invalid data.");
            }

            if (registro.Password == null)
            {
                return BadRequest("Passwords do not match.");
            }

            var result = await _loginRegister.Register(registro);
            if (result.message.StartsWith("El usuario ya existe"))

            {
                return BadRequest(result.message);
            }
            else
            {
                return Ok(result.message);
            }
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("ObtenerUsuarios")]
        public async Task<IActionResult> ObtenerUsuarios()
        {


            var usuarios = await _loginRegister.ObtenerUsuario();
            return Ok(usuarios);
        }

        [HttpPost("ObtenerUsuarioEmail")]
        public async Task<IActionResult> ObtenerUsuarioEmai([FromForm] string email)
        {
            var usuario = await _loginRegister.ObtenerUsuarioEmail(email);
            if (usuario == null)
            {
                return NotFound("Usuario no encontrado.");
            }
            var UsuarioDto = _mapper.Map<ObtenerusuarioDto>(usuario);
            return Ok(UsuarioDto);
        }

        [Authorize(Roles = "Admin")]
        [HttpDelete("EliminarUsuario")]
        public async Task<IActionResult> EliminarUsuario([FromForm] string email)
        {
            var claims = HttpContext.User.Claims.Select(c => new { c.Type, c.Value });
            foreach (var claim in claims)
            {
                Console.WriteLine($"Tipo: {claim.Type} - Valor: {claim.Value}");
            }
            var usuario = await _loginRegister.EliminarUsuario(email);
            if (usuario == null)
            {
                return NotFound("Usuario no encontrado.");
            }
            return Ok(usuario);
        }

        [HttpGet]
        [Route("login")]
        public Task LoginWithGoogle()
        {
            var redirectUrl = "https://localhost:7175/api/Auth/signin-google";
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(GoogleDefaults.AuthenticationScheme, redirectUrl);
            return HttpContext.ChallengeAsync(GoogleDefaults.AuthenticationScheme, properties);
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("signin-google")]
        public async Task<IActionResult> SignInGoogle(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
                return BadRequest($"Error from external provider: {remoteError}");

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return BadRequest("Error loading external login information.");

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);

            if (result.Succeeded)
            {
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var usuario = await _userManager.FindByEmailAsync(email);

                if (usuario == null)
                {
                    return BadRequest("Usuario no encontrado.");
                }

                var roles = await _loginRegister.ObtenerRolesUsuario(email);
                var jwt = await _loginRegister.GenerarToken(usuario, roles);
                var refreshToken = await _loginRegister.GenerarRefreshToken(email);
                return Content($"Hola, tu token: {jwt} y tu refresh token: {refreshToken} y tu email: {email}");
            }


            var userEmail = info.Principal.FindFirstValue(ClaimTypes.Email);
            var name = info.Principal.FindFirstValue(ClaimTypes.Name);

            var user = await _loginRegister.RegistrarUsuarioDesdeGoogleAsync(userEmail, name, info);
            if (user == null)
            {
                return BadRequest("Error al registrar el usuario desde Google.");
            }

            return Ok($"Usuario registrado desde Google. Estos son tus datos: {user.email}, tu nombre es: {user.nombre}, tu token es: {user.accestoken}, y tu refresh token es: {user.refreshToken}");
        }


        [HttpGet]
        [AllowAnonymous]
        [Route("logout-google")]
        public async Task<IActionResult> LogoutGoogle()
        {

            await _signInManager.SignOutAsync();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Ok("Logout exitoso. Puedes cerrar sesión en Google desde tu navegador.");
        }



    }
}