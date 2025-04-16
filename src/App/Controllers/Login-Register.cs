using Aplication.DTOs;
using Aplication.Intrfaces;
using Aplication.Models;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace Aplication.Controllers
{
    [Route("api/Auth")]
    [ApiController]


    public class LoginRegisterController : ControllerBase
    {
        private readonly ILoginRegister _loginRegister;
        private readonly IMapper _mapper;
        public LoginRegisterController(ILoginRegister loginRegister, IMapper mapper)
        {

            _loginRegister = loginRegister;
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

            // Verificar si result tiene una propiedad message
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

            // Retornar el token si el inicio de sesión fue exitoso
            if (result.GetType().GetProperty("token") != null)
            {
                return Ok(new { token = result.token });
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
    }
}