using Google.Apis.Auth;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;

namespace ApiV1Coop.Controllers.auth
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : Controller
    {
        // Obtener las variables de entorno de manera segura
        private readonly string _jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "default-jwt-secret"; // Clave secreta para JWT
        private readonly string _googleClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? "default-google-client-id"; // Client ID de Google

        [HttpPost("google")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request)
        {
            if (string.IsNullOrEmpty(request?.Token))
            {
                return BadRequest(new { error = "El token de Google es requerido." });
            }

            try
            {
                // Verificar el token con Google
                var payload = await VerifyGoogleToken(request.Token);
                if (payload == null)
                {
                    return Unauthorized(new { error = "Token de Google inválido." });
                }

                // Aquí simulas almacenar el usuario (puedes guardarlo en una base de datos)
                var user = new
                {
                    GoogleId = payload.Subject,
                    Name = payload.Name,
                    Email = payload.Email,
                    Picture = payload.Picture
                };

                // Generar JWT
                var jwtToken = GenerateJwtToken(user.GoogleId, user.Email);

                // Retornar el JWT al frontend
                return Ok(new { message = "Usuario guardado", token = jwtToken });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpGet("test")]
        public IActionResult TestConnection()
        {
            return Ok(new { message = "Conexión exitosa" });
        }

        private async Task<GoogleJsonWebSignature.Payload?> VerifyGoogleToken(string token)
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new List<string> { _googleClientId } // Usamos el client ID de Google de las variables de entorno
            };

            try
            {
                var payload = await GoogleJsonWebSignature.ValidateAsync(token, settings);
                return payload;
            }
            catch
            {
                return null;
            }
        }

        private string GenerateJwtToken(string userId, string email)
        {
            var claims = new[] {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Email, email)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret)); // Usamos el JWT secreto de las variables de entorno
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "http://localhost:5000",
                audience: "http://localhost:4200",
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public class GoogleLoginRequest
    {
        public string? Token { get; set; }
    }
}
