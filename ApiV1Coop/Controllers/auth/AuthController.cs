using Google.Apis.Auth;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

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
        public async Task<IActionResult> GoogleLogin()
        {
            // Obtener el token del encabezado Authorization
            var authorizationHeader = Request.Headers["Authorization"].ToString();

            if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer "))
            {
                return BadRequest(new { error = "El encabezado Authorization es requerido y debe contener el token de Google." });
            }

            // Extraer el token después de "Bearer "
            var googleToken = authorizationHeader.Substring("Bearer ".Length).Trim();

            try
            {
                // Verificar el token con Google
                var payload = await VerifyGoogleToken(googleToken);
                if (payload == null)
                {
                    return Unauthorized(new { error = "Token de Google inválido." });
                }

                // Aquí simulas los datos quemados
                var response = new
                {
                    data = new[]
                    {
                        new
                        {
                            type = "usuarios",
                            id = "123456789", // ID quemado
                            attributes = new
                            {
                                usuario_id = "123456789", // ID quemado
                                googleId = payload.Subject,
                                name = payload.Name,
                                email = payload.Email,
                                picture = payload.Picture,
                                token = GenerateJwtToken(payload.Subject, payload.Email) // Generar el token JWT
                            }
                        }
                    }
                };

                return Ok(response);
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
}
