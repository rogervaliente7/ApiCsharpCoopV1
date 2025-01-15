using Google.Apis.Auth;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using ApiV1Coop.Models;
using Microsoft.EntityFrameworkCore;

namespace ApiV1Coop.Controllers.auth
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : Controller
    {
        private readonly AppDbContext _dbContext; // Inyectar el contexto de la base de datos
        private readonly string _jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "default-jwt-secret";
        private readonly string _googleClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? "default-google-client-id";

        public AuthController(AppDbContext dbContext)
        {
            _dbContext = dbContext; // Inicializar el contexto de la base de datos
        }

        [HttpPost("google")]
        public async Task<IActionResult> GoogleLogin()
        {
            var authorizationHeader = Request.Headers["Authorization"].ToString();
            Console.WriteLine("Token recibido en el backend: " + authorizationHeader);

            if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer "))
            {
                return BadRequest(new { error = "El encabezado Authorization es requerido y debe contener el token de Google." });
            }

            var googleToken = authorizationHeader.Substring("Bearer ".Length).Trim();
            Console.WriteLine("Token sin prefijo: " + googleToken);

            try
            {
                var payload = await VerifyGoogleToken(googleToken);
                if (payload == null)
                {
                    Console.WriteLine("Token de Google inválido.");
                    return Unauthorized(new { error = "Token de Google inválido." });
                }

                // Buscar si el usuario ya existe
                var existingUser = _dbContext.Usuarios.FirstOrDefault(u => u.Correo == payload.Email);

                if (existingUser == null)
                {
                    // Crear un nuevo usuario si no existe
                    var newUser = new Usuario
                    {
                        Nombre = payload.Name,
                        Correo = payload.Email,
                        GoogleToken = googleToken,
                        Picture = payload.Picture,
                        JwtToken = GenerateJwtToken(payload.Subject, payload.Email),
                    };

                    _dbContext.Usuarios.Add(newUser);
                    await _dbContext.SaveChangesAsync();

                    // Recargar el usuario recién creado
                    existingUser = newUser;
                    Console.WriteLine("Usuario creado en la base de datos.");
                }
                else
                {
                    // Actualizar el token JWT si ya existe
                    existingUser.JwtToken = GenerateJwtToken(payload.Subject, payload.Email);
                    _dbContext.Usuarios.Update(existingUser);
                    await _dbContext.SaveChangesAsync();

                    Console.WriteLine("Usuario ya existe en la base de datos, token actualizado.");
                }

                // Devolver respuesta con el ID del usuario
                Console.WriteLine(new
                {
                    message = "Inicio de sesión exitoso",
                    token = existingUser.JwtToken,
                    user = new
                    {
                        id = existingUser.Id,
                        name = existingUser.Nombre,
                        email = existingUser.Correo,
                        picture = existingUser.Picture
                    }
                });
                
                return Ok(new
                {
                    message = "Inicio de sesión exitoso",
                    token = existingUser.JwtToken,
                    user = new
                    {
                        id = existingUser.Id,
                        name = existingUser.Nombre,
                        email = existingUser.Correo,
                        picture = existingUser.Picture
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error al procesar el token: " + ex.Message);
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpPost("signup")]
        public async Task<IActionResult> Signup([FromBody] SignupRequest request)
        {
            // Validar que todos los campos requeridos estén presentes
            if (string.IsNullOrEmpty(request.Correo))
                return BadRequest(new { error = "El campo 'correo' es obligatorio." });
            
            if (string.IsNullOrEmpty(request.Nombre))
                return BadRequest(new { error = "El campo 'nombre' es obligatorio." });

            if (string.IsNullOrEmpty(request.Password))
                return BadRequest(new { error = "El campo 'password' es obligatorio." });

            try
            {
                // Verificar si ya existe un usuario con el mismo correo
                var existingUser = _dbContext.Usuarios.FirstOrDefault(u => u.Correo == request.Correo);
                if (existingUser != null)
                {
                    return BadRequest(new { error = "Ya existe un usuario con este correo." });
                }

                // Crear un nuevo usuario
                var newUser = new Usuario
                {
                    Nombre = request.Nombre,
                    Correo = request.Correo,
                    Password = request.Password, // Considera encriptar el password antes de guardarlo
                    JwtToken = GenerateJwtToken(Guid.NewGuid().ToString(), request.Correo),
                    IsValidated = false // Valor predeterminado
                };

                // Guardar el usuario en la base de datos
                _dbContext.Usuarios.Add(newUser);
                await _dbContext.SaveChangesAsync();

                // Retornar respuesta con el token JWT
                return Ok(new
                {
                    message = "Solicitud creada exitosamente",
                    token = newUser.JwtToken,
                    user = new
                    {
                        id = newUser.Id,
                        name = newUser.Nombre,
                        email = newUser.Correo,
                        opt_code = 123123,
                        is_validated = false
                    }
                });
            }
            catch (Exception ex)
            {
                // Manejo de errores genéricos
                Console.WriteLine("Error al procesar la solicitud de signup: " + ex.Message);
                return StatusCode(500, new { error = "Ocurrió un error interno. Por favor, intenta nuevamente." });
            }
        }

        [HttpPatch("signup_validate")]
        public async Task<IActionResult> ValidateSignUp([FromBody] SignupValidateRequest request)
        {
            if (string.IsNullOrEmpty(request.JwtToken) || string.IsNullOrEmpty(request.OptCode))
            {
                return BadRequest(new { error = "El JwtToken y el optCode son obligatorios." });
            }

            try
            {
                // Imprimir el contenido del request
                Console.WriteLine("JwtToken recibido: " + request.JwtToken);
                Console.WriteLine("OptCode recibido: " + request.OptCode);

                // Consulta SQL personalizada usando FromSqlRaw
                var query = @"
                    SELECT TOP(1) [u].[Id], [u].[correo], [u].[google_token], [u].[is_validated], [u].[jwt_token], 
                        [u].[nombre], [u].[password], [u].[picture]
                    FROM [Usuarios] AS [u]
                    WHERE [u].[jwt_token] = {0}";

                var found_user = await _dbContext.Usuarios
                    .FromSqlRaw(query, request.JwtToken)
                    .FirstOrDefaultAsync();

                if (found_user == null)
                {
                    return BadRequest(new { error = "Usuario no encontrado o ya validado." });
                }

                // Imprimir el query generado con el parámetro JwtToken
                Console.WriteLine("User encontrado: " + found_user);

                // Actualizar el campo is_validated
                found_user.IsValidated = true;
                _dbContext.Usuarios.Update(found_user);
                await _dbContext.SaveChangesAsync();

                return Ok(new { 
                    message = "Usuario validado exitosamente.",
                    user = new
                    {
                        id = found_user.Id,
                        name = found_user.Nombre,
                        email = found_user.Correo,
                        opt_code = 123123,
                        is_validated = false
                    }
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpPatch("google/signup_validate")]
        public async Task<IActionResult> GoogleSignUpValidate([FromBody] GoogleSignUpValidateRequest request)
        {
            if (string.IsNullOrEmpty(request.JwtToken) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new { error = "El jwtToken y el password son obligatorios." });
            }

            try
            {
                // Imprimir el contenido del request
                Console.WriteLine("JwtToken recibido: " + request.JwtToken);
                Console.WriteLine("Password recibido: " + request.Password);

                // Consultar al usuario con el jwtToken
                // var found_user = await _dbContext.Usuarios
                //     .Where(u => u.JwtToken == request.JwtToken && u.Password != null)
                //     .FirstOrDefaultAsync();


                var query = @"
                    SELECT TOP(1) [u].[Id], [u].[correo], [u].[google_token], [u].[is_validated], [u].[jwt_token], 
                                [u].[nombre], [u].[password], [u].[picture]
                    FROM [Usuarios] AS [u]
                    WHERE [u].[jwt_token] = {0} AND [u].[password] IS NULL";


                var found_user = await _dbContext.Usuarios
                    .FromSqlRaw(query, request.JwtToken)
                    .FirstOrDefaultAsync();
              
                if (found_user == null)
                {
                    return BadRequest(new { error = "Usuario no encontrado o no tiene contraseña definida." });
                }

                // Validar la contraseña, en un caso real aquí puedes comparar la contraseña de forma segura con un hash
                if (found_user.Password != request.Password)  // Comparación simple, en producción deberías usar un hash
                {
                    return BadRequest(new { error = "Contraseña incorrecta." });
                }

                // Actualizar el estado de validación
                found_user.IsValidated = true;
                _dbContext.Usuarios.Update(found_user);
                await _dbContext.SaveChangesAsync();

                return Ok(new { 
                    message = "Usuario validado exitosamente.",
                    user = new
                    {
                        id = found_user.Id,
                        name = found_user.Nombre,
                        email = found_user.Correo,
                        opt_code = 123123,
                        is_validated = false
                    }
                });
            }
            catch (Exception ex)
            {
                // Manejar excepciones generales
                return BadRequest(new { error = ex.Message });
            }
        }


        private async Task<GoogleJsonWebSignature.Payload?> VerifyGoogleToken(string token)
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new List<string> { _googleClientId }
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

        // private string GenerateJwtToken(string userId, string email)
        // {
        //     var claims = new[] {
        //         new Claim(ClaimTypes.NameIdentifier, userId),
        //         new Claim(ClaimTypes.Email, email)
        //     };

        //     var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
        //     var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        //     var token = new JwtSecurityToken(
        //         issuer: "http://localhost:5016",
        //         audience: "http://localhost:4200",
        //         claims: claims,
        //         expires: DateTime.Now.AddHours(1),
        //         signingCredentials: creds
        //     );

        //     return new JwtSecurityTokenHandler().WriteToken(token);
        // }

        private string GenerateJwtToken(string userId, string email)
        {
            // Generamos un identificador único para cada token
            var uniqueTokenId = Guid.NewGuid().ToString();

            var claims = new[] {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Email, email),
                new Claim("uniqueTokenId", uniqueTokenId),  // Agregamos el identificador único
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "http://localhost:5016",
                audience: "http://localhost:4200",
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


    }
}


// using Google.Apis.Auth;
// using System.IdentityModel.Tokens.Jwt;
// using System.Security.Claims;
// using System.Text;
// using Microsoft.AspNetCore.Http;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.IdentityModel.Tokens;

// namespace ApiV1Coop.Controllers.auth
// {
//     [Route("api/auth")]
//     [ApiController]
//     public class AuthController : Controller
//     {
//         // Obtener las variables de entorno de manera segura
//         private readonly string _jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "default-jwt-secret"; // Clave secreta para JWT
//         private readonly string _googleClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? "default-google-client-id"; // Client ID de Google

//         [HttpPost("google")]
//         public async Task<IActionResult> GoogleLogin()
//         {
//             // Obtener el token del encabezado Authorization
//             var authorizationHeader = Request.Headers["Authorization"].ToString();
//             Console.WriteLine("Token recibido en el backend: " + authorizationHeader);

//             if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer "))
//             {
//                 return BadRequest(new { error = "El encabezado Authorization es requerido y debe contener el token de Google." });
//             }

//             // Extraer el token después de "Bearer "
//             var googleToken = authorizationHeader.Substring("Bearer ".Length).Trim();
//             Console.WriteLine("Token sin prefijo: " + googleToken);

//             try
//             {
//                 // Verificar el token con Google
//                 var payload = await VerifyGoogleToken(googleToken);
//                 if (payload == null)
//                 {
//                     Console.WriteLine("Token de Google inválido.");
//                     return Unauthorized(new { error = "Token de Google inválido." });
//                 }

//                 // Simular datos quemados o procesar la lógica de negocio real
//                 var response = new
//                 {
//                     data = new[]
//                     {
//                         new
//                         {
//                             type = "usuarios",
//                             id = "123456789", // ID quemado
//                             attributes = new
//                             {
//                                 usuario_id = "123456789", // ID quemado
//                                 googleId = payload.Subject,
//                                 name = payload.Name,
//                                 email = payload.Email,
//                                 picture = payload.Picture,
//                                 token = GenerateJwtToken(payload.Subject, payload.Email) // Generar el token JWT
//                             }
//                         }
//                     }
//                 };

//                 Console.WriteLine("Respuesta generada en el backend: " + System.Text.Json.JsonSerializer.Serialize(response));
//                 return Ok(response);
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine("Error al procesar el token: " + ex.Message);
//                 return BadRequest(new { error = ex.Message });
//             }
//         }



//         [HttpGet("test")]
//         public IActionResult TestConnection()
//         {
//             return Ok(new { message = "Conexión exitosa" });
//         }

//         private async Task<GoogleJsonWebSignature.Payload?> VerifyGoogleToken(string token)
//         {
//             var settings = new GoogleJsonWebSignature.ValidationSettings
//             {
//                 Audience = new List<string> { _googleClientId } // Usamos el client ID de Google de las variables de entorno
//             };

//             try
//             {
//                 var payload = await GoogleJsonWebSignature.ValidateAsync(token, settings);
//                 return payload;
//             }
//             catch
//             {
//                 return null;
//             }
//         }

//         private string GenerateJwtToken(string userId, string email)
//         {
//             var claims = new[] {
//                 new Claim(ClaimTypes.NameIdentifier, userId),
//                 new Claim(ClaimTypes.Email, email)
//             };

//             var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret)); // Usamos el JWT secreto de las variables de entorno
//             var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

//             var token = new JwtSecurityToken(
//                 issuer: "http://localhost:5016",
//                 audience: "http://localhost:4200",
//                 claims: claims,
//                 expires: DateTime.Now.AddHours(1),
//                 signingCredentials: creds
//             );

//             return new JwtSecurityTokenHandler().WriteToken(token);
//         }
//     }
// }
