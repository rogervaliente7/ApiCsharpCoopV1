using Google.Apis.Auth;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using ApiV1Coop.Models;
using Microsoft.EntityFrameworkCore;
using System.Data.SqlClient;
using Microsoft.Data.SqlClient;

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

                // Actualizar el campo is_validated
                found_user.IsValidated = true;
                _dbContext.Usuarios.Update(found_user);
                await _dbContext.SaveChangesAsync();

                // Crear una nueva sesión para el usuario
                var sessionToken = Guid.NewGuid().ToString();  // Generar un token único para la sesión
                var expirationTime = DateTime.UtcNow.AddHours(1);  // La sesión expira en 1 hora (ajustable)

                var session = new Session
                {
                    UserId = found_user.Id,
                    SessionToken = sessionToken,
                    ExpirationTime = expirationTime
                };
                
                _dbContext.Sessions.Add(session);
                await _dbContext.SaveChangesAsync();

                return Ok(new 
                { 
                    message = "Usuario validado exitosamente.",
                    session_token = session.SessionToken,
                    expiration_time = session.ExpirationTime,
                    user = new
                    {
                        id = found_user.Id,
                        name = found_user.Nombre,
                        email = found_user.Correo,
                        opt_code = 123123,  // Aquí puedes asignar un código de validación si lo deseas
                        is_validated = found_user.IsValidated
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
                // Consulta SQL para encontrar al usuario con jwtToken y que la contraseña aún sea NULL
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
                    return BadRequest(new { error = "Usuario no encontrado o ya tiene una contraseña configurada." });
                }

                // Asignar la nueva contraseña
                found_user.Password = request.Password;
                found_user.IsValidated = true;

                // Actualizar el usuario en la base de datos
                _dbContext.Usuarios.Update(found_user);
                await _dbContext.SaveChangesAsync();

                // Crear una nueva sesión para el usuario
                var sessionToken = Guid.NewGuid().ToString();  // Generar un token único para la sesión
                var expirationTime = DateTime.UtcNow.AddHours(1);  // La sesión expira en 1 hora (ajustable)

                var session = new Session
                {
                    UserId = found_user.Id,
                    SessionToken = sessionToken,
                    ExpirationTime = expirationTime
                };

                _dbContext.Sessions.Add(session);
                await _dbContext.SaveChangesAsync();

                return Ok(new 
                { 
                    message = "Usuario validado y contraseña asignada exitosamente.",
                    session_token = session.SessionToken,
                    expiration_time = session.ExpirationTime,
                    user = new
                    {
                        id = found_user.Id,
                        name = found_user.Nombre,
                        email = found_user.Correo,
                        opt_code = 123123,  // Aquí puedes asignar un código de validación si lo deseas
                        is_validated = found_user.IsValidated
                    }
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            // Validar que ambos parámetros están presentes
            if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new { error = "El correo y la contraseña son obligatorios." });
            }

            try
            {
                // Imprimir el contenido del request para depuración
                Console.WriteLine("Correo recibido: " + request.Email);
                Console.WriteLine("Contraseña recibida: " + request.Password);

                // Consulta SQL para verificar si ya hay una sesión activa
                var checkSessionQuery = @"
                    SELECT TOP(1) [SessionToken]
                    FROM [Sessions]
                    WHERE [UserId] = (SELECT [Id] FROM [Usuarios] WHERE [correo] = @correo)
                    AND [ExpirationTime] > @currentTime";

                var checkSessionCommand = _dbContext.Database.GetDbConnection().CreateCommand();
                checkSessionCommand.CommandText = checkSessionQuery;
                checkSessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@correo", request.Email));
                checkSessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@currentTime", DateTime.UtcNow));

                // Abrir la conexión de base de datos
                if (checkSessionCommand.Connection.State != System.Data.ConnectionState.Open)
                {
                    await checkSessionCommand.Connection.OpenAsync();
                }

                // Ejecutar la consulta de sesión activa
                var sessionReader = await checkSessionCommand.ExecuteReaderAsync();
                if (await sessionReader.ReadAsync())
                {
                    return BadRequest(new { error = "El usuario ya tiene una sesión activa." });
                }

                // Consulta SQL para validar el usuario con el correo y la contraseña
                var query = @"
                    SELECT TOP(1) [u].[Id], [u].[correo], [u].[google_token], [u].[is_validated], [u].[jwt_token], 
                                [u].[nombre], [u].[password], [u].[picture], s.[ExpirationTime]
                    FROM [Usuarios] AS [u]
                    LEFT JOIN [Sessions] AS s ON s.[UserId] = u.[Id]
                    WHERE [u].[correo] = @correo AND [u].[password] = @password";

                var command = _dbContext.Database.GetDbConnection().CreateCommand();
                command.CommandText = query;

                // Agregar parámetros para evitar inyecciones SQL
                command.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@correo", request.Email));
                command.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@password", request.Password));

                // Abrir la conexión de base de datos
                if (command.Connection.State != System.Data.ConnectionState.Open)
                {
                    await command.Connection.OpenAsync();
                }

                // Ejecutar la consulta y leer el resultado
                var reader = await command.ExecuteReaderAsync();

                if (await reader.ReadAsync())
                {
                    var expirationTime = reader["ExpirationTime"] as DateTime?;

                    // Verificar si la sesión ha expirado
                    if (expirationTime.HasValue && expirationTime.Value < TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "America/El_Salvador"))
                    {
                        return Unauthorized(new { error = "El token de sesión ha expirado." });
                    }

                    // Validar si el usuario ha sido verificado
                    var isValidated = reader["is_validated"] as bool? ?? false;
                    if (!isValidated)
                    {
                        return Unauthorized(new { error = "El usuario no ha sido validado." });
                    }

                    // Obtener los datos del usuario
                    var foundUser = new
                    {
                        Id = reader["Id"],
                        Correo = reader["correo"],
                        GoogleToken = reader["google_token"],
                        IsValidated = isValidated,
                        JwtToken = reader["jwt_token"],
                        Nombre = reader["nombre"],
                        Password = reader["password"],
                        Picture = reader["picture"]
                    };

                    Console.WriteLine("USUARIO ENCONTRADO: " + foundUser);

                    // Aquí puedes generar un token de sesión nuevo, si es necesario
                    var sessionToken = Guid.NewGuid().ToString();
                    var expirationTimeNew = DateTime.UtcNow.AddMinutes(1); // Para pruebas: el token expira en 1 minuto

                    // Crear una nueva sesión en la base de datos
                    var sessionQuery = @"
                        INSERT INTO [Sessions] ([CreatedAt], [ExpirationTime], [SessionToken], [UserId])
                        VALUES (@createdAt, @expirationTime, @sessionToken, @userId)";

                    var sessionCommand = _dbContext.Database.GetDbConnection().CreateCommand();
                    sessionCommand.CommandText = sessionQuery;
                    sessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@createdAt", TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "America/El_Salvador")));
                    sessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@expirationTime", TimeZoneInfo.ConvertTimeBySystemTimeZoneId(expirationTimeNew.AddMinutes(1), "America/El_Salvador")));
                    sessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@sessionToken", sessionToken));
                    sessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@userId", foundUser.Id));

                    await sessionCommand.ExecuteNonQueryAsync();

                    return Ok(new
                    {
                        message = "Usuario validado y sesión creada exitosamente.",
                        session_token = sessionToken,
                        expiration_time = TimeZoneInfo.ConvertTimeBySystemTimeZoneId(expirationTimeNew.AddMinutes(1), "America/El_Salvador"),
                        user = new
                        {
                            id = foundUser.Id,
                            nombre = foundUser.Nombre,
                            correo = foundUser.Correo,
                            is_validated = foundUser.IsValidated
                        }
                    });
                }
                else
                {
                    // Si no se encontró el usuario o no hay sesión activa
                    Console.WriteLine("Usuario no encontrado o sesión no válida.");
                    return Unauthorized(new { error = "Correo o contraseña incorrectos." });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Hubo un problema al procesar la solicitud: " + ex.Message);
                return StatusCode(500, new { error = "Hubo un problema al procesar la solicitud. Intenta de nuevo más tarde." });
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
