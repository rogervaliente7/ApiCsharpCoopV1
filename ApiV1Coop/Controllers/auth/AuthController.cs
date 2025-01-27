using Google.Apis.Auth;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using ApiV1Coop.Models;
using ApiV1Coop.Services;
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

        [HttpGet("test")]
        public IActionResult TestConnection()
        {
            return Ok(new { message = "Conexión exitosa" });
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
            if (string.IsNullOrEmpty(request.Correo))
                return BadRequest(new { error = "El campo 'correo' es obligatorio." });

            if (string.IsNullOrEmpty(request.Nombre))
                return BadRequest(new { error = "El campo 'nombre' es obligatorio." });

            if (string.IsNullOrEmpty(request.Password))
                return BadRequest(new { error = "El campo 'password' es obligatorio." });

            Console.WriteLine("Correo recibido: " + request.Correo);

            try
            {
                var existingUser = _dbContext.Usuarios.FirstOrDefault(u => u.Correo == request.Correo);
                if (existingUser != null)
                {
                    return BadRequest(new { error = "Ya existe un usuario con este correo." });
                }

                var optCode = new Random().Next(100000, 999999); // Generar código OPT

                var newUser = new Usuario
                {
                    Nombre = request.Nombre,
                    Correo = request.Correo,
                    Password = request.Password, // Encripta este valor
                    JwtToken = GenerateJwtToken(Guid.NewGuid().ToString(), request.Correo),
                    IsValidated = false,
                    OptCode = optCode // Guardar el código OPT
                };

                _dbContext.Usuarios.Add(newUser);
                await _dbContext.SaveChangesAsync();

                // Enviar el correo con el código OPT
                var mailSender = new MailSenderSmtp();
                var templatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "Templates", "opt_email_template.html");
                var htmlTemplate = System.IO.File.ReadAllText(templatePath);
                var htmlBody = htmlTemplate.Replace("{Nombre}", newUser.Nombre)
                                        .Replace("{optCode}", optCode.ToString());
                await mailSender.SendEmailAsync(newUser.Correo, "Código de confirmación de autenticación", htmlBody);

                return Ok(new
                {
                    message = "Solicitud creada exitosamente",
                    token = newUser.JwtToken,
                    user = new
                    {
                        id = newUser.Id,
                        name = newUser.Nombre,
                        email = newUser.Correo,
                        is_validated = false,
                        opt_code = optCode
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error al procesar la solicitud de signup: " + ex.Message);
                return StatusCode(500, new { error = "Ocurrió un error interno. Por favor, intenta nuevamente." });
            }
        }

        [HttpPatch("signup_validate")]
        public async Task<IActionResult> ValidateSignUp([FromBody] SignupValidateRequest request)
        {
            if (string.IsNullOrEmpty(request.JwtToken) || string.IsNullOrEmpty(request.OptCode))
            {
                return BadRequest(new { error = "El JwtToken y el OptCode son obligatorios." });
            }

            try
            {
                var query = @"
                    SELECT TOP(1) [u].[Id], [u].[correo], [u].[google_token], [u].[is_validated], [u].[jwt_token], 
                                [u].[nombre], [u].[password], [u].[picture], [u].[opt_code]
                    FROM [Usuarios] AS [u]
                    WHERE [u].[jwt_token] = {0}";

                var foundUser = await _dbContext.Usuarios
                    .FromSqlRaw(query, request.JwtToken)
                    .FirstOrDefaultAsync();

                if (foundUser == null)
                {
                    return BadRequest(new { error = "Usuario no encontrado o ya validado." });
                }

                // Validar el OptCode
               if (foundUser.OptCode != null && foundUser.OptCode != Convert.ToInt32(request.OptCode))
                {
                    return Unauthorized(new { error = "El código OPT proporcionado es incorrecto." });
                }

                // Marcar como validado
                foundUser.IsValidated = true;
                _dbContext.Usuarios.Update(foundUser);
                await _dbContext.SaveChangesAsync();

                var sessionToken = Guid.NewGuid().ToString();
                var expirationTime = TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "America/El_Salvador").AddMinutes(30);

                var session = new Session
                {
                    UserId = foundUser.Id,
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
                        id = foundUser.Id,
                        name = foundUser.Nombre,
                        email = foundUser.Correo,
                        is_validated = foundUser.IsValidated
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
                var expirationTime = TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "America/El_Salvador").AddMinutes(30);  // La sesión expira en media hora (ajustable)

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
                    SELECT TOP(1) [SessionToken], [ExpirationTime], [UserId]
                    FROM [Sessions]
                    WHERE [UserId] = (SELECT [Id] FROM [Usuarios] WHERE [correo] = @correo)
                    ORDER BY [ExpirationTime] DESC"; // Ordenamos para obtener la sesión más reciente

                var checkSessionCommand = _dbContext.Database.GetDbConnection().CreateCommand();
                checkSessionCommand.CommandText = checkSessionQuery;
                checkSessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@correo", request.Email));

                // Abrir la conexión de base de datos
                if (checkSessionCommand.Connection.State != System.Data.ConnectionState.Open)
                {
                    await checkSessionCommand.Connection.OpenAsync();
                }

                // Ejecutar la consulta de sesión activa
                var sessionReader = await checkSessionCommand.ExecuteReaderAsync();
                string sessionToken = null;
                DateTime? sessionExpirationTime = null;

                if (await sessionReader.ReadAsync())
                {
                    sessionToken = sessionReader["SessionToken"] as string;
                    sessionExpirationTime = sessionReader["ExpirationTime"] as DateTime?;
                }

                // Consulta SQL para validar el usuario con el correo y la contraseña
                var query = @"
                    SELECT TOP(1) [u].[Id], [u].[correo], [u].[google_token], [u].[is_validated], [u].[jwt_token], 
                                [u].[nombre], [u].[password], [u].[picture]
                    FROM [Usuarios] AS [u]
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
                    var foundUser = new
                    {
                        Id = reader["Id"],
                        Correo = reader["correo"],
                        GoogleToken = reader["google_token"],
                        IsValidated = reader["is_validated"] as bool? ?? false,
                        JwtToken = reader["jwt_token"],
                        Nombre = reader["nombre"],
                        Password = reader["password"],
                        Picture = reader["picture"]
                    };

                    Console.WriteLine("USUARIO ENCONTRADO: " + foundUser);

                    // Verificar si ya existe una sesión activa
                    if (sessionToken != null)
                    {
                        // Si la sesión activa no ha expirado
                        if (sessionExpirationTime.HasValue && sessionExpirationTime.Value > TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "America/El_Salvador"))
                        {
                            return Ok(new
                            {
                                message = "Sesión activa encontrada.",
                                session_token = sessionToken,
                                expiration_time = sessionExpirationTime.Value,
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
                            // Si la sesión ha expirado, eliminamos la sesión vieja
                            var deleteSessionQuery = "DELETE FROM [Sessions] WHERE [SessionToken] = @sessionToken";
                            var deleteSessionCommand = _dbContext.Database.GetDbConnection().CreateCommand();
                            deleteSessionCommand.CommandText = deleteSessionQuery;
                            deleteSessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@sessionToken", sessionToken));
                            await deleteSessionCommand.ExecuteNonQueryAsync();
                        }
                    }

                    // Crear una nueva sesión
                    var sessionTokenNew = Guid.NewGuid().ToString();
                    var expirationTimeNew = TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "America/El_Salvador").AddMinutes(30); // Nuevo tiempo de expiración

                    var sessionQuery = @"
                        INSERT INTO [Sessions] ([CreatedAt], [ExpirationTime], [SessionToken], [UserId])
                        VALUES (@createdAt, @expirationTime, @sessionToken, @userId)";

                    var sessionCommand = _dbContext.Database.GetDbConnection().CreateCommand();
                    sessionCommand.CommandText = sessionQuery;
                    sessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@createdAt", TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "America/El_Salvador")));
                    sessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@expirationTime", expirationTimeNew));
                    sessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@sessionToken", sessionTokenNew));
                    sessionCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@userId", foundUser.Id));

                    await sessionCommand.ExecuteNonQueryAsync();

                    return Ok(new
                    {
                        message = "Usuario validado y nueva sesión creada.",
                        session_token = sessionTokenNew,
                        expiration_time = expirationTimeNew,
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
                    // Si no se encontró el usuario o la contraseña es incorrecta
                    return Unauthorized(new { error = "Correo o contraseña incorrectos." });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Hubo un problema al procesar la solicitud: " + ex.Message);
                return StatusCode(500, new { error = "Hubo un problema al procesar la solicitud. Intenta de nuevo más tarde." });
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
        {
            try
            {
                // Validar que el sessionToken está presente
                if (string.IsNullOrEmpty(request.SessionToken))
                {
                    return BadRequest(new { error = "El sessionToken es obligatorio." });
                }

                // Consulta para buscar la sesión activa
                var query = @"
                    SELECT TOP(1) [Id], [ExpirationTime]
                    FROM [Sessions]
                    WHERE [SessionToken] = @sessionToken";

                var command = _dbContext.Database.GetDbConnection().CreateCommand();
                command.CommandText = query;
                command.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@sessionToken", request.SessionToken));

                // Abrir la conexión de base de datos
                if (command.Connection.State != System.Data.ConnectionState.Open)
                {
                    await command.Connection.OpenAsync();
                }

                // Ejecutar la consulta y verificar si existe la sesión
                var reader = await command.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                {
                    return Unauthorized(new { error = "Sesión no encontrada o ya expirada." });
                }

                // Actualizar el ExpirationTime al tiempo actual para "invalidar" el token
                reader.Close(); // Cerrar el lector antes de ejecutar otro comando

                var updateQuery = @"
                    UPDATE [Sessions]
                    SET [ExpirationTime] = @newExpirationTime
                    WHERE [SessionToken] = @sessionToken";

                var updateCommand = _dbContext.Database.GetDbConnection().CreateCommand();
                updateCommand.CommandText = updateQuery;
                updateCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@newExpirationTime", TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "America/El_Salvador")));
                updateCommand.Parameters.Add(new Microsoft.Data.SqlClient.SqlParameter("@sessionToken", request.SessionToken));

                await updateCommand.ExecuteNonQueryAsync();

                return Ok(new { 
                    message = "Sesión cerrada exitosamente.",
                    expirationTime = TimeZoneInfo.ConvertTimeBySystemTimeZoneId(DateTime.UtcNow, "America/El_Salvador"),
                });
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
