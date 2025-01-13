using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using DotNetEnv;

var builder = WebApplication.CreateBuilder(args);

// Cargar las variables de entorno desde el archivo .env
Env.Load();

Console.WriteLine("JWT_SECRET: " + Environment.GetEnvironmentVariable("JWT_SECRET"));
// Configuraci�n de JWT Bearer
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "http://localhost:5000",  // El servidor que emite el token (tu API)
            ValidAudience = "http://localhost:4200", // El receptor del token (tu frontend)
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                Environment.GetEnvironmentVariable("JWT_SECRET") ?? "default-jwt-secret"))
        };
    });


builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication(); // Habilitar autenticaci�n JWT
app.UseAuthorization();

app.MapControllers();

app.Run();
