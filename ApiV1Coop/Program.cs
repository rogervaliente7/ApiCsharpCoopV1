using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using DotNetEnv;

var builder = WebApplication.CreateBuilder(args);

// Cargar las variables de entorno desde el archivo .env
Env.Load();

Console.WriteLine("JWT_SECRET: " + Environment.GetEnvironmentVariable("JWT_SECRET"));

// Configuración de CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("http://localhost:4200") // Dominio del frontend
              .AllowAnyHeader() // Permitir cualquier encabezado
              .AllowAnyMethod(); // Permitir cualquier método HTTP (GET, POST, etc.)
    });
});

// Configuración de JWT Bearer
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

// Aplicar la política de CORS antes de autenticación y autorización
app.UseCors("AllowFrontend");

app.UseAuthentication(); // Habilitar autenticación JWT
app.UseAuthorization();

app.MapControllers();

app.Run();
