using System;

namespace ApiV1Coop.Models
{
    public class SignupRequest
    {
        public required string Correo { get; set; }
        public required string Nombre { get; set; }
        public required string Password { get; set; }
    }
}