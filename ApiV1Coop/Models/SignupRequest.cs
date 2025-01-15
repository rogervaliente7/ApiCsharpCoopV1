using System;

namespace ApiV1Coop.Models
{
    public class SignupRequest
    {
        public string Correo { get; set; }
        public string Nombre { get; set; }
        public string Password { get; set; }
    }
}