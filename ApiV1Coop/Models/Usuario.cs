using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ApiV1Coop.Models
{
    public class Usuario
    {
        [Key]
        public int Id { get; set; }

        [Column("nombre")]
        public string Nombre { get; set; }

        [Column("correo")]
        public string Correo { get; set; }

        [Column("password")]
        public string? Password { get; set; }

        [Column("google_token")]
        public string? GoogleToken { get; set; }

        [Column("picture")]
        public string? Picture { get; set; }

        [Column("jwt_token")]
        public string? JwtToken { get; set; }

        [Column("is_validated")]
        public bool IsValidated { get; set; } = false; // Valor predeterminado
    }
}
