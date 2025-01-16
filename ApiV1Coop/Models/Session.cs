using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ApiV1Coop.Models
{
    public class Session // Model
    {
        public int Id { get; set; }  // Identificador único para la sesión
        public int UserId { get; set; }  // Relación con el usuario (foreign key)
        public string SessionToken { get; set; }  // Token único de la sesión
        public DateTime ExpirationTime { get; set; }  // Fecha y hora en la que la sesión expira
        public DateTime CreatedAt { get; set; }  // Fecha de creación de la sesión

        // Relación con la entidad Usuario
        public virtual Usuario User { get; set; }

        public Session()
        {
            CreatedAt = DateTime.UtcNow;  // Asignar la fecha de creación cuando se instancie la clase
        }
    }
}
