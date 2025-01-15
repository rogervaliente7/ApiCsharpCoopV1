// Clase de solicitud para el endpoint
using System;

public class SignupValidateRequest
{
    public string JwtToken { get; set; }
    public string OptCode { get; set; }
}