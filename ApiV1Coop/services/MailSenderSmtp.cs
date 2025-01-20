using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace ApiV1Coop.Services
{
    public class MailSenderSmtp
    {
        private readonly string _smtpHost = "smtp.gmail.com"; // Host SMTP de Gmail
        private readonly int _smtpPort = 587; // Puerto para TLS
        private readonly string _senderEmail = Environment.GetEnvironmentVariable("EMAIL_SENDER") ?? "default-sender-email"; // Correo del remitente
        private readonly string _appPassword = Environment.GetEnvironmentVariable("APP_PASSWORD") ?? "default-app-password"; // Contraseña de aplicación de Gmail

        public async Task SendEmailAsync(string recipientEmail, string subject, string body)
        {
            using (var smtpClient = new SmtpClient(_smtpHost, _smtpPort))
            {
                smtpClient.Credentials = new NetworkCredential(_senderEmail, _appPassword);
                smtpClient.EnableSsl = true;

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_senderEmail),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = false // Cambia a true si el cuerpo contiene HTML
                };

                mailMessage.To.Add(recipientEmail);

                await smtpClient.SendMailAsync(mailMessage);
                Console.WriteLine("Email enviado a: " + recipientEmail);
            }
        }
    }
}