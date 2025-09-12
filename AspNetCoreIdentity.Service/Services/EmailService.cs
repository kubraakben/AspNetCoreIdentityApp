using AspNetCoreIdentityApp.Core.OptionsModel;
using Microsoft.Extensions.Options;
using System.Net.Mail;

namespace AspNetCoreIdentityApp.Service.Services
{
    public class EmailService:IEmailService
    {
        private readonly EmailSettings _emailSettings;
        public EmailService(IOptions<EmailSettings> options)
        {
            _emailSettings = options.Value;
        }
        public async Task SendResetPasswordEmail(string resetPasswordEmailLink, string ToEmail)
        {
            var smptClient = new SmtpClient();
            smptClient.Host = _emailSettings.Host; // SMTP server address
            smptClient.DeliveryMethod = SmtpDeliveryMethod.Network;
            smptClient.UseDefaultCredentials = false;
            smptClient.Port = 587;
            smptClient.Credentials = new System.Net.NetworkCredential(_emailSettings.Email, _emailSettings.Password);
            smptClient.EnableSsl = true;
            
            var mailMessage = new MailMessage();  
            mailMessage.From= new MailAddress(_emailSettings.Email);
            mailMessage.To.Add(ToEmail);
            mailMessage.Subject = "Reset Password";
            mailMessage.Body = $"<h1>Reset Password</h1><p>Click <a href='{resetPasswordEmailLink}'>here</a> to reset your password.</p>";
            mailMessage.IsBodyHtml = true;

            await smptClient.SendMailAsync(mailMessage);
        }
    }
}
