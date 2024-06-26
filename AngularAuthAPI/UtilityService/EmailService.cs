using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Threading.Tasks;
using AngularAuthAPI.Models;
using MimeKit;

namespace AngularAuthAPI.UtilityService
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _config;
        public EmailService(IConfiguration configuration){
            _config = configuration;
        }

        public void SendEmail(EmailModel emailModel){
            var emailMessage = new MimeMessage();
            var from = _config["EmailSettings:From"];
            emailMessage.From.Add(new MailboxAddress("Edward", from));
            emailMessage.To.Add(new MailboxAddress(emailModel.To, emailModel.To));
            emailMessage.Subject = emailModel.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html){
                Text = string.Format(emailModel.Content)
            };

            using(var client = new MailKit.Net.Smtp.SmtpClient())
            {
                try
                {
                    client.Connect(_config["EmailSettings:SmtpServer"], 465, true);
                    client.Authenticate(_config["EmailSettings:From"], _config["EmailSettings:Password"]);
                    client.Send(emailMessage);
                }
                catch (System.Exception)
                {
                    
                    throw;
                }
                finally{
                    client.Disconnect(true);
                    client.Dispose();
                }
            }
        }
    }
}