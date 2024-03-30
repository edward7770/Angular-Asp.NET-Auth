using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AngularAuthAPI.Models;

namespace AngularAuthAPI.UtilityService
{
    public interface IEmailService
    {
        void SendEmail(EmailModel emailModel);
    }
}