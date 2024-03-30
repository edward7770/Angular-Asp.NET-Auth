using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AngularAuthAPI.Helpers
{
    public static class EmailBody
    {
        public static string EmailStringBody(string email, string emailToken){
            return $@"
                <html>
                    <body>
                        <h1>Reset Password</h1>
                        <a href=""http://localhost:4200/reset?email={email}&code={emailToken}"" target=""_blank"">Reset Password</a>
                    </body>
                </html>
            ";
        }
    }
}