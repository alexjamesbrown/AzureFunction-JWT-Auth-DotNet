using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace azure_functions_jwt_demo.Functions
{
    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public static class LoginFunction
    {
        private static SigningCredentials signingCredentials;

        static LoginFunction()
        {

            //probably do something a little more secure than this eventually!
            var securityKey = Constants.Key;
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));
            signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        }

        [FunctionName("Login")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            var json = await req.ReadAsStringAsync();
            var loginModel = JsonConvert.DeserializeObject<LoginModel>(json);

            //super secure mechanism
            if (loginModel.Username == "alex" && loginModel.Password == "password")
            {
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, loginModel.Username),
                    new Claim(ClaimTypes.Role, "Admin"),
                    new Claim("CustomClaim", "Custom Claim Value"),
                };

                //
                var token = new JwtSecurityToken(
                    issuer: "https://localhost",
                    audience: "https://localhost/aud",
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: signingCredentials);

                return new OkObjectResult(new
                {
                    token = new JwtSecurityTokenHandler()
                        .WriteToken(token)
                });
            }

            //denied!
            return new StatusCodeResult(401);
        }
    }
}