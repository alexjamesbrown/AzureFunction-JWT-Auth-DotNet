using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using azure_functions_jwt_demo.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace azure_functions_jwt_demo.Functions
{
    public static class ValuesFunction
    {
        [FunctionName("Values")]
        [Authorize]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = null)] HttpRequest req,
            ILogger log)
        {
            if (!req.IsAuthenticated())
                return new UnauthorizedResult();

            var userClaims = req.HttpContext
                .User
                .Claims
                .Select(x => $"name: {x.Type} value: {x.Value}");

            return new OkObjectResult(userClaims);
        }
    }
}
