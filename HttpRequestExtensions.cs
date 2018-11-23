using System.Net;
using Microsoft.AspNetCore.Http;

namespace azure_functions_jwt_demo
{
    public static class HttpRequestExtensions
    {
        public static bool IsAuthenticated(this HttpRequest request)
        {
            if (request.HttpContext.Response.StatusCode == (int)HttpStatusCode.Unauthorized)
                return false;

            if (request.HttpContext.User == null)
                return false;

            return true;
        }
    }
}