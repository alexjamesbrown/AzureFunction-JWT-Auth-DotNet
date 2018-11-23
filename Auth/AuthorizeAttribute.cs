using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs.Host;

namespace azure_functions_jwt_demo.Auth
{
    public class AuthorizeAttribute : FunctionInvocationFilterAttribute
    {
        // I'm using a Lazy here just so that exceptions on startup are in the scope of a function execution.
        // I'm using PublicationOnly so that exceptions during creation are retried on the next execution.
        private static readonly Lazy<TokenAuthenticator> Authenticator = new Lazy<TokenAuthenticator>(
            () => new TokenAuthenticator("https://localhost", new[] { "https://localhosXXt/aud" }));

        public override Task OnExecutingAsync(FunctionExecutingContext executingContext, CancellationToken cancellationToken)
        {
            var httpRequest = ExtractHttpRequestArgument(executingContext);

            if (httpRequest == null)
                return base.OnExecutingAsync(executingContext, cancellationToken);

            var authenticatorResult = Authenticator.Value.Authenticate(httpRequest);

            if (!authenticatorResult.Success)
            {
                httpRequest.HttpContext.User = null;
                httpRequest.HttpContext.Response.StatusCode = 401;

                //this is for logging later on. It's not returned in the response
                httpRequest.HttpContext.Items.Add("Reason", authenticatorResult.FailureReason);
            }

            return base.OnExecutingAsync(executingContext, cancellationToken);
        }

        private HttpRequest ExtractHttpRequestArgument(FunctionExecutingContext executingContext)
        {
            var httpRequestArgument = executingContext.Arguments
                .SingleOrDefault(x => x.Value.GetType().IsSubclassOf(typeof(HttpRequest)));

            if (httpRequestArgument.Equals(new KeyValuePair<string, object>()))
                return null;

            return httpRequestArgument.Value as HttpRequest;
        }
    }
}