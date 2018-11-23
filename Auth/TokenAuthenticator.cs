using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace azure_functions_jwt_demo.Auth
{
    public sealed class TokenAuthenticator
    {
        private readonly TokenValidationParameters _parameters;
        private readonly JwtSecurityTokenHandler _handler;

        public TokenAuthenticator(string validIssuer, IEnumerable<string> validAudiences)
        {
            _parameters = new TokenValidationParameters
            {
                ValidIssuer = validIssuer,
                ValidAudiences = validAudiences,
                ValidateIssuerSigningKey = true,

                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateLifetime = true,
            };

            _handler = new JwtSecurityTokenHandler();
        }

        public TokenAuthenticatorResult Authenticate(HttpRequest request)
        {
            var token = Token(request);

            if (string.IsNullOrEmpty(token))
                return new TokenAuthenticatorResult("Authentication header does not use Bearer token.");

            try
            {
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Constants.Key));

                _parameters.IssuerSigningKeys = new[] { key };

                var user = _handler.ValidateToken(token, _parameters, out var validatedToken);
                
                return new TokenAuthenticatorResult(user, validatedToken);
            }
            catch (Exception ex)
            {
                //log.LogError("Authorization failed", ex);
                return new TokenAuthenticatorResult("Failed Authentication");
            }
        }

        private static string Token(HttpRequest request)
        {
            var authorizationHeader = request.Headers.SingleOrDefault(x => x.Key == "Authorization");
            var authenticationHeaderValue = AuthenticationHeaderValue.Parse(authorizationHeader.Value);

            if (authenticationHeaderValue == null || !string.Equals(authenticationHeaderValue.Scheme, "Bearer", StringComparison.InvariantCultureIgnoreCase))
                return null;

            return authenticationHeaderValue.Parameter;
        }

        public class TokenAuthenticatorResult
        {
            public TokenAuthenticatorResult(ClaimsPrincipal claimsPrincipal, SecurityToken securityToken)
            {
                ClaimsPrincipal = claimsPrincipal;
                SecurityToken = securityToken;
            }

            public TokenAuthenticatorResult(string failureReason)
            {
                FailureReason = failureReason;
            }

            public string FailureReason { get; }

            public ClaimsPrincipal ClaimsPrincipal { get; }
            public SecurityToken SecurityToken { get; }

            public bool Success => ClaimsPrincipal != null && string.IsNullOrEmpty(FailureReason);
        }
    }
}