using Microsoft.AspNet.Mvc;
using Microsoft.AspNet.Mvc.Filters;
using Microsoft.Extensions.Primitives;
using OwnApt.Authentication.Domain.Interface;
using OwnApt.Authentication.Domain.Service;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace OwnApt.Authentication.Domain.Filters
{
    public class AuthenticationFilter : ActionFilterAttribute, IAsyncAuthorizationFilter
    {
        #region Private Fields + Properties

        private Dictionary<string, string> allowedApps;
        private IHmacService hmacService;

        #endregion Private Fields + Properties

        #region Public Constructors + Destructors

        public AuthenticationFilter()
        {
            this.hmacService = new HmacService();
            this.allowedApps = new Dictionary<string, string>
            {
                {"abcd1234", "1234abcd"}
            };
        }

        #endregion Public Constructors + Destructors

        #region Public Methods

        public async Task OnAuthorizationAsync(AuthorizationContext context)
        {
            // Get and check the authorization header
            var authHeader = context.HttpContext.Request.Headers["authorization"];
            if (authHeader == default(StringValues))
            {
                context.Result = new HttpUnauthorizedResult();
                return;
            }

            // Parse the auth header values and check they are valid
            var authHeaderValues = authHeader[0].Split(' ');
            var authScheme = authHeaderValues[0];
            if (authScheme != "amx")
            {
                context.Result = new HttpUnauthorizedResult();
                return;
            }

            // Run the values through our HMAC algorithm
            var appId = authHeaderValues[1].Split(':')[0];
            var appIsRecognized = await ValidateAppId(appId);
            if (!appIsRecognized)
            {
                context.Result = new HttpUnauthorizedResult();
                return;
            }

            var secretKey = this.allowedApps[appId];
            var requestBody = await this.ReadRequestBody(context.HttpContext.Request.Body);
            var isValid = await this.hmacService.ValidateHmacStringAsync(authHeaderValues[1], secretKey, requestBody);
            if (!isValid)
            {
                context.Result = new HttpUnauthorizedResult();
                return;
            }
        }

        #endregion Public Methods

        #region Private Methods

        private string[] ParseAuthHeaderValues(string authHeader)
        {
            var values = authHeader.Split(':');
            return (values.Length == 4 || values.Length == 5) ? values : null;
        }

        private async Task<bool> ValidateAppId(string appId)
        {
            return await Task.FromResult(this.allowedApps.ContainsKey(appId));
        }

        private async Task<string> ReadRequestBody(Stream body)
        {
            string requestBody;
            body.Position = 0;
            using (var reader = new StreamReader(body))
            {
                requestBody = await reader.ReadToEndAsync();
            }

            return await Task.FromResult(requestBody);
        }

        #endregion Private Methods
    }
}