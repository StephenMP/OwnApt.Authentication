using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Primitives;
using OwnApt.Authentication.Common.Interface;
using OwnApt.Authentication.Common.Service;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OwnApt.Authentication.Api.Filter
{
    public sealed class HmacAuthenticationFilter : ActionFilterAttribute, IAsyncAuthorizationFilter
    {
        #region Private Fields

        private readonly Dictionary<string, string> allowedApps;
        private readonly IHmacService hmacService;

        #endregion Private Fields

        #region Public Constructors

        public HmacAuthenticationFilter()
        {
            this.hmacService = new HmacService();
            this.allowedApps = new Dictionary<string, string>
            {
                {"d63c7a5913dd472481e1d88bbc2bc420", "qlTOlX/p2tyQd1k/0T4nLfwB/Lk="}
            };
        }

        #endregion Public Constructors

        #region Public Methods

        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            // Get and check the authorization header
            var authHeader = context.HttpContext.Request.Headers["authorization"];
            if (authHeader == default(StringValues))
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            // Parse the auth header values and check they are valid
            var authHeaderValues = authHeader[0].Split(' ');
            var authScheme = authHeaderValues[0];
            if (authScheme != "amx")
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            // Run the values through our HMAC algorithm
            var appId = authHeaderValues[1].Split(':')[0];
            var appIsRecognized = await ValidateAppIdAsync(appId);
            if (!appIsRecognized)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            // We need to copy the body stream since reading it consumes it
            //var tempStream = new MemoryStream();
            //context.HttpContext.Request.Body.CopyTo(tempStream);

            //var rawBody = tempStream.ToArray();
            //var bodyStreamToConsume = new MemoryStream(rawBody);
            //context.HttpContext.Request.Body = new MemoryStream(rawBody);

            //var requestBody = await this.ReadRequestBodyAsync(bodyStreamToConsume);
            var secretKey = this.allowedApps[appId];
            var isValid = await this.hmacService.ValidateHmacStringAsync(authHeaderValues[1], secretKey, "");//, requestBody);
            if (!isValid)
            {
                context.Result = new UnauthorizedResult();
                return;
            }
        }

        #endregion Public Methods

        //private static async Task<string> ReadRequestBodyAsync(Stream body)
        //{
        //    string requestBody;
        //    using (var reader = new StreamReader(body))
        //    {
        //        requestBody = await reader.ReadToEndAsync();
        //    }

        //    return await Task.FromResult(requestBody);
        //}

        #region Private Methods

        private async Task<bool> ValidateAppIdAsync(string appId)
        {
            return await Task.FromResult(this.allowedApps.ContainsKey(appId));
        }

        #endregion Private Methods
    }
}
