using OwnApt.Authentication.Common.Interface;
using OwnApt.Authentication.Common.Service;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace OwnApt.Authentication.Client.Handler
{
    public class HmacDelegatingHandler : DelegatingHandler
    {
        #region Private Fields

        private readonly string appId;
        private readonly IHmacService hmacService;
        private readonly string secretKey;

        #endregion Private Fields

        #region Public Constructors

        public HmacDelegatingHandler(string appId, string secretKey)
        {
            this.hmacService = new HmacService();
            this.appId = appId;
            this.secretKey = secretKey;
        }

        #endregion Public Constructors

        #region Protected Methods

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var httpMethod = request.Method.Method;
            var requestBody = request.Content == null ? "" : await request.Content.ReadAsStringAsync();
            var hmacString = hmacService.CreateHmacString(this.appId, this.secretKey, httpMethod);//, requestBody);

            request.Headers.Authorization = new AuthenticationHeaderValue("amx", hmacString);
            return await base.SendAsync(request, cancellationToken);
        }

        #endregion Protected Methods
    }
}
