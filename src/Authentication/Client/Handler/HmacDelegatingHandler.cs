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
        #region Private Fields + Properties

        private string appId;
        private string cachedHmacString;
        private IHmacService hmacService;
        private string secretKey;

        #endregion Private Fields + Properties

        #region Public Constructors + Destructors

        public HmacDelegatingHandler(string appId, string secretKey)
        {
            this.hmacService = new HmacService();
            this.appId = appId;
            this.secretKey = secretKey;
        }

        public HmacDelegatingHandler(string appId, string secretKey, string cachedHmacString) : this(appId, secretKey)
        {
            this.cachedHmacString = cachedHmacString;
        }

        #endregion Public Constructors + Destructors

        #region Protected Methods

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var hmacString = this.cachedHmacString;

            if (string.IsNullOrWhiteSpace(hmacString))
            {
                var httpMethod = request.Method.Method;
                var requestBody = request.Content == null ? "" : await request.Content.ReadAsStringAsync();
                hmacString = await hmacService.CreateHmacStringAsync(this.appId, this.secretKey, httpMethod, requestBody);
            }

            request.Headers.Authorization = new AuthenticationHeaderValue("amx", hmacString);
            return await base.SendAsync(request, cancellationToken);
        }

        #endregion Protected Methods
    }
}
