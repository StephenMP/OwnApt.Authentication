using OwnApt.Authentication.Domain.Interface;
using OwnApt.Authentication.Domain.Service;
using System;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Authentication.Tests.Component
{
    internal class AuthenticationSteps
    {
        private IHmacService hmacService;
        private string appId;
        private string secretKey;
        private Random random = new Random();
        private string[] requestArray = new string[] { "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD" };
        private string httpMethod;
        private string jsonRequestBody;
        private string hmacString;
        private bool isValid;

        internal void GivenIHaveAJsonRequestBody()
        {
            this.jsonRequestBody = $"\"{random.Next()}\":\"{random.Next()}\"";
        }

        internal void ThenICanVerifyICreateHmacStringAsync()
        {
            Assert.NotNull(this.hmacString);
            Assert.NotEmpty(this.hmacString);

            var hmacArray = hmacString.Split(':');

            Assert.Equal(this.appId, hmacArray[0]);
            Assert.Equal(6, hmacArray.Length);
        }

        internal void GivenIHaveAnHmacService()
        {
            this.hmacService = new HmacService();
        }

        internal async Task WhenIValidateHmacStringAsync()
        {
            this.isValid = await this.hmacService.ValidateHmacStringAsync(this.hmacString, this.secretKey, this.jsonRequestBody);
        }

        internal void ThenICanVerifyIValidateHmacStringAsync()
        {
            Assert.True(isValid);
        }

        internal void GivenIHaveARequestMethod()
        {
            this.httpMethod = requestArray[random.Next(0, requestArray.Length - 1)];
        }

        internal void GivenIHaveASecretKey()
        {
            this.secretKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString("N")));
        }

        internal void ThenICanVerifyICannotValidateHmacStringAsync()
        {
            Assert.False(this.isValid);
        }

        internal void GivenIHaveAnAppId()
        {
            this.appId = Guid.NewGuid().ToString("N");
        }

        internal async Task WhenICreateHmacStringAsync()
        {
            this.hmacString = await this.hmacService.CreateHmacStringAsync(this.appId, this.secretKey, this.httpMethod, this.jsonRequestBody);
        }

        internal void GivenIHaveATamperedHmacString()
        {
            var hmacArray = this.hmacString.Split(':');
            hmacArray[5] = "\"thisIsANew\":\"requestBody\"";
            this.hmacString = $"{hmacArray[0]}:{hmacArray[1]}:{hmacArray[2]}:{hmacArray[3]}:{hmacArray[4]}:{hmacArray[5]}";
        }
    }
}