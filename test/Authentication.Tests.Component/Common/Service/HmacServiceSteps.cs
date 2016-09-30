using OwnApt.Authentication.Common.Interface;
using OwnApt.Authentication.Common.Service;
using System;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Authentication.Tests.Component
{
    internal class HmacServiceSteps
    {
        #region Private Fields

        private readonly Random random = new Random();
        private readonly string[] requestArray = { "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD" };
        private string appId;
        private IHmacService hmacService;
        private string hmacString;
        private string httpMethod;
        private bool isValid;
        private string jsonRequestBody;
        private string secretKey;

        #endregion Private Fields

        #region Internal Methods

        internal void GivenIHaveAJsonRequestBody()
        {
            this.jsonRequestBody = $"\"{random.Next()}\":\"{random.Next()}\"";
        }

        internal void GivenIHaveAnAppId()
        {
            this.appId = Guid.NewGuid().ToString("N");
        }

        internal void GivenIHaveAnHmacService()
        {
            this.hmacService = new HmacService();
        }

        internal void GivenIHaveARequestMethod()
        {
            this.httpMethod = requestArray[random.Next(0, requestArray.Length - 1)];
        }

        internal void GivenIHaveASecretKey()
        {
            this.secretKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString("N")));
        }

        internal void GivenIHaveATamperedHmacString()
        {
            var hmacArray = this.hmacString.Split(':');
            hmacArray[1] = Guid.NewGuid().ToString("N");
            this.hmacString = $"{hmacArray[0]}:{hmacArray[1]}:{hmacArray[2]}:{hmacArray[3]}:{hmacArray[4]}";//:{hmacArray[5]}";
        }

        internal void ThenICanVerifyICannotValidateHmacString()
        {
            Assert.False(this.isValid);
        }

        internal void ThenICanVerifyICreateHmacString()
        {
            Assert.NotNull(this.hmacString);
            Assert.NotEmpty(this.hmacString);

            var hmacArray = hmacString.Split(':');

            Assert.Equal(this.appId, hmacArray[0]);
            Assert.Equal(5, hmacArray.Length);
        }

        internal void ThenICanVerifyIValidateHmacString()
        {
            Assert.True(isValid);
        }

        internal void WhenICreateHmacString()
        {
            this.hmacString = this.hmacService.CreateHmacString(this.appId, this.secretKey, this.httpMethod);//, this.jsonRequestBody);
        }

        internal void WhenIValidateHmacString()
        {
            this.isValid = this.hmacService.ValidateHmacString(this.hmacString, this.secretKey);//, this.jsonRequestBody);
        }

        #endregion Internal Methods
    }
}
