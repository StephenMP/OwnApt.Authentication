using System.Threading.Tasks;
using Xunit;

namespace Authentication.Tests.Component
{
    public class HmacServiceFeatures
    {
        #region Private Fields

        private readonly HmacServiceSteps steps = new HmacServiceSteps();

        #endregion Private Fields

        #region Public Methods

        [Fact]
        public async Task CanCreateHmacStringAsync()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();
            await this.steps.WhenICreateHmacStringAsync();
            this.steps.ThenICanVerifyICreateHmacString();
        }

        [Fact]
        public async Task CannotValidateHmacStringDueToDifferentAsync()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            await this.steps.WhenICreateHmacStringAsync();

            this.steps.GivenIHaveASecretKey();

            await this.steps.WhenIValidateHmacStringAsync();

            this.steps.ThenICanVerifyICannotValidateHmacString();
        }

        [Fact(Skip = "Removed body sign validation temporarily")]
        public async Task CannotValidateHmacStringDueToDifferentJsonRequestBodyAsync()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            await this.steps.WhenICreateHmacStringAsync();

            this.steps.GivenIHaveAJsonRequestBody();

            await this.steps.WhenIValidateHmacStringAsync();

            this.steps.ThenICanVerifyICannotValidateHmacString();
        }

        [Fact]
        public async Task CannotValidateHmacStringDueToTamperedHmacStringAsync()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            await this.steps.WhenICreateHmacStringAsync();

            this.steps.GivenIHaveATamperedHmacString();

            await this.steps.WhenIValidateHmacStringAsync();

            this.steps.ThenICanVerifyICannotValidateHmacString();
        }

        [Fact]
        public async Task CanValidateHmacStringAsync()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            await this.steps.WhenICreateHmacStringAsync();
            await this.steps.WhenIValidateHmacStringAsync();

            this.steps.ThenICanVerifyIValidateHmacString();
        }

        #endregion Public Methods
    }
}
