using OwnApt.Authentication.Common.Service;
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
        public void CanCreateHmacString()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();
            this.steps.WhenICreateHmacString();
            this.steps.ThenICanVerifyICreateHmacString();
        }

        [Fact]
        public void CannotValidateHmacStringDueToDifferent()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            this.steps.WhenICreateHmacString();

            this.steps.GivenIHaveASecretKey();

            this.steps.WhenIValidateHmacString();

            this.steps.ThenICanVerifyICannotValidateHmacString();
        }

        [Fact(Skip = "Removed body sign validation temporarily")]
        public void CannotValidateHmacStringDueToDifferentJsonRequestBody()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            this.steps.WhenICreateHmacString();

            this.steps.GivenIHaveAJsonRequestBody();

            this.steps.WhenIValidateHmacString();

            this.steps.ThenICanVerifyICannotValidateHmacString();
        }

        [Fact]
        public void CannotValidateHmacStringDueToTamperedHmacString()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            this.steps.WhenICreateHmacString();

            this.steps.GivenIHaveATamperedHmacString();

            this.steps.WhenIValidateHmacString();

            this.steps.ThenICanVerifyICannotValidateHmacString();
        }

        [Fact]
        public void CanValidateHmacString()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            this.steps.WhenICreateHmacString();
            this.steps.WhenIValidateHmacString();

            this.steps.ThenICanVerifyIValidateHmacString();
        }

        #endregion Public Methods
    }
}
