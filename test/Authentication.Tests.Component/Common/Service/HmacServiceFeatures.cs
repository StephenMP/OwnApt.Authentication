﻿using System.Threading.Tasks;
using Xunit;

namespace Authentication.Tests.Component
{
    public class HmacServiceFeatures
    {
        #region Private Fields

        private HmacServiceSteps steps = new HmacServiceSteps();

        #endregion Private Fields

        #region Public Methods

        [Fact]
        public async Task CanCreateHmacString()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();
            await this.steps.WhenICreateHmacStringAsync();
            this.steps.ThenICanVerifyICreateHmacStringAsync();
        }

        [Fact]
        public async Task CannotValidateHmacStringDueToDifferent()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            await this.steps.WhenICreateHmacStringAsync();

            this.steps.GivenIHaveASecretKey();

            await this.steps.WhenIValidateHmacStringAsync();

            this.steps.ThenICanVerifyICannotValidateHmacStringAsync();
        }

        [Fact(Skip = "Removed body sign validation temporarily")]
        public async Task CannotValidateHmacStringDueToDifferentJsonRequestBody()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            await this.steps.WhenICreateHmacStringAsync();

            this.steps.GivenIHaveAJsonRequestBody();

            await this.steps.WhenIValidateHmacStringAsync();

            this.steps.ThenICanVerifyICannotValidateHmacStringAsync();
        }

        [Fact]
        public async Task CannotValidateHmacStringDueToTamperedHmacString()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            await this.steps.WhenICreateHmacStringAsync();

            this.steps.GivenIHaveATamperedHmacString();

            await this.steps.WhenIValidateHmacStringAsync();

            this.steps.ThenICanVerifyICannotValidateHmacStringAsync();
        }

        [Fact]
        public async Task CanValidateHmacString()
        {
            this.steps.GivenIHaveAnAppId();
            this.steps.GivenIHaveASecretKey();
            this.steps.GivenIHaveARequestMethod();
            this.steps.GivenIHaveAJsonRequestBody();
            this.steps.GivenIHaveAnHmacService();

            await this.steps.WhenICreateHmacStringAsync();
            await this.steps.WhenIValidateHmacStringAsync();

            this.steps.ThenICanVerifyIValidateHmacStringAsync();
        }

        #endregion Public Methods
    }
}
