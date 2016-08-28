using Xunit;

namespace Authentication.Tests.Component
{
    public class CryptoProviderFeatures
    {
        #region Public Fields + Properties

        public CryptoProviderSteps steps = new CryptoProviderSteps();

        #endregion Public Fields + Properties

        #region Public Methods

        [Fact]
        public void CanDecrypt()
        {
            this.steps.GivenIHaveDataToEncrypt();

            this.steps.WhenIEncryptData();

            this.steps.ThenICanVerifyIEncryptData();

            this.steps.WhenIDecryptData();

            this.steps.ThenICanVerifyIDecryptData();
        }

        [Fact]
        public void CanEncrypt()
        {
            this.steps.GivenIHaveDataToEncrypt();
            this.steps.WhenIEncryptData();
            this.steps.ThenICanVerifyIEncryptData();
        }

        #endregion Public Methods
    }
}
