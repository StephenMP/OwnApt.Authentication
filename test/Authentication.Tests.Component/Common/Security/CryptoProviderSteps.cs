using OwnApt.Authentication.Client.Security;
using System;
using Xunit;

namespace Authentication.Tests.Component
{
    public class CryptoProviderSteps
    {
        #region Private Fields

        private string dataToEncrypt;
        private string decryptedData;
        private string encryptedData;

        #endregion Private Fields

        #region Internal Methods

        internal void GivenIHaveDataToEncrypt()
        {
            this.dataToEncrypt = Guid.NewGuid().ToString("N");
        }

        internal void ThenICanVerifyIDecryptData()
        {
            Assert.NotNull(this.decryptedData);
            Assert.NotEmpty(this.decryptedData);
            Assert.Equal(this.decryptedData, this.dataToEncrypt);
        }

        internal void ThenICanVerifyIEncryptData()
        {
            Assert.NotNull(this.encryptedData);
            Assert.NotEmpty(this.encryptedData);
            Assert.NotEqual(this.dataToEncrypt, this.encryptedData);
        }

        internal void WhenIDecryptData()
        {
            this.decryptedData = CryptoProvider.Decrypt(this.encryptedData);
        }

        internal void WhenIEncryptData()
        {
            this.encryptedData = CryptoProvider.Encrypt(dataToEncrypt);
        }

        #endregion Internal Methods
    }
}
