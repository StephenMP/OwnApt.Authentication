using Authentication.Domain.Interface;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.Domain.Service
{
    public class HmacService : IHmacService
    {
        #region Public Methods

        public async Task<string> CreateHmacStringAsync(string appId, string secretKey)
        {
            var utcFileTimestamp = DateTime.UtcNow.ToFileTimeUtc();
            var guidSignature = Guid.NewGuid().ToString("N");
            var computedBase64SecretKeyCombined = await this.ComputeBase64SecretyKeyCombined(appId, secretKey, utcFileTimestamp, guidSignature);
            return $"amx {appId}:{computedBase64SecretKeyCombined}:{utcFileTimestamp}:{guidSignature}";
        }

        public async Task<string> CreateHmacStringAsync(string appId, string secretKey, string jsonRequestBody)
        {
            var hmacString = await this.CreateHmacStringAsync(appId, secretKey);
            var computedBase64SignedBody = await this.ComputeSignedRequestBody(jsonRequestBody);

            return $"{hmacString}:{computedBase64SignedBody}";
        }

        public async Task<bool> ValidateHmacStringAsync(string hmacString, string secretKey)
        {
            var hmacArray = hmacString.Split(':');
            var appId = hmacArray[0];
            var providedSignedSecretKey = hmacArray[1];
            var timeStamp = long.Parse(hmacArray[2]);
            var guidSignature = hmacArray[3];

            return await ValidateTimeToLive(timeStamp)
                && await ValidateSignedSecretKey(appId, secretKey, timeStamp, guidSignature, providedSignedSecretKey);
        }

        public async Task<bool> ValidateHmacStringAsync(string hmacString, string secretKey, string providedSignedRequestBody, string jsonRequestBody)
        {
            return await ValidateHmacStringAsync(hmacString, secretKey)
                && await ValidateBody(providedSignedRequestBody, jsonRequestBody);
        }

        #endregion Public Methods

        #region Private Methods

        private async Task<string> ComputeBase64SecretyKeyCombined(string appId, string secretKey, long utcFileTimestamp, string guidSignature)
        {
            var byteSecretKey = Encoding.UTF8.GetBytes(secretKey);
            byte[] hashedSecretKey;

            using (var hmac = new HMACSHA1())
            {
                hashedSecretKey = hmac.ComputeHash(byteSecretKey);
            }

            var secretKeyCombined = $"{hashedSecretKey}:{utcFileTimestamp}:{guidSignature}";
            var byteSecretKeyCombined = Encoding.UTF8.GetBytes(secretKeyCombined);
            var computedBase64SecretKeyCombined = Convert.ToBase64String(byteSecretKeyCombined);

            return await Task.FromResult(computedBase64SecretKeyCombined);
        }

        private async Task<string> ComputeSignedRequestBody(string jsonRequestBody)
        {
            var byteBodyString = Encoding.UTF8.GetBytes(jsonRequestBody);
            byte[] md5SignedBody;

            using (var md5 = MD5.Create())
            {
                md5SignedBody = md5.ComputeHash(byteBodyString);
            }

            var computedBase64SignedBody = Convert.ToBase64String(md5SignedBody);

            return await Task.FromResult(computedBase64SignedBody);
        }

        private async Task<bool> ValidateBody(string providedSignedRequestBody, string jsonRequestBody)
        {
            var computedBase64SignedBody = await this.ComputeSignedRequestBody(jsonRequestBody);
            return await Task.FromResult(computedBase64SignedBody == providedSignedRequestBody);
        }

        private async Task<bool> ValidateSignedSecretKey(string appId, string secretKey, long utcFileTimestamp, string guidSignature, string providedSignedSecretKey)
        {
            var computedSignedSecretKey = await this.ComputeBase64SecretyKeyCombined(appId, secretKey, utcFileTimestamp, guidSignature);
            return await Task.FromResult(computedSignedSecretKey == providedSignedSecretKey);
        }

        private async Task<bool> ValidateTimeToLive(long utcFileTimestamp)
        {
            var timeStampDateTime = DateTime.FromFileTimeUtc(utcFileTimestamp);
            return await Task.FromResult(timeStampDateTime.AddSeconds(10) > DateTime.UtcNow);
        }

        #endregion Private Methods
    }
}
