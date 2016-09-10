using OwnApt.Authentication.Common.Interface;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OwnApt.Authentication.Common.Service
{
    public class HmacService : IHmacService
    {
        #region Methods

        public async Task<string> CreateHmacStringAsync(string appId, string secretKey, string httpMethod, string jsonRequestBody = "")
        {
            jsonRequestBody = jsonRequestBody ?? "";
            var computedBase64SignedBody = await ComputeSignedRequestBodyAsync(jsonRequestBody);
            var guidSignature = Guid.NewGuid().ToString("N");
            var utcFileTimestamp = DateTime.UtcNow.ToFileTimeUtc();
            var computedBase64SecretKeyCombined = await ComputeBase64SecretyKeyCombinedAsync(secretKey, httpMethod, utcFileTimestamp, guidSignature, computedBase64SignedBody);

            return $"{appId}:{computedBase64SecretKeyCombined}:{httpMethod}:{utcFileTimestamp}:{guidSignature}:{computedBase64SignedBody}";
        }

        public async Task<bool> ValidateHmacStringAsync(string hmacString, string secretKey, string jsonRequestBody = "")
        {
            jsonRequestBody = jsonRequestBody ?? "";
            var hmacArray = hmacString.Split(':');
            var appId = hmacArray[0];
            var providedSignedSecretKey = hmacArray[1];
            var httpMethod = hmacArray[2];
            var timeStamp = long.Parse(hmacArray[3]);
            var guidSignature = hmacArray[4];
            var providedSignedRequestBody = hmacArray.Length == 6 ? hmacArray[5] : "";

            return await ValidateHmacArrayAsync(hmacArray)
                && await ValidateTimeToLiveAsync(timeStamp)
                //&& await ValidateBody(providedSignedRequestBody, jsonRequestBody)
                && await ValidateSignedSecretKeyAsync(secretKey, httpMethod, timeStamp, guidSignature, providedSignedSecretKey, providedSignedRequestBody);
        }

        private async static Task<string> ComputeBase64SecretyKeyCombinedAsync(string secretKey, string httpMethod, long utcFileTimestamp, string guidSignature, string signedRequestBody)
        {
            var byteSecretKey = Encoding.UTF8.GetBytes(secretKey);
            var secretKeyCombined = $"{secretKey}:{httpMethod}:{utcFileTimestamp}:{guidSignature}:{signedRequestBody}";
            var byteSecretKeyCombined = Encoding.UTF8.GetBytes(secretKeyCombined);
            byte[] hashedSecretKey;

            using (var hmac = new HMACSHA1(byteSecretKey))
            {
                hashedSecretKey = hmac.ComputeHash(byteSecretKeyCombined);
            }

            var computedBase64SecretKeyCombined = Convert.ToBase64String(byteSecretKeyCombined);
            return await Task.FromResult(computedBase64SecretKeyCombined);
        }

        private async static Task<string> ComputeSignedRequestBodyAsync(string jsonRequestBody)
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

        //private async static Task<bool> ValidateBodyAsync(string providedSignedRequestBody, string jsonRequestBody)
        //{
        //    var computedBase64SignedBody = await ComputeSignedRequestBodyAsync(jsonRequestBody);
        //    return await Task.FromResult(computedBase64SignedBody == providedSignedRequestBody);
        //}

        private async static Task<bool> ValidateHmacArrayAsync(string[] hmacArray)
        {
            return await Task.FromResult(hmacArray.Length == 5 || hmacArray.Length == 6);
        }

        private async static Task<bool> ValidateSignedSecretKeyAsync(string secretKey, string httpMethod, long utcFileTimestamp, string guidSignature, string providedSignedSecretKey, string signedRequestBody)
        {
            var computedSignedSecretKey = await ComputeBase64SecretyKeyCombinedAsync(secretKey, httpMethod, utcFileTimestamp, guidSignature, signedRequestBody);
            return await Task.FromResult(computedSignedSecretKey == providedSignedSecretKey);
        }

        private async static Task<bool> ValidateTimeToLiveAsync(long utcFileTimestamp)
        {
            var timeStampDateTime = DateTime.FromFileTimeUtc(utcFileTimestamp);
            return await Task.FromResult(timeStampDateTime.AddMinutes(1) > DateTime.UtcNow);
        }

        #endregion Methods
    }
}
