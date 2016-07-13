using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.Domain.Interface
{
    public interface IHmacService
    {
        Task<string> CreateHmacStringAsync(string appId, string secretKey);
        Task<string> CreateHmacStringAsync(string appId, string secretKey, string jsonRequestBody);
        Task<bool> ValidateHmacStringAsync(string hmacString, string secretKey);
        Task<bool> ValidateHmacStringAsync(string hmacString, string secretKey, string providedSignedRequestBody, string jsonRequestBody);
    }
}
