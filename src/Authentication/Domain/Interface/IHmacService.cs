using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.Domain.Interface
{
    public interface IHmacService
    {
        Task<string> CreateHmacStringAsync(string appId, string secretKey, string httpMethod, string jsonRequestBody);
        Task<bool> ValidateHmacStringAsync(string hmacString, string secretKey, string jsonRequestBody);
    }
}
