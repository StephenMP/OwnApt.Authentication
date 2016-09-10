using System.Threading.Tasks;

namespace OwnApt.Authentication.Common.Interface
{
    public interface IHmacService
    {
        #region Methods

        Task<string> CreateHmacStringAsync(string appId, string secretKey, string httpMethod, string jsonRequestBody);

        Task<bool> ValidateHmacStringAsync(string hmacString, string secretKey, string jsonRequestBody);

        #endregion Methods
    }
}
