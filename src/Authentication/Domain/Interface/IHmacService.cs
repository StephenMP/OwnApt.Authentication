using System.Threading.Tasks;

namespace OwnApt.Authentication.Domain.Interface
{
    public interface IHmacService
    {
        #region Public Methods

        Task<string> CreateHmacStringAsync(string appId, string secretKey, string httpMethod, string jsonRequestBody);

        Task<bool> ValidateHmacStringAsync(string hmacString, string secretKey, string jsonRequestBody);

        #endregion Public Methods
    }
}
