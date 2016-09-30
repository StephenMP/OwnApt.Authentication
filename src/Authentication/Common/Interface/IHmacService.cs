using System.Threading.Tasks;

namespace OwnApt.Authentication.Common.Interface
{
    public interface IHmacService
    {
        #region Public Methods

        string CreateHmacString(string appId, string secretKey, string httpMethod);//, string jsonRequestBody);

        bool ValidateHmacString(string hmacString, string secretKey);//, string jsonRequestBody);

        #endregion Public Methods
    }
}
