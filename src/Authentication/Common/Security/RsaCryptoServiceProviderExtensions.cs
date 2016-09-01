using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace OwnApt.Authentication.Common.Security
{
    public static class RsaCryptoServiceProviderExtensions
    {
        #region Public Methods

        public static void FromXmlString(this RSA rsa, string rsaXmlString)
        {
            var rsaPropertyCache = ParseRsaXmlString(rsaXmlString);
            rsa.ImportParameters(new RSAParameters
            {
                D = rsaPropertyCache["D"],
                DP = rsaPropertyCache["DP"],
                DQ = rsaPropertyCache["DQ"],
                Exponent = rsaPropertyCache["Exponent"],
                InverseQ = rsaPropertyCache["InverseQ"],
                Modulus = rsaPropertyCache["Modulus"],
                P = rsaPropertyCache["P"],
                Q = rsaPropertyCache["Q"]
            });
        }

        #endregion Public Methods

        #region Private Methods

        private static Dictionary<string, byte[]> ParseRsaXmlString(string rsaXmlString)
        {
            var rsaTags = new string[] { "Modulus", "Exponent", "P", "Q", "DP", "DQ", "InverseQ", "D" };
            var rsaPropertyCache = new Dictionary<string, byte[]>();

            foreach (var tagName in rsaTags)
            {
                rsaXmlString = rsaXmlString.Substring(rsaXmlString.IndexOf($"<{tagName}>") + $"<{tagName}>".Length);
                rsaPropertyCache.Add(tagName, Convert.FromBase64String(rsaXmlString.Substring(0, rsaXmlString.IndexOf($"</{tagName}>"))));
            }

            return rsaPropertyCache;
        }

        #endregion Private Methods
    }
}
