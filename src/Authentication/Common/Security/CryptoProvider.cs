using OwnApt.Authentication.Common.Security;
using System;
using System.Security.Cryptography;
using System.Text;

namespace OwnApt.Authentication.Client.Security
{
    public static class CryptoProvider
    {
        #region Private Fields + Properties

        private const string PrivateKey = "<RSAKeyValue><Modulus>n5B7x8adptwKBwlF2ulATKplgF98JfzMewq0buYjWhfvrgttTYRAvdQo4OGEaPHYnd6a99LqE9iJZIC33YnpIa0BKmSdAocO7M56wirJKVsI2Q6WXopE0BmMdIUX7rwRSthj/Sfy4V7S+aD8e/x0nui7df/L+FqXjFAlTJ4CuuPK1OizkNwX7HCiOGGNNOUZIMplekVHXII6Am9b6z3ArsUl28qwVzzLRzEFPSKtOxXdcsXx0jcLjVfOwVyrw3RYUUd6JW0/DySJ9mz0KB7LXHA4WeQYVfwo+MT6OMC0FQv4ac8jwzqLFZfcF7fE3AbROd3aixSFNGlhlMaA4QQgjiYIW/JxoENtr9K7LMn2zR3dYpQaeqWVM+eDQJasmdkl4LXi8cpzHYp8PfVPb8c4XVEr/x0k36EfD5Jvspw+eowveB5zCVIHG11aLrkK45scazS+luEoA8MpRQ7uUR58fJavpfzBgucSQLksgza8xMKkH4Nh+2ijJhJ//kXbP7DVZcq4ontnb51R3yfCXUn+rPdQe4+FfiKZIHJUwFGxsWngNjJcHFvdU9xtXPE2ciR0wuQDJKALFGTnrq0JnfGC4t9jUHCxe1wRLQ/NNsFRKWTonpxs01H5WBwjRQNS9aMT25vFgsMG4yEa8fuVPvkeM3fY8YZcWf8q/oCrXJuURGU=</Modulus><Exponent>AQAB</Exponent><P>4UNrcPKaYy2AWV9mqpGMzNtKhrEiWH3x29u89CMHtJC7uwTIk7m0hVxdX3nngqjtR8mLcT7kiK0JziGxzdCwd+s4gH2oq+cbb8Rh/jvXWi2uJXESBW2DAnTyKULaQZwaD9IKgKA5vFdrWZv7I3xxD88/MWuwHf5RFTM/Tylopt6iUV0AZ9FCjn5IlI4y3fUP8qhOUbIF/t1uXp60Nqegws99+xRcmpENVj6mC9/fzcOSgYFlLYz9Rl71s1wbDvo71cAjzM8E1lvPO+vM4wDoxgQ4OFzhM4xOyT6x1PiR7QPdNqtnBxNHx/kbmHCHH431NXdmA9e/3q55nuiowyADpQ==</P><Q>tVYpGitJfnWAKwRklS9X1XVWgymA39lIjn86h5AG6pK0b1D7MIQqC0/ERXrepr0cR8QEng4PTPHpiyY7AM7HYgUFlRmqdahK2Uba7dTXoUXCaucYijQADe7UwKFElUftRuoei0revgyY7tgsSN6MUt0JvPaaqCuishVHTg4VwpTa9N+sohat/JMg0X2SIXe0VFaTPJtANMZsSAduVIkJWdCO4WfiRk6qKm4LycxLHHcbb5iL6+NJRuC828SOte3yNfq/jetRPvw2WCHsu/QJ5VRJgkopGK9rq2EdTHoD3xmNuPJFTDq+bMRuY5lZm2x5cU0njAHUQcfoF6FhddBhwQ==</Q><DP>ZTmwrD64ldy6km7GaduiE+RvJvuuXWmrJ4sk6+hZ7BAl7DKIF6oZrtwEsYTMPfC/P8UXvjnu5GQtxc1qYvxmcFzpNQRCqYzezWjISECH02Q3n2eiG4JMnuwCbfw2q8kEBRvz0D0v9Kyr9sabIiUngV02HnUv3SqNMSOoTWBkQKhG9J0AM6bba8DfyLHltcwL8JUlLJz9CLxkfmx+uxi0qxYmnI9X1bVc8uaQI0HlBkfeLAgDeWaj4d2GN6UqG57jCHihHcXhfJohE+IwXcno0CLRSLKkGE/yj4h2zScuG/3iiFCZqZpGZVxRxDy827ck+3O+CfgHpn9s87XFMHnQaQ==</DP><DQ>ect/G9aLLGbbSQlQTWtZAUQocTxFFRSpyRvnQfoYyyDyE/o+XJ3IZ4SR/WDDfxZxkjo0J7ylxjaNeCqbYrV/8XQSBc0RUqlQbJNMpIVatzVVmdvR/bFjf/gz6ZXnrKR82C6TiVcmOFvZtEJ5rA/eDCHuUn8H7YAxbI8iL2kCcIjub550IwI8pfJkDpDav6PY+PSVPBXCkC/dtptXHWxVXX/ZF8hgkHxxisITJN0UbfAJ+3BoOm2UYAi+kJV6jPNexaa/ViEBlt5r2dIfYTZOFzv/i4UoCS55kMhPl3g0dXqCWABRTxv9nqxowHjVWLEI+HKr5zurRutwFb8M6MangQ==</DQ><InverseQ>QOfsHx1OT8fFtXoTQyaFuoN6SYktYwJewaRxwCHj5nlY5/fPnXmtMJBIN21m73v9iRTkdhv0iQ4GzB0zcSiAu7UwFmO5wiYp31A8naq+dNvAAnHNxgEtpT0Dt5ZMh7P+d/ACbkU/iIeGMJX/mqercOgahFPHq+ypGBpj9xecL3TTWwk/Ow8s5pk+5oIRMWI91OUakIARTtOOCh7m2R3w9FWjXt3YimqMqCqc+p1pcH6zuRqQQUamTRd0vxz/zY+fyEPo8EhlKsq3jSBB7GA30OjNcyWv7+try7rWa2OpRCSGXl2GBBbu9AR2NavIjU1YXm1V50QLTsUZ4oxSTqvhkg==</InverseQ><D>A99fRBYCLmVIBtH9cWA4iKCYqSQU6lAaso0sAizQ/iDQ48kdT6SoAWNqul1GyyXWQ17+ce+bJKNCxfib91y5CeS98tmXxOxI5+VLLepMN2+t61ff1uIL5JgMisLOXD0rJBIHe5w/WD0zdhsBEOcSE03XLnhoXe0gh43lzD77Sa4stnxotT/EnEV2IaB4Ec9SMloVjeesbgz8Du74cy35WFSEREB369oXt33aIHJ2jVWzXVOua4Y2xpxAGJaUImcXTwh8aRGgCbd+wK2pKRscOOPBV/WOkKTd/35tiziQ3LNNn1wtxER0t5ZLFJx7At/VSDTMVvrgkIkGAc5/T/BVDbKo3KtZj47sOuzcd1g1HqDdZbbiMN6GHHq8FYNTbwLxdOoYh+qSWsAR2+OoW6L731jQEuZqKRJNvoGcAUBp1xUpeyu+KotxFrXSnhEC01ZuC003oVipYMPvjpqKbY92xNIdQ1kN/yDtnQQB7KDHPQelFAuWmNXmOc4BBd6tWljBTwHkh0YVDJ0bCUoyN6Guelz8uGkTESpzwFkLfxx5wuPBUzxLqPKqwPBDunNgtWgiNjvYZI3kNNHPa75z46jJRWrr1MZUDFvNZq1DOux9TySARqJetdY1lKPjr4ktZ24OZswka5KKqq2MejE4+iI2C7k+TmT42Ts8AdOKOcqXXkE=</D></RSAKeyValue>";
        private const string Modulus = "n5B7x8adptwKBwlF2ulATKplgF98JfzMewq0buYjWhfvrgttTYRAvdQo4OGEaPHYnd6a99LqE9iJZIC33YnpIa0BKmSdAocO7M56wirJKVsI2Q6WXopE0BmMdIUX7rwRSthj/Sfy4V7S+aD8e/x0nui7df/L+FqXjFAlTJ4CuuPK1OizkNwX7HCiOGGNNOUZIMplekVHXII6Am9b6z3ArsUl28qwVzzLRzEFPSKtOxXdcsXx0jcLjVfOwVyrw3RYUUd6JW0/DySJ9mz0KB7LXHA4WeQYVfwo+MT6OMC0FQv4ac8jwzqLFZfcF7fE3AbROd3aixSFNGlhlMaA4QQgjiYIW/JxoENtr9K7LMn2zR3dYpQaeqWVM+eDQJasmdkl4LXi8cpzHYp8PfVPb8c4XVEr/x0k36EfD5Jvspw+eowveB5zCVIHG11aLrkK45scazS+luEoA8MpRQ7uUR58fJavpfzBgucSQLksgza8xMKkH4Nh+2ijJhJ//kXbP7DVZcq4ontnb51R3yfCXUn+rPdQe4+FfiKZIHJUwFGxsWngNjJcHFvdU9xtXPE2ciR0wuQDJKALFGTnrq0JnfGC4t9jUHCxe1wRLQ/NNsFRKWTonpxs01H5WBwjRQNS9aMT25vFgsMG4yEa8fuVPvkeM3fY8YZcWf8q/oCrXJuURGU=";
        private const string Exponent = "AQAB";
        private const string P = "4UNrcPKaYy2AWV9mqpGMzNtKhrEiWH3x29u89CMHtJC7uwTIk7m0hVxdX3nngqjtR8mLcT7kiK0JziGxzdCwd+s4gH2oq+cbb8Rh/jvXWi2uJXESBW2DAnTyKULaQZwaD9IKgKA5vFdrWZv7I3xxD88/MWuwHf5RFTM/Tylopt6iUV0AZ9FCjn5IlI4y3fUP8qhOUbIF/t1uXp60Nqegws99+xRcmpENVj6mC9/fzcOSgYFlLYz9Rl71s1wbDvo71cAjzM8E1lvPO+vM4wDoxgQ4OFzhM4xOyT6x1PiR7QPdNqtnBxNHx/kbmHCHH431NXdmA9e/3q55nuiowyADpQ==";
        private const string Q = "tVYpGitJfnWAKwRklS9X1XVWgymA39lIjn86h5AG6pK0b1D7MIQqC0/ERXrepr0cR8QEng4PTPHpiyY7AM7HYgUFlRmqdahK2Uba7dTXoUXCaucYijQADe7UwKFElUftRuoei0revgyY7tgsSN6MUt0JvPaaqCuishVHTg4VwpTa9N+sohat/JMg0X2SIXe0VFaTPJtANMZsSAduVIkJWdCO4WfiRk6qKm4LycxLHHcbb5iL6+NJRuC828SOte3yNfq/jetRPvw2WCHsu/QJ5VRJgkopGK9rq2EdTHoD3xmNuPJFTDq+bMRuY5lZm2x5cU0njAHUQcfoF6FhddBhwQ==";
        private const string DP = "ZTmwrD64ldy6km7GaduiE+RvJvuuXWmrJ4sk6+hZ7BAl7DKIF6oZrtwEsYTMPfC/P8UXvjnu5GQtxc1qYvxmcFzpNQRCqYzezWjISECH02Q3n2eiG4JMnuwCbfw2q8kEBRvz0D0v9Kyr9sabIiUngV02HnUv3SqNMSOoTWBkQKhG9J0AM6bba8DfyLHltcwL8JUlLJz9CLxkfmx+uxi0qxYmnI9X1bVc8uaQI0HlBkfeLAgDeWaj4d2GN6UqG57jCHihHcXhfJohE+IwXcno0CLRSLKkGE/yj4h2zScuG/3iiFCZqZpGZVxRxDy827ck+3O+CfgHpn9s87XFMHnQaQ==";
        private const string DQ = "ect/G9aLLGbbSQlQTWtZAUQocTxFFRSpyRvnQfoYyyDyE/o+XJ3IZ4SR/WDDfxZxkjo0J7ylxjaNeCqbYrV/8XQSBc0RUqlQbJNMpIVatzVVmdvR/bFjf/gz6ZXnrKR82C6TiVcmOFvZtEJ5rA/eDCHuUn8H7YAxbI8iL2kCcIjub550IwI8pfJkDpDav6PY+PSVPBXCkC/dtptXHWxVXX/ZF8hgkHxxisITJN0UbfAJ+3BoOm2UYAi+kJV6jPNexaa/ViEBlt5r2dIfYTZOFzv/i4UoCS55kMhPl3g0dXqCWABRTxv9nqxowHjVWLEI+HKr5zurRutwFb8M6MangQ==";
        private const string InverseQ = "QOfsHx1OT8fFtXoTQyaFuoN6SYktYwJewaRxwCHj5nlY5/fPnXmtMJBIN21m73v9iRTkdhv0iQ4GzB0zcSiAu7UwFmO5wiYp31A8naq+dNvAAnHNxgEtpT0Dt5ZMh7P+d/ACbkU/iIeGMJX/mqercOgahFPHq+ypGBpj9xecL3TTWwk/Ow8s5pk+5oIRMWI91OUakIARTtOOCh7m2R3w9FWjXt3YimqMqCqc+p1pcH6zuRqQQUamTRd0vxz/zY+fyEPo8EhlKsq3jSBB7GA30OjNcyWv7+try7rWa2OpRCSGXl2GBBbu9AR2NavIjU1YXm1V50QLTsUZ4oxSTqvhkg==";
        private const string D = "A99fRBYCLmVIBtH9cWA4iKCYqSQU6lAaso0sAizQ/iDQ48kdT6SoAWNqul1GyyXWQ17+ce+bJKNCxfib91y5CeS98tmXxOxI5+VLLepMN2+t61ff1uIL5JgMisLOXD0rJBIHe5w/WD0zdhsBEOcSE03XLnhoXe0gh43lzD77Sa4stnxotT/EnEV2IaB4Ec9SMloVjeesbgz8Du74cy35WFSEREB369oXt33aIHJ2jVWzXVOua4Y2xpxAGJaUImcXTwh8aRGgCbd+wK2pKRscOOPBV/WOkKTd/35tiziQ3LNNn1wtxER0t5ZLFJx7At/VSDTMVvrgkIkGAc5/T/BVDbKo3KtZj47sOuzcd1g1HqDdZbbiMN6GHHq8FYNTbwLxdOoYh+qSWsAR2+OoW6L731jQEuZqKRJNvoGcAUBp1xUpeyu+KotxFrXSnhEC01ZuC003oVipYMPvjpqKbY92xNIdQ1kN/yDtnQQB7KDHPQelFAuWmNXmOc4BBd6tWljBTwHkh0YVDJ0bCUoyN6Guelz8uGkTESpzwFkLfxx5wuPBUzxLqPKqwPBDunNgtWgiNjvYZI3kNNHPa75z46jJRWrr1MZUDFvNZq1DOux9TySARqJetdY1lKPjr4ktZ24OZswka5KKqq2MejE4+iI2C7k+TmT42Ts8AdOKOcqXXkE=";
        private static readonly Encoding Encoder = Encoding.UTF8;

        #endregion Private Fields + Properties

        #region Public Methods

        public static string Decrypt(string encryptedString)
        {
            using (var rsa = RSA.Create())
            {
                //rsa.ImportParameters(new RSAParameters {
                //    D = Convert.FromBase64String(D),
                //    DP = Convert.FromBase64String(DP),
                //    DQ = Convert.FromBase64String(DQ),
                //    Exponent = Convert.FromBase64String(Exponent),
                //    InverseQ = Convert.FromBase64String(InverseQ),
                //    Modulus = Convert.FromBase64String(Modulus),
                //    P = Convert.FromBase64String(P),
                //    Q = Convert.FromBase64String(Q)
                //});

                rsa.FromXmlString(PrivateKey);
                var paddedEncryptedBytes = Convert.FromBase64String(encryptedString.Substring(24));
                var paddedEncryptedBase64String = Encoder.GetString(paddedEncryptedBytes);
                var encryptedBase64String = paddedEncryptedBase64String.Substring(32, paddedEncryptedBase64String.Length - 64);
                var encryptedBytes = Convert.FromBase64String(encryptedBase64String);
                var stringBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA512);
                var rawString = Encoder.GetString(stringBytes);

                return rawString;
            }
        }

        public static string Encrypt(string rawString)
        {
            using (var rsa = RSA.Create())
            {
                //rsa.ImportParameters(new RSAParameters
                //{
                //    D = Convert.FromBase64String(D),
                //    DP = Convert.FromBase64String(DP),
                //    DQ = Convert.FromBase64String(DQ),
                //    Exponent = Convert.FromBase64String(Exponent),
                //    InverseQ = Convert.FromBase64String(InverseQ),
                //    Modulus = Convert.FromBase64String(Modulus),
                //    P = Convert.FromBase64String(P),
                //    Q = Convert.FromBase64String(Q)
                //});

                rsa.FromXmlString(PrivateKey);
                var stringBytes = Encoder.GetBytes(rawString);
                var encryptedBytes = rsa.Encrypt(stringBytes, RSAEncryptionPadding.OaepSHA512);
                var encryptedBase64String = Convert.ToBase64String(encryptedBytes);
                var leftGarbage = Guid.NewGuid().ToString("N");
                var rightGarbage = Guid.NewGuid().ToString("N");
                var paddedEncryptedBase64String = $"{leftGarbage}{encryptedBase64String}{rightGarbage}";
                var paddedEncryptedBytes = Encoder.GetBytes(paddedEncryptedBase64String);
                var paddedEncryptedBase64StringWithGarbage = $"{Guid.NewGuid().ToString("N").Substring(0, 24)}{Convert.ToBase64String(paddedEncryptedBytes)}";

                return paddedEncryptedBase64StringWithGarbage;
            }
        }

        #endregion Public Methods
    }
}
