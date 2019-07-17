using FCP.Util;
using System;

namespace AspNetCore.SecurityCommon
{
    public class AESService : ICipherService
    {
        public AESService(IAESProvider provider)
        {
            Provider = provider ?? throw new ArgumentNullException(nameof(provider));
        }

        protected IAESProvider Provider { get; }

        public string Encrypt(string originStr)
        {
            var encryptBytes = Provider.Encrypt(originStr);

            if (encryptBytes.isEmpty())
                return string.Empty;

            return Convert.ToBase64String(encryptBytes);
        }

        public string Decrypt(string encryptStr)
        {
            if (string.IsNullOrWhiteSpace(encryptStr))
                return string.Empty;

            var encryptBytes = Convert.FromBase64String(encryptStr);

            return Provider.Decrypt(encryptBytes);
        }
    }
}
