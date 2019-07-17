using FCP.Util;
using System;

namespace AspNetCore.SecurityCommon
{
    public class RSAService : ICipherService
    {
        public RSAService(IRSAProvider provider)
        {
            Provider = provider ?? throw new ArgumentNullException(nameof(provider));
        }

        protected IRSAProvider Provider { get; }

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
