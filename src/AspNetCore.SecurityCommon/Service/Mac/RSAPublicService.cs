using FCP.Util;
using System;

namespace AspNetCore.SecurityCommon
{
    public class RSAPublicService : IMacService
    {
        public RSAPublicService(IRSAPublicProvider provider)
        {
            Provider = provider ?? throw new ArgumentNullException(nameof(provider));
        }

        protected IRSAPublicProvider Provider { get; }

        public string Encrypt(string originStr)
        {
            var encryptBytes = Provider.Encrypt(originStr);

            if (encryptBytes.isEmpty())
                return string.Empty;

            return Convert.ToBase64String(encryptBytes);
        }
    }
}
