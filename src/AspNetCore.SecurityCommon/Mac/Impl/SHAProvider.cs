using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Text;

namespace AspNetCore.SecurityCommon
{
    public class SHAProvider : MacProvider
    {
        private Lazy<ICipherParameters> _lazyKeyParameter;

        private SHAProvider(string algorithmName, string shaKey)
            : base(algorithmName)
        {
            if (string.IsNullOrWhiteSpace(shaKey))
                throw new ArgumentNullException(nameof(shaKey));

            _lazyKeyParameter = new Lazy<ICipherParameters>(() => new KeyParameter(Encoding.UTF8.GetBytes(shaKey)));
        }

        protected override ICipherParameters Parameters => _lazyKeyParameter.Value;

        #region factory methods
        public static SHAProvider SHA1(string shaKey) => new SHAProvider("HMAC-SHA1", shaKey);

        public static SHAProvider SHA256(string shaKey) => new SHAProvider("HMAC-SHA256", shaKey);
        #endregion
    }
}
