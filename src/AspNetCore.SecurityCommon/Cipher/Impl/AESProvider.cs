using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Text;

namespace AspNetCore.SecurityCommon
{
    public class AESProvider : CipherProvider, IAESProvider
    {
        private Lazy<ParametersWithIV> _lazyParametersWithIV;

        private AESProvider(string algorithmName, string aesKey, string aesIv)
            : base(algorithmName)
        {
            if (string.IsNullOrWhiteSpace(aesKey))
                throw new ArgumentNullException(nameof(aesKey));

            if (string.IsNullOrWhiteSpace(aesIv))
                throw new ArgumentNullException(nameof(aesIv));

            _lazyParametersWithIV = new Lazy<ParametersWithIV>(() => BuildParametersWithIV(aesKey, aesIv));
        }

        public ParametersWithIV KeyWithIV => _lazyParametersWithIV.Value;

        public byte[] IV => KeyWithIV.GetIV();

        protected override ICipherParameters EncryptParameters => KeyWithIV;

        protected override ICipherParameters DecryptParameters => KeyWithIV;

        private static ParametersWithIV BuildParametersWithIV(string aesKey, string aesIv)
        {
            var keyParameter = new KeyParameter(Encoding.UTF8.GetBytes(aesKey));

            return new ParametersWithIV(keyParameter, Encoding.UTF8.GetBytes(aesIv));
        }

        #region factory methods
        public static AESProvider CBCPkcs5(string aesKey, string aesIv) => new AESProvider("AES/CBC/PKCS5Padding", aesKey, aesIv);
        #endregion
    }
}
