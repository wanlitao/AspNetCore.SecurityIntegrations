using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;

namespace AspNetCore.SecurityCommon
{
    public class RSAProvider : CipherProvider, IRSAProvider
    {
        private Lazy<AsymmetricCipherKeyPair> _lazyCipherKeyPair;

        private RSAProvider(string algorithmName)
            : base(algorithmName)
        { }

        public AsymmetricKeyParameter PublicKey => _lazyCipherKeyPair.Value.Public;

        public AsymmetricKeyParameter PrivateKey => _lazyCipherKeyPair.Value.Private;

        protected override ICipherParameters EncryptParameters => PublicKey;

        protected override ICipherParameters DecryptParameters => PrivateKey;

        #region Read Key
        private static AsymmetricCipherKeyPair ReadRSAKeyPairFromFile(string privateKeyFileName)
        {
            var privateKeyStream = SecurityUtil.GetFileStreamFromAppDomainDirectory(privateKeyFileName);
            if (privateKeyStream == null)
                throw new ArgumentException("read private key file stream fail");

            using (var reader = new StreamReader(privateKeyStream))
            {
                var pemReader = new PemReader(reader);
                return pemReader.ReadObject() as AsymmetricCipherKeyPair;
            }
        }

        private static AsymmetricCipherKeyPair ReadRSAKeyPair(string privateKey)
        {
            if (string.IsNullOrWhiteSpace(privateKey))
                throw new ArgumentNullException(nameof(privateKey));

            using (var reader = new StringReader(privateKey))
            {
                var pemReader = new PemReader(reader);
                return pemReader.ReadObject() as AsymmetricCipherKeyPair;
            }
        }
        #endregion

        #region factory methods
        public static RSAProvider FromKeyFile(string algorithmName, string privateKeyFileName)
        {
            if (string.IsNullOrWhiteSpace(privateKeyFileName))
                throw new ArgumentNullException(nameof(privateKeyFileName));

            return new RSAProvider(algorithmName)
            {
                _lazyCipherKeyPair = new Lazy<AsymmetricCipherKeyPair>(() => ReadRSAKeyPairFromFile(privateKeyFileName))
            };
        }

        public static RSAProvider FromKey(string algorithmName, string privateKey)
        {
            if (string.IsNullOrWhiteSpace(privateKey))
                throw new ArgumentNullException(nameof(privateKey));

            return new RSAProvider(algorithmName)
            {
                _lazyCipherKeyPair = new Lazy<AsymmetricCipherKeyPair>(() => ReadRSAKeyPair(privateKey))
            };
        }

        public static RSAProvider ECBPkcs1FromKeyFile(string privateKeyFileName) => FromKeyFile("RSA/ECB/PKCS1Padding", privateKeyFileName);

        public static RSAProvider ECBPkcs1FromKey(string privateKey) => FromKey("RSA/ECB/PKCS1Padding", privateKey);
        #endregion
    }
}
