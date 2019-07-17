using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Text;

namespace AspNetCore.SecurityCommon
{
    public class RSAPublicProvider : MacProvider, IRSAPublicProvider
    {
        private Lazy<AsymmetricKeyParameter> _lazyPublicKey;

        private RSAPublicProvider(string algorithmName)
            : base(algorithmName)
        { }

        public AsymmetricKeyParameter PublicKey => _lazyPublicKey.Value;

        protected override ICipherParameters Parameters => PublicKey;

        public override byte[] Encrypt(string originStr)
        {
            if (string.IsNullOrWhiteSpace(originStr))
                return null;

            byte[] originbytes = Encoding.UTF8.GetBytes(originStr);
            IBufferedCipher cipher = CipherUtilities.GetCipher(AlgorithmName);
            cipher.Init(true, Parameters);

            return cipher.DoFinal(originbytes);
        }

        #region Read Key
        private static AsymmetricKeyParameter ReadRSAPublicKeyFromFile(string publicKeyFileName)
        {
            var publicKeyStream = SecurityUtil.GetFileStreamFromAppDomainDirectory(publicKeyFileName);
            if (publicKeyStream == null)
                throw new ArgumentException("read public key file stream fail");

            using (var reader = new StreamReader(publicKeyStream))
            {
                var pemReader = new PemReader(reader);
                return pemReader.ReadObject() as AsymmetricKeyParameter;
            }
        }

        private static AsymmetricKeyParameter ReadRSAPublicKey(string publicKey)
        {
            if (string.IsNullOrWhiteSpace(publicKey))
                throw new ArgumentNullException(nameof(publicKey));

            using (var reader = new StringReader(publicKey))
            {
                var pemReader = new PemReader(reader);
                return pemReader.ReadObject() as AsymmetricKeyParameter;
            }
        }
        #endregion

        #region factory methods
        public static RSAPublicProvider FromKeyFile(string algorithmName, string publicKeyFileName)
        {
            if (string.IsNullOrWhiteSpace(publicKeyFileName))
                throw new ArgumentNullException(nameof(publicKeyFileName));

            return new RSAPublicProvider(algorithmName)
            {
                _lazyPublicKey = new Lazy<AsymmetricKeyParameter>(() => ReadRSAPublicKeyFromFile(publicKeyFileName))
            };
        }

        public static RSAPublicProvider FromKey(string algorithmName, string publicKey)
        {
            if (string.IsNullOrWhiteSpace(publicKey))
                throw new ArgumentNullException(nameof(publicKey));

            return new RSAPublicProvider(algorithmName)
            {
                _lazyPublicKey = new Lazy<AsymmetricKeyParameter>(() => ReadRSAPublicKey(publicKey))
            };
        }

        public static RSAPublicProvider ECBPkcs1FromKeyFile(string publicKeyFileName) => FromKeyFile("RSA/ECB/PKCS1Padding", publicKeyFileName);

        public static RSAPublicProvider ECBPkcs1FromKey(string publicKey) => FromKey("RSA/ECB/PKCS1Padding", publicKey);
        #endregion
    }
}
