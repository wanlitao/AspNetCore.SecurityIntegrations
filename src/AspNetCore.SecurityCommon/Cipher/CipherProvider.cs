using FCP.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Text;

namespace AspNetCore.SecurityCommon
{
    public abstract class CipherProvider : ICipherProvider
    {
        protected CipherProvider(string algorithmName)
        {
            if (string.IsNullOrWhiteSpace(algorithmName))
                throw new ArgumentNullException(nameof(algorithmName));

            AlgorithmName = algorithmName;
        }

        public string AlgorithmName { get; }

        protected abstract ICipherParameters EncryptParameters { get; }

        protected abstract ICipherParameters DecryptParameters { get; }

        public virtual byte[] Encrypt(string originStr)
        {
            if (string.IsNullOrWhiteSpace(originStr))
                return null;

            byte[] originbytes = Encoding.UTF8.GetBytes(originStr);
            IBufferedCipher cipher = CipherUtilities.GetCipher(AlgorithmName);
            cipher.Init(true, EncryptParameters);

            return cipher.DoFinal(originbytes);
        }

        public virtual string Decrypt(byte[] encryptBytes)
        {
            if (encryptBytes.isEmpty())
                return string.Empty;
            
            IBufferedCipher cipher = CipherUtilities.GetCipher(AlgorithmName);
            cipher.Init(false, DecryptParameters);

            byte[] recoverBytes = cipher.DoFinal(encryptBytes);
            return Encoding.UTF8.GetString(recoverBytes);
        }
    }
}
