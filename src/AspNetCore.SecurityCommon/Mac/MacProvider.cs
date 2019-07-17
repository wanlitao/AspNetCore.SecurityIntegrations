using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Text;

namespace AspNetCore.SecurityCommon
{
    public abstract class MacProvider : IMacProvider
    {
        protected MacProvider(string algorithmName)
        {
            if (string.IsNullOrWhiteSpace(algorithmName))
                throw new ArgumentNullException(nameof(algorithmName));

            AlgorithmName = algorithmName;
        }

        public string AlgorithmName { get; }

        protected abstract ICipherParameters Parameters { get; }

        public virtual byte[] Encrypt(string originStr)
        {
            if (string.IsNullOrWhiteSpace(originStr))
                return null;

            var originbytes = Encoding.UTF8.GetBytes(originStr);
            IMac mac = MacUtilities.GetMac(AlgorithmName);
            mac.Init(Parameters);
            mac.BlockUpdate(originbytes, 0, originbytes.Length);

            var encryptBytes = new byte[mac.GetMacSize()];
            mac.DoFinal(encryptBytes, 0);

            return encryptBytes;
        }
    }
}
