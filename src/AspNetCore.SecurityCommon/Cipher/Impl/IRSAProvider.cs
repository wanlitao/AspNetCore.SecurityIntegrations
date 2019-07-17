using Org.BouncyCastle.Crypto;

namespace AspNetCore.SecurityCommon
{
    public interface IRSAProvider : ICipherProvider
    {
        AsymmetricKeyParameter PublicKey { get; }

        AsymmetricKeyParameter PrivateKey { get; }
    }
}
