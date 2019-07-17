using Org.BouncyCastle.Crypto;

namespace AspNetCore.SecurityCommon
{
    public interface IRSAPublicProvider : IMacProvider
    {
        AsymmetricKeyParameter PublicKey { get; }
    }
}
