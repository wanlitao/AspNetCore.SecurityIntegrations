using Org.BouncyCastle.Crypto.Parameters;

namespace AspNetCore.SecurityCommon
{
    public interface IAESProvider : ICipherProvider
    {
        ParametersWithIV KeyWithIV { get; }

        byte[] IV { get; }
    }
}
