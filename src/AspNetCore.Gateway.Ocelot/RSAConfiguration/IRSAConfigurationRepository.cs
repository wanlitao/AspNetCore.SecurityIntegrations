using Ocelot.Responses;
using System.Threading.Tasks;

namespace AspNetCore.Gateway.Ocelot
{
    public interface IRSAConfigurationRepository
    {
        Task<Response<string>> GetPublicKey();

        Task<Response<string>> GetPrivateKey();
    }
}
