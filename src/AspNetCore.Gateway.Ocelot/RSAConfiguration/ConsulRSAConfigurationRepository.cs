using Consul;
using Ocelot.Cache;
using Ocelot.Configuration;
using Ocelot.Configuration.Repository;
using Ocelot.Logging;
using Ocelot.Provider.Consul;
using Ocelot.Responses;
using System.Text;
using System.Threading.Tasks;

namespace AspNetCore.Gateway.Ocelot
{
    public class ConsulRSAConfigurationRepository : IRSAConfigurationRepository
    {
        private const string _configurationKeyPrefix = "rsa";

        private readonly IConsulClient _consul;    
        private readonly IOcelotCache<string> _cache;

        private readonly IOcelotLogger _logger;

        public ConsulRSAConfigurationRepository(
            IOcelotCache<string> cache,
            IInternalConfigurationRepository internalConfigRepo,
            IConsulClientFactory clientFactory,
            IOcelotLoggerFactory loggerFactory)
        {
            _cache = cache;

            var internalConfig = internalConfigRepo.Get();
            var consulConfig = GetConsulConfiguration(internalConfig);
            _consul = clientFactory.Get(consulConfig);

            _logger = loggerFactory.CreateLogger<ConsulRSAConfigurationRepository>();
        }

        private static ConsulRegistryConfiguration GetConsulConfiguration(Response<IInternalConfiguration> internalConfiguration)
        {
            var serviceDiscoveryConfig = internalConfiguration.Data.ServiceProviderConfiguration;

            return new ConsulRegistryConfiguration(serviceDiscoveryConfig.Host,
                serviceDiscoveryConfig.Port, string.Empty, serviceDiscoveryConfig.Token);
        }

        protected static string PrivateConfigurationKey => $"{_configurationKeyPrefix}/private";

        protected static string PublicConfigurationKey => $"{_configurationKeyPrefix}/public";

        protected async Task<Response<string>> QueryConsulKV(string configKey)
        {
            var queryResult = await _consul.KV.Get(configKey);

            if (queryResult.Response == null)
            {
                return new OkResponse<string>(null);
            }

            var configValue = queryResult.Response.Value;
            var configValueStr = Encoding.UTF8.GetString(configValue);

            return new OkResponse<string>(configValueStr);
        }

        public async Task<Response<string>> GetPrivateKey()
        {
            var privateKey = _cache.Get(PrivateConfigurationKey, _configurationKeyPrefix);

            if (privateKey != null)
            {
                return new OkResponse<string>(privateKey);
            }

            return await QueryConsulKV(PrivateConfigurationKey);
        }

        public async Task<Response<string>> GetPublicKey()
        {
            var publicKey = _cache.Get(PublicConfigurationKey, _configurationKeyPrefix);

            if (publicKey != null)
            {
                return new OkResponse<string>(publicKey);
            }

            return await QueryConsulKV(PublicConfigurationKey);
        }
    }
}
