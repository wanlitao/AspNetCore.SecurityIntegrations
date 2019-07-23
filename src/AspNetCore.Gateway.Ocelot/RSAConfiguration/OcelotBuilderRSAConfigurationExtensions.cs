using Microsoft.Extensions.DependencyInjection.Extensions;
using Ocelot.Cache;
using Ocelot.DependencyInjection;

namespace AspNetCore.Gateway.Ocelot
{
    public static class OcelotBuilderRSAConfigurationExtensions
    {
        public static IOcelotBuilder AddConsulRSAConfiguration(this IOcelotBuilder builder)
        {
            builder.Services.TryAddSingleton<IOcelotCache<string>, InMemoryCache<string>>();
            builder.Services.TryAddSingleton<IRSAConfigurationRepository, ConsulRSAConfigurationRepository>();
            
            return builder;
        }
    }
}
