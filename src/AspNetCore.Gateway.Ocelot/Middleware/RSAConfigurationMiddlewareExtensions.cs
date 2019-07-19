using Ocelot.Middleware.Pipeline;

namespace AspNetCore.Gateway.Ocelot
{
    internal static class RSAConfigurationMiddlewareExtensions
    {
        internal static IOcelotPipelineBuilder UseRSAConfiguration(this IOcelotPipelineBuilder builder, string clientRequestPath)
        {
            return builder.UseMiddleware<RSAConfigurationMiddleware>(clientRequestPath);
        }
    }
}
