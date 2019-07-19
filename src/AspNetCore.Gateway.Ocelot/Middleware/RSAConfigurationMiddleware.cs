using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Ocelot.Logging;
using Ocelot.Middleware;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace AspNetCore.Gateway.Ocelot
{
    public class RSAConfigurationMiddleware : OcelotMiddleware
    {
        private readonly IConfiguration _configuration;
        private readonly IConfigurationSection _appSettings;

        private readonly OcelotRequestDelegate _next;

        private readonly string _clientRequestPath;
        private readonly string _rsaPublicRequestPath;

        public RSAConfigurationMiddleware(OcelotRequestDelegate next,
            IConfiguration configuration, IOcelotLoggerFactory loggerFactory,
            string clientRequestPath)            
            : base(loggerFactory.CreateLogger<SSLAuthenticationMiddleware>())
        {
            _next = next;

            _configuration = configuration;
            _appSettings = configuration.GetSection("appSettings");

            _clientRequestPath = clientRequestPath;
            _rsaPublicRequestPath = $"{clientRequestPath}/public";
        }

        public async Task Invoke(DownstreamContext context)
        {
            if (IsRSAPublicKeyRequest(context.HttpContext))
            {
                context.DownstreamResponse = new DownstreamResponse(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("request rsa public key")
                });
                return;
            }

            await _next.Invoke(context);
        }

        private bool IsRSAPublicKeyRequest(HttpContext context)
        {
            return context.Request.Path == _rsaPublicRequestPath;
        }
    }
}
