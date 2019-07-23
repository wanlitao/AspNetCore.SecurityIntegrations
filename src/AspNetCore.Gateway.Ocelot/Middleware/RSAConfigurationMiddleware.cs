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

        private readonly IRSAConfigurationRepository _rsaConfigRepo;

        private readonly string _clientRequestPath;
        private readonly string _rsaPublicRequestPath;

        public RSAConfigurationMiddleware(OcelotRequestDelegate next,
            IConfiguration configuration, IOcelotLoggerFactory loggerFactory,
            IRSAConfigurationRepository rsaConfigRepo,
            string clientRequestPath)
            : base(loggerFactory.CreateLogger<SSLAuthenticationMiddleware>())
        {
            _next = next;

            _configuration = configuration;
            _appSettings = configuration.GetSection("appSettings");

            _rsaConfigRepo = rsaConfigRepo;

            _clientRequestPath = clientRequestPath;
            _rsaPublicRequestPath = $"{clientRequestPath}/public";
        }

        public async Task Invoke(DownstreamContext context)
        {
            if (!IsRSAPublicKeyRequest(context.HttpContext))
            {
                await _next.Invoke(context);
                return;
            }
           
            var publicKeyResult = await _rsaConfigRepo.GetPublicKey();

            if (publicKeyResult == null || string.IsNullOrWhiteSpace(publicKeyResult.Data))
            {
                context.DownstreamResponse = BuildDownstreamResponse(HttpStatusCode.NotFound, "not found rsa public key.");
                return;
            }

            context.DownstreamResponse = BuildDownstreamResponse(HttpStatusCode.OK, publicKeyResult.Data);
        }

        private bool IsRSAPublicKeyRequest(HttpContext context)
        {
            return context.Request.Path == _rsaPublicRequestPath;
        }

        private static DownstreamResponse BuildDownstreamResponse(HttpStatusCode statusCode, string contentStr)
        {
            return new DownstreamResponse(new HttpResponseMessage
            {
                StatusCode = statusCode,
                Content = new StringContent(contentStr)
            });
        }
    }
}
