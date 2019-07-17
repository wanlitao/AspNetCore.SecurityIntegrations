using AspNetCore.SecurityCommon;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using FCP.Util;
using FCP.Util.Async;

namespace AspNetCore.ConsoleClient
{
    public class ClientHostedService : IHostedService
    {
        private readonly IConfiguration _config;
        private readonly ILogger _logger;

        private readonly IHttpClientFactory _clientFactory;
        private readonly IMacService _rsaPublicService;

        public ClientHostedService(IConfiguration config, ILogger<ClientHostedService> logger,
            IHttpClientFactory clientFactory, IMacService rsaPublicService)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
            _rsaPublicService = rsaPublicService ?? throw new ArgumentNullException(nameof(rsaPublicService));
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            Console.WriteLine($"{nameof(ClientHostedService)} start...");

            SendSampleApiRequestAsync();

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            Console.WriteLine($"{nameof(ClientHostedService)} stop...");

            return Task.CompletedTask;
        }

        private async Task SendSampleApiRequestAsync()
        {
            await SendApiRequestAsync(HttpMethod.Get, "sample/api/v1/values/name", null);

            await SendApiRequestAsync(HttpMethod.Post, "sample/api/v1/values",
                new JsonStringContent<ValueDetail>(new ValueDetail { Name = "prefix", Value = 10 }));
        }

        private async Task SendApiRequestAsync(HttpMethod method, string requestPath, HttpContent content)
        {
            var client = _clientFactory.CreateClient("gateway");

            var signatureKey = GenerateSignatureKey();

            var aesKey = GenerateAESKey();
            var aesIv = GenerateAESIV();

            var requestMessage = await BuildRequestMessage(method, new Uri(client.BaseAddress, requestPath), content,
                signatureKey, aesKey, aesIv);
            var response = await client.SendAsync(requestMessage);

            await ValidateAndDecryptResponseMessage(response, signatureKey, aesKey, aesIv);
        }

        #region Helper Functions
        private static string GenerateSignatureKey()
        {
            var keyGenerator = GeneratorUtilities.GetKeyGenerator("HMAC-SHA256");

            var keyBytes = keyGenerator.GenerateKey();

            return TypeHelper.MD5(keyBytes);
        }

        private static string GenerateAESKey()
        {
            var keyGenerator = GeneratorUtilities.GetKeyGenerator("AES128");

            var keyBytes = keyGenerator.GenerateKey();            

            return TypeHelper.MD5(keyBytes).Substring(8, 16);
        }

        private static string GenerateAESIV()
        {
            var ivBytes = new byte[16];

            var secureRandom = new SecureRandom();
            secureRandom.NextBytes(ivBytes);

            return TypeHelper.MD5(ivBytes).Substring(8, 16);
        }

        private static IMacService GetSHAService(string shaKey)
        {
            return new MacService(SHAProvider.SHA256(shaKey));
        }

        private static string CalcRequestSignature(HttpRequestMessage request, string timestamp, string shaKey)
        {
            var shaService = GetSHAService(shaKey);

            var sourceStr = $"{request.Method.Method.ToUpper()} {request.RequestUri.AbsolutePath} {timestamp}";

            return shaService.Encrypt(sourceStr);
        }

        private static ICipherService GetAESService(string aesKey, string aesIv)
        {
            return new AESService(AESProvider.CBCPkcs5(aesKey, aesIv));
        }

        private static async Task<HttpContent> EncryptRequestContent(HttpRequestMessage request, ICipherService aesService)
        {
            if (request.Content == null)
                return request.Content;

            var sourceContentStr = await request.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(sourceContentStr))
                return request.Content;

            //Save Original ContentType
            var sourceContentType = request.Content.Headers.ContentType;

            var encryptContentStr = aesService.Encrypt(sourceContentStr);
            var encryptContent = new StringContent(encryptContentStr);
            encryptContent.Headers.ContentType = sourceContentType;

            return encryptContent;
        }

        private async Task<HttpRequestMessage> BuildRequestMessage(HttpMethod method, Uri requestUri, HttpContent content,
            string signatureKey, string aesKey, string aesIv)
        {
            var requestMessage = new HttpRequestMessage
            {
                Method = method,
                RequestUri = requestUri,
                Content = content
            };

            //Timestamp
            var timestamp = (DateTime.UtcNow - SecurityConstants.Timestamp_StartUtcDateTime).TotalMilliseconds;
            var timestampStr = Convert.ToInt64(timestamp).ToString();
            requestMessage.Headers.Add(SecurityConstants.HttpHeaders_Timestamp, timestampStr);

            //SignatureKey            
            var encryptSignatureKey = _rsaPublicService.Encrypt(signatureKey);
            requestMessage.Headers.Add(SecurityConstants.HttpHeaders_SignatureKey, encryptSignatureKey);

            //Signature
            var signature = CalcRequestSignature(requestMessage, timestampStr, signatureKey);
            requestMessage.Headers.Add(SecurityConstants.HttpHeaders_Signature, signature);

            //Securitykey            
            var securityKey = $"{aesKey}||{aesIv}";
            var encryptSecurityKey = _rsaPublicService.Encrypt(securityKey);
            requestMessage.Headers.Add(SecurityConstants.HttpHeaders_SecurityKey, encryptSecurityKey);

            //Encrypt Content
            var aesService = GetAESService(aesKey, aesIv);
            requestMessage.Content = await EncryptRequestContent(requestMessage, aesService);

            return requestMessage;
        }

        private static bool CheckExistsSignatureHeaders(HttpResponseMessage response)
        {
            if (!response.Headers.Contains(SecurityConstants.HttpHeaders_Timestamp))
            {
                Console.WriteLine("Missing Timestamp Header");
                return false;
            }

            if (!response.Headers.Contains(SecurityConstants.HttpHeaders_Signature))
            {
                Console.WriteLine("Missing Signature Header");
                return false;
            }

            return true;
        }

        private static bool CheckTimestampExpire(string timestampHeaderStr, int expireSeconds)
        {
            var timestamp = TypeHelper.parseLong(timestampHeaderStr);

            var dtNowTimestamp = (DateTime.UtcNow - SecurityConstants.Timestamp_StartUtcDateTime).TotalMilliseconds;

            return dtNowTimestamp > timestamp + expireSeconds * 1000;
        }

        private static string CalcResponseSignature(HttpResponseMessage response, string timestamp, string shaKey)
        {
            var shaService = GetSHAService(shaKey);

            var sourceStr = $"{(int)response.StatusCode} {timestamp}";

            return shaService.Encrypt(sourceStr);
        }

        private static async Task<string> DecryptResponseContent(HttpResponseMessage response, ICipherService aesService)
        {
            if (response.Content == null)
                return string.Empty;

            var responseContentStr = await response.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(responseContentStr))
                return string.Empty;
           
            return aesService.Decrypt(responseContentStr);
        }

        private static async Task ValidateAndDecryptResponseMessage(HttpResponseMessage response, string signatureKey, string aesKey, string aesIv)        
        {
            if (!CheckExistsSignatureHeaders(response))
                return;

            //Timestamp
            var timestampHeaderStr = response.Headers.GetValues(SecurityConstants.HttpHeaders_Timestamp)?.FirstOrDefault();
            if (CheckTimestampExpire(timestampHeaderStr, 60))
            {
                Console.WriteLine("Timestamp Expired");
                return;
            }

            //Signature
            var signatureHeaderStr = response.Headers.GetValues(SecurityConstants.HttpHeaders_Signature)?.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(signatureHeaderStr))
            {
                Console.WriteLine("Invalid Signature");
                return;
            }

            //Signature Verification
            var signature = CalcResponseSignature(response, timestampHeaderStr, signatureKey);
            if (string.Compare(signatureHeaderStr, signature) != 0)
            {
                Console.WriteLine("Signature Verification Failed");
                return;
            }

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"response error {response.StatusCode}");
                return;
            }

            var aesService = GetAESService(aesKey, aesIv);
            var contentStr = await DecryptResponseContent(response, aesService);            
            Console.WriteLine($"response content is {contentStr}");
        }
        #endregion
    }

    public class ValueDetail
    {
        public string Name { get; set; }

        public int Value { get; set; }
    }
}
