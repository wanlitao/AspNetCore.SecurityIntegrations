using AspNetCore.SecurityCommon;
using FCP.Util;
using Microsoft.Extensions.Configuration;
using Ocelot.Errors;
using Ocelot.Logging;
using Ocelot.Middleware;
using Ocelot.Request.Middleware;
using Ocelot.Responses;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace AspNetCore.Gateway.Ocelot
{
    public class SSLAuthenticationMiddleware : OcelotMiddleware
    {
        internal const string AppSettings_Timestamp_Expire_Seconds = "Timestamp_Expire_Seconds";

        private readonly IConfiguration _configuration;
        private readonly IConfigurationSection _appSettings;

        private readonly OcelotRequestDelegate _next;

        private readonly IRSAConfigurationRepository _rsaConfigRepo;

        public SSLAuthenticationMiddleware(OcelotRequestDelegate next,
            IConfiguration configuration, IOcelotLoggerFactory loggerFactory,
            IRSAConfigurationRepository rsaConfigRepo)
            : base(loggerFactory.CreateLogger<SSLAuthenticationMiddleware>())
        {
            _next = next;

            _configuration = configuration;
            _appSettings = configuration.GetSection("appSettings");

            _rsaConfigRepo = rsaConfigRepo;
        }

        public async Task Invoke(DownstreamContext context)
        {
            if (!IsServiceApiRequest(context))
            {
                await _next.Invoke(context);
                return;
            }
          
            var request = context.DownstreamRequest;

            var error = CheckExistsSSLHttpHeaders(request);
            if (error != null)
            {
                SetPipelineError(context, error);
                return;
            }

            //Timestamp
            var timestampHeaderStr = request.Headers.GetValues(SecurityConstants.HttpHeaders_Timestamp)?.FirstOrDefault();
            var timestampExpireSeconds = TypeHelper.parseInt(_appSettings[AppSettings_Timestamp_Expire_Seconds]);
            if (CheckTimestampExpire(timestampHeaderStr, timestampExpireSeconds))
            {
                SetPipelineError(context, new UnauthenticatedError("Timestamp Expired"));
                return;
            }

            //Signature
            var signatureHeaderStr = request.Headers.GetValues(SecurityConstants.HttpHeaders_Signature)?.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(signatureHeaderStr))
            {
                SetPipelineError(context, new UnauthenticatedError("Invalid Signature"));
                return;
            }

            //RSA Service
            var rsaServiceResult = await GetRSAService();
            if (rsaServiceResult.IsError)
            {
                SetPipelineError(context, rsaServiceResult.Errors.First());
                return;
            }
            var rsaService = rsaServiceResult.Data;

            //SignatureKey
            var signatureKeyHeaderStr = request.Headers.GetValues(SecurityConstants.HttpHeaders_SignatureKey)?.FirstOrDefault();
            var signatureKey = rsaService.Decrypt(signatureKeyHeaderStr);
            if (string.IsNullOrWhiteSpace(signatureKey))
            {
                SetPipelineError(context, new UnauthenticatedError("Invalid Signature Key"));
                return;
            }

            //Signature Verification
            var signature = CalcRequestSignature(request, timestampHeaderStr, signatureKey);
            if (string.Compare(signatureHeaderStr, signature) != 0)
            {
                SetPipelineError(context, new UnauthenticatedError("Signature Verification Failed"));
                return;
            }

            //SecurityKey
            var securityKeyHeaderStr = request.Headers.GetValues(SecurityConstants.HttpHeaders_SecurityKey)?.FirstOrDefault();
            var securityKeySourceStr = rsaService.Decrypt(securityKeyHeaderStr);
            var (aesKey, aesIv) = SplitAESKeyAndIV(securityKeySourceStr);
            if (string.IsNullOrWhiteSpace(aesKey) || string.IsNullOrWhiteSpace(aesIv))
            {
                SetPipelineError(context, new UnauthenticatedError("Invalid Security Key"));
                return;
            }

            var aesService = GetAESService(aesKey, aesIv);
            //Decrypt Request
            request.Content = await GetSourceRequestContent(request, aesService);
            request.ToHttpRequestMessage().Content = request.Content;  //sync to HttpRequestMessage content

            //Remove SSL HttpHeaders
            RemoveSSLHttpHeaders(request);

            await _next.Invoke(context);

            //Encrypt Response
            if (context.DownstreamResponse != null)
            {
                var encryptResponse = await BuildEncryptResponse(context.DownstreamResponse, aesService);

                var responseTimestamp = AddResponseTimestamp(encryptResponse);
                AddResponseSignature(encryptResponse, responseTimestamp, signatureKey);

                context.DownstreamResponse = encryptResponse;
            }
        }

        #region Helper Functions
        private static bool IsServiceApiRequest(DownstreamContext context)
        {
            return !string.IsNullOrWhiteSpace(context.DownstreamReRoute.ServiceName)
                && context.DownstreamReRoute.DownstreamPathTemplate.Value.StartsWith("/api");
        }

        private static Error CheckExistsSSLHttpHeaders(DownstreamRequest request)
        {
            if (!request.Headers.Contains(SecurityConstants.HttpHeaders_Timestamp))
                return new UnauthenticatedError("Missing Timestamp Header");

            if (!request.Headers.Contains(SecurityConstants.HttpHeaders_SecurityKey))
                return new UnauthenticatedError("Missing SecurityKey Header");

            if (!request.Headers.Contains(SecurityConstants.HttpHeaders_SignatureKey))
                return new UnauthenticatedError("Missing Signature Header");

            if (!request.Headers.Contains(SecurityConstants.HttpHeaders_Signature))
                return new UnauthenticatedError("Missing Signature Header");

            return null;
        }

        private static bool CheckTimestampExpire(string timestampHeaderStr, int expireSeconds)
        {
            var timestamp = TypeHelper.parseLong(timestampHeaderStr);

            var dtNowTimestamp = (DateTime.UtcNow - SecurityConstants.Timestamp_StartUtcDateTime).TotalMilliseconds;

            return dtNowTimestamp > timestamp + expireSeconds * 1000;
        }

        private async Task<Response<ICipherService>> GetRSAService()
        {
            var privateKeyResult = await _rsaConfigRepo.GetPrivateKey();

            if (privateKeyResult == null || string.IsNullOrWhiteSpace(privateKeyResult.Data))
                return new ErrorResponse<ICipherService>(new UnauthenticatedError("not found rsa private key."));

            var privateKey = privateKeyResult.Data.Replace("\\n", Environment.NewLine);
            var rsaProvider = RSAProvider.ECBPkcs1FromKey(privateKey);

            return new OkResponse<ICipherService>(new RSAService(rsaProvider));
        }

        private static IMacService GetSHAService(string shaKey)
        {
            return new MacService(SHAProvider.SHA256(shaKey));
        }

        private static string CalcRequestSignature(DownstreamRequest request, string timestamp, string shaKey)
        {
            var shaService = GetSHAService(shaKey);

            var sourceStr = $"{request.Method.ToUpper()} {request.AbsolutePath} {timestamp}";

            return shaService.Encrypt(sourceStr);
        }

        private static (string, string) SplitAESKeyAndIV(string securityKeySourceStr)
        {
            if (string.IsNullOrWhiteSpace(securityKeySourceStr))
                return (string.Empty, string.Empty);

            var securityKeyStrArray = securityKeySourceStr.Split("||");

            if (securityKeyStrArray.isEmpty() || securityKeyStrArray.Length != 2)
                return (string.Empty, string.Empty);

            return (securityKeyStrArray[0], securityKeyStrArray[1]);
        }

        private static ICipherService GetAESService(string aesKey, string aesIv)
        {
            return new AESService(AESProvider.CBCPkcs5(aesKey, aesIv));
        }

        private static async Task<HttpContent> GetSourceRequestContent(DownstreamRequest request, ICipherService aesService)
        {
            if (request.Content == null)
                return request.Content;

            var requestContentStr = await request.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(requestContentStr))
                return request.Content;
            
            //Save Original ContentType
            var requestContentType = request.Content.Headers.ContentType;

            var sourceContentStr = aesService.Decrypt(requestContentStr);
            var sourceContent = new StringContent(sourceContentStr);
            sourceContent.Headers.ContentType = requestContentType;

            return sourceContent;
        }

        private static void RemoveSSLHttpHeaders(DownstreamRequest request)
        {
            var sslHttpHeaders = new string[]
            {
                SecurityConstants.HttpHeaders_Timestamp,
                SecurityConstants.HttpHeaders_SecurityKey,
                SecurityConstants.HttpHeaders_SignatureKey,
                SecurityConstants.HttpHeaders_Signature
            };

            foreach(var sslHttpHeader in sslHttpHeaders)
            {
                request.Headers.Remove(sslHttpHeader);
            }
        }

        private static bool IsSuccessStatusCode(DownstreamResponse response)
        {
            var statusCode = response.StatusCode;

            return ((int)statusCode >= 200) && ((int)statusCode <= 299);
        }

        private static async Task<DownstreamResponse> BuildEncryptResponse(DownstreamResponse response, ICipherService aesService)
        {
            if (!IsSuccessStatusCode(response))
                return response;

            if (response.Content == null)
                return response;
            
            var responseContentStr = await response.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(responseContentStr))
                return response;

            var responseContentType = response.Content.Headers.ContentType;

            var encryptContentStr = aesService.Encrypt(responseContentStr);
            var encryptContent = new StringContent(encryptContentStr);
            encryptContent.Headers.ContentType = responseContentType;

            return new DownstreamResponse(encryptContent, response.StatusCode, response.Headers, response.ReasonPhrase);
        }

        private static string GetTimestamp()
        {
            var timestamp = (DateTime.UtcNow - SecurityConstants.Timestamp_StartUtcDateTime).TotalMilliseconds;

            return Convert.ToInt64(timestamp).ToString();
        }

        private static string AddResponseTimestamp(DownstreamResponse response)
        {
            var timestamp = GetTimestamp();

            response.Headers.Add(new Header(SecurityConstants.HttpHeaders_Timestamp, Enumerable.Repeat(timestamp, 1)));

            return timestamp;
        }

        private static void AddResponseSignature(DownstreamResponse response, string timestamp, string shaKey)
        {
            var shaService = GetSHAService(shaKey);

            var sourceStr = $"{(int)response.StatusCode} {timestamp}";
            var signature = shaService.Encrypt(sourceStr);

            response.Headers.Add(new Header(SecurityConstants.HttpHeaders_Signature, Enumerable.Repeat(signature, 1)));
        }
        #endregion
    }
}
