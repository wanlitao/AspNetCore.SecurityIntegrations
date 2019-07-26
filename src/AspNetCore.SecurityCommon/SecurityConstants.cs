using System;

namespace AspNetCore.SecurityCommon
{
    public static class SecurityConstants
    {
        public const string HttpHeaders_Timestamp = "X-SSL-Timestamp";
        public const string HttpHeaders_SecurityKey = "X-SSL-SecurityKey";
        public const string HttpHeaders_SignatureKey = "X-SSL-SignatureKey";
        public const string HttpHeaders_Signature = "X-SSL-Signature";

        public static DateTime Timestamp_StartUtcDateTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    }
}
