using Microsoft.AspNetCore.Http;
using System.Security.Cryptography;
using System.Text;

namespace Hrithik.Security.ReplayProtection.Internal
{
    /// <summary>
    /// Builds a deterministic fingerprint for an HTTP request
    /// to detect and prevent replay attacks.
    /// </summary>
    /// <remarks>
    /// The fingerprint is generated from request metadata and a
    /// cryptographic hash of the request payload. Raw request data
    /// is never stored.
    /// </remarks>
    internal static class RequestFingerprintBuilder
    {
        /// <summary>
        /// Builds a unique fingerprint for the given HTTP request.
        /// </summary>
        /// <param name="context">
        /// The current HTTP context containing request information.
        /// </param>
        /// <param name="nonce">
        /// A unique nonce provided by the client.
        /// </param>
        /// <param name="timestamp">
        /// A UTC timestamp provided by the client.
        /// </param>
        /// <param name="cancellationToken">
        /// A cancellation token for the asynchronous operation.
        /// </param>
        /// <returns>
        /// A hexadecimal SHA-256 hash representing the request fingerprint.
        /// </returns>
        public static async Task<string> BuildAsync(
            HttpContext context,
            string nonce,
            string timestamp,
            CancellationToken cancellationToken = default)
        {
            // 1. Read request metadata
            var method = context.Request.Method.ToUpperInvariant();
            var path = context.Request.Path.ToString().ToLowerInvariant();
            var query = context.Request.QueryString.HasValue
                ? context.Request.QueryString.Value!.ToLowerInvariant()
                : string.Empty;

            // 2. Read body safely (if present)
            string bodyHash = string.Empty;

            if (context.Request.ContentLength > 0)
            {
                context.Request.EnableBuffering();

                using var reader = new StreamReader(
                    context.Request.Body,
                    Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false,
                    leaveOpen: true);

                var body = await reader.ReadToEndAsync(cancellationToken);
                context.Request.Body.Position = 0;

                bodyHash = ComputeSha256(body);
            }

            // 3. Build canonical string
            var canonical = string.Join('|',
                nonce,
                timestamp,
                method,
                path,
                query,
                bodyHash);

            // 4. Hash the canonical representation
            return ComputeSha256(canonical);
        }

        private static string ComputeSha256(string input)
        {
            var bytes = Encoding.UTF8.GetBytes(input);

            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(bytes);

            return Convert.ToHexString(hash);
        }
    }
}
