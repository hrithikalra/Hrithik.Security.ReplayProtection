using Hrithik.Security.ReplayProtection.Abstractions;
using Hrithik.Security.ReplayProtection.Exceptions;
using Hrithik.Security.ReplayProtection.Internal;
using Hrithik.Security.ReplayProtection.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Hrithik.Security.ReplayProtection.Middleware
{
    /// <summary>
    /// Middleware that enforces replay attack protection for incoming HTTP requests.
    /// </summary>
    /// <remarks>
    /// This middleware validates request freshness using a nonce and timestamp
    /// combination and ensures that the same request cannot be processed more than once.
    /// It should be registered early in the ASP.NET Core request pipeline.
    /// </remarks>
    public sealed class ReplayProtectionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ReplayProtectionOptions _options;
        private readonly INonceStore _nonceStore;

        /// <summary>
        /// Initializes a new instance of the <see cref="ReplayProtectionMiddleware"/> class.
        /// </summary>
        /// <param name="next">
        /// The next middleware delegate in the HTTP request pipeline.
        /// </param>
        /// <param name="options">
        /// The replay protection configuration options.
        /// </param>
        /// <param name="nonceStore">
        /// The store used to track processed request fingerprints.
        /// </param>
        public ReplayProtectionMiddleware(
            RequestDelegate next,
            IOptions<ReplayProtectionOptions> options,
            INonceStore nonceStore)
        {
            _next = next;
            _options = options.Value;
            _nonceStore = nonceStore;
        }

        /// <summary>
        /// Processes an incoming HTTP request and applies replay protection validation.
        /// </summary>
        /// <param name="context">
        /// The current HTTP context.
        /// </param>
        /// <returns>
        /// A task that represents the asynchronous middleware operation.
        /// </returns>
        /// <exception cref="ReplayAttackException">
        /// Thrown when a replay attack or invalid replay condition is detected.
        /// </exception>
        public async Task InvokeAsync(HttpContext context)
        {
            // Protect only unsafe HTTP methods
            if (IsSafeMethod(context.Request.Method))
            {
                await _next(context);
                return;
            }

            // 1. Extract required headers
            if (!context.Request.Headers.TryGetValue(_options.NonceHeader, out var nonce) ||
                !context.Request.Headers.TryGetValue(_options.TimestampHeader, out var timestamp))
            {
                if (_options.RejectIfMissingHeaders)
                {
                    throw new ReplayAttackException(
                        "Missing replay protection headers.",
                        "RP-001",
                        StatusCodes.Status400BadRequest);
                }

                await _next(context);
                return;
            }

            // 2. Validate timestamp format
            if (!long.TryParse(timestamp, out var epoch))
            {
                throw new ReplayAttackException(
                    "Invalid timestamp format.",
                    "RP-002",
                    StatusCodes.Status400BadRequest);
            }

            var requestTime = DateTimeOffset.FromUnixTimeSeconds(epoch);
            var now = DateTimeOffset.UtcNow;

            // 3. Validate clock skew
            if (Math.Abs((now - requestTime).TotalSeconds) >
                _options.AllowedClockSkew.TotalSeconds)
            {
                throw new ReplayAttackException(
                    "Request timestamp outside allowed clock skew.",
                    "RP-003",
                    StatusCodes.Status401Unauthorized);
            }

            // 4. Build request fingerprint
            var fingerprint = await RequestFingerprintBuilder.BuildAsync(
                context,
                nonce!,
                timestamp!);

            // 5. Detect replay
            if (await _nonceStore.ExistsAsync(fingerprint))
            {
                throw new ReplayAttackException(
                    "Replay attack detected.",
                    "RP-004",
                    StatusCodes.Status409Conflict);
            }

            // 6. Store fingerprint and continue
            await _nonceStore.StoreAsync(
                fingerprint,
                _options.NonceTtl);

            await _next(context);
        }

        private static bool IsSafeMethod(string method)
            => HttpMethods.IsGet(method) ||
               HttpMethods.IsHead(method) ||
               HttpMethods.IsOptions(method);
    }
}
