using Hrithik.Security.ReplayProtection.Abstractions;
using Microsoft.Extensions.Caching.Distributed;

namespace Hrithik.Security.ReplayProtection.Stores
{
    /// <summary>
    /// An <see cref="INonceStore"/> implementation that uses
    /// <see cref="IDistributedCache"/> for storing request fingerprints.
    /// </summary>
    /// <remarks>
    /// This implementation is suitable for production and distributed
    /// environments and works with cache providers such as Redis,
    /// SQL Server, or any other <see cref="IDistributedCache"/> implementation.
    /// </remarks>
    public sealed class DistributedCacheNonceStore : INonceStore
    {
        private readonly IDistributedCache _cache;

        /// <summary>
        /// Initializes a new instance of the <see cref="DistributedCacheNonceStore"/> class.
        /// </summary>
        /// <param name="cache">
        /// The distributed cache used to store request fingerprints.
        /// </param>
        public DistributedCacheNonceStore(IDistributedCache cache)
        {
            _cache = cache;
        }

        /// <summary>
        /// Determines whether the specified request fingerprint
        /// already exists in the distributed cache.
        /// </summary>
        /// <param name="key">
        /// A unique request fingerprint.
        /// </param>
        /// <param name="ct">
        /// A cancellation token for the asynchronous operation.
        /// </param>
        /// <returns>
        /// <c>true</c> if the fingerprint exists (replay detected);
        /// otherwise, <c>false</c>.
        /// </returns>
        public async Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            var value = await _cache.GetAsync(key, ct);
            return value != null;
        }

        /// <summary>
        /// Stores the specified request fingerprint in the distributed cache
        /// with an absolute expiration time.
        /// </summary>
        /// <param name="key">
        /// A unique request fingerprint.
        /// </param>
        /// <param name="ttl">
        /// The duration for which the fingerprint should be retained.
        /// </param>
        /// <param name="ct">
        /// A cancellation token for the asynchronous operation.
        /// </param>
        public async Task StoreAsync(string key, TimeSpan ttl, CancellationToken ct = default)
        {
            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            };

            await _cache.SetAsync(
                key,
                Array.Empty<byte>(),
                options,
                ct);
        }
    }
}
