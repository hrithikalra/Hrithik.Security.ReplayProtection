using Hrithik.Security.ReplayProtection.Abstractions;
using System.Collections.Concurrent;

namespace Hrithik.Security.ReplayProtection.Stores
{
    /// <summary>
    /// An in-memory implementation of <see cref="INonceStore"/> used
    /// to track request fingerprints for replay attack detection.
    /// </summary>
    /// <remarks>
    /// This implementation is intended for development, testing,
    /// and single-instance applications.
    /// For production and distributed environments, use
    /// <see cref="DistributedCacheNonceStore"/> instead.
    /// </remarks>
    public sealed class InMemoryNonceStore : INonceStore
    {
        private readonly ConcurrentDictionary<string, DateTimeOffset> _store = new();

        /// <summary>
        /// Determines whether the specified request fingerprint
        /// already exists in the store.
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
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            CleanupExpired();
            return Task.FromResult(_store.ContainsKey(key));
        }

        /// <summary>
        /// Stores the specified request fingerprint with an expiration time.
        /// </summary>
        /// <param name="key">
        /// A unique request fingerprint.
        /// </param>
        /// <param name="ttl">
        /// The duration for which the fingerprint should remain valid.
        /// </param>
        /// <param name="ct">
        /// A cancellation token for the asynchronous operation.
        /// </param>
        public Task StoreAsync(string key, TimeSpan ttl, CancellationToken ct = default)
        {
            var expiresAt = DateTimeOffset.UtcNow.Add(ttl);
            _store[key] = expiresAt;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Removes expired fingerprints from the store.
        /// </summary>
        private void CleanupExpired()
        {
            var now = DateTimeOffset.UtcNow;

            foreach (var item in _store)
            {
                if (item.Value <= now)
                {
                    _store.TryRemove(item.Key, out _);
                }
            }
        }
    }
}
