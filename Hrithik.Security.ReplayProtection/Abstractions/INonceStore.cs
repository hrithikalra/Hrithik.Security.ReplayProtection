namespace Hrithik.Security.ReplayProtection.Abstractions
{
    /// <summary>
    /// Defines a storage mechanism for tracking request fingerprints
    /// to detect and prevent replay attacks.
    /// </summary>
    /// <remarks>
    /// Implementations should ensure that stored keys automatically
    /// expire after the specified time-to-live (TTL).
    /// This interface is designed to support both in-memory and
    /// distributed storage backends.
    /// </remarks>
    public interface INonceStore
    {
        /// <summary>
        /// Checks whether the specified fingerprint already exists
        /// in the store.
        /// </summary>
        /// <param name="key">
        /// A unique request fingerprint derived from request metadata.
        /// </param>
        /// <param name="ct">
        /// A cancellation token for the asynchronous operation.
        /// </param>
        /// <returns>
        /// <c>true</c> if the fingerprint exists (replay detected);
        /// otherwise, <c>false</c>.
        /// </returns>
        Task<bool> ExistsAsync(string key, CancellationToken ct = default);

        /// <summary>
        /// Stores the specified request fingerprint with an expiration time.
        /// </summary>
        /// <param name="key">
        /// A unique request fingerprint derived from request metadata.
        /// </param>
        /// <param name="ttl">
        /// The duration for which the fingerprint should remain valid.
        /// After this period, the fingerprint must expire automatically.
        /// </param>
        /// <param name="ct">
        /// A cancellation token for the asynchronous operation.
        /// </param>
        Task StoreAsync(string key, TimeSpan ttl, CancellationToken ct = default);
    }
}
