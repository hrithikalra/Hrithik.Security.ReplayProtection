namespace Hrithik.Security.ReplayProtection.Options
{
    /// <summary>
    /// Represents configuration options for replay attack protection.
    /// </summary>
    /// <remarks>
    /// These options control how incoming HTTP requests are validated
    /// for freshness and uniqueness to prevent replay attacks.
    /// </remarks>
    public sealed class ReplayProtectionOptions
    {
        /// <summary>
        /// Gets or sets the name of the HTTP header that contains
        /// the unique request nonce.
        /// </summary>
        /// <remarks>
        /// The default value is <c>X-Request-Id</c>.
        /// It is recommended to use a cryptographically unique value
        /// such as a UUID.
        /// </remarks>
        public string NonceHeader { get; set; } = "X-Request-Id";

        /// <summary>
        /// Gets or sets the name of the HTTP header that contains
        /// the request timestamp.
        /// </summary>
        /// <remarks>
        /// The default value is <c>X-Timestamp</c>.
        /// The timestamp must be provided as a Unix timestamp
        /// (UTC, seconds).
        /// </remarks>
        public string TimestampHeader { get; set; } = "X-Timestamp";

        /// <summary>
        /// Gets or sets the maximum allowed clock skew between
        /// the client and the server.
        /// </summary>
        /// <remarks>
        /// Requests with timestamps outside this window will be rejected.
        /// The default value is 5 minutes, which is a common
        /// banking-grade security standard.
        /// </remarks>
        public TimeSpan AllowedClockSkew { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Gets or sets the duration for which a request fingerprint
        /// should be retained to detect replay attempts.
        /// </summary>
        /// <remarks>
        /// The default value is 10 minutes.
        /// This value should be greater than or equal to
        /// <see cref="AllowedClockSkew"/>.
        /// </remarks>
        public TimeSpan NonceTtl { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>
        /// Gets or sets a value indicating whether requests missing
        /// required replay protection headers should be rejected.
        /// </summary>
        /// <remarks>
        /// When set to <c>true</c> (default), requests without the
        /// configured nonce or timestamp headers will be rejected.
        /// When set to <c>false</c>, such requests will bypass
        /// replay protection.
        /// </remarks>
        public bool RejectIfMissingHeaders { get; set; } = true;
    }
}
