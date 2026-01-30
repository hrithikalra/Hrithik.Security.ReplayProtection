namespace Hrithik.Security.ReplayProtection.Exceptions
{
    /// <summary>
    /// Represents an exception that is thrown when a replay attack
    /// or an invalid replay protection condition is detected.
    /// </summary>
    /// <remarks>
    /// This exception is intended to be used internally by the replay
    /// protection middleware and can be translated into an appropriate
    /// HTTP error response by the hosting application.
    /// </remarks>
    public sealed class ReplayAttackException : Exception
    {
        /// <summary>
        /// Gets the application-specific error code associated
        /// with the replay protection failure.
        /// </summary>
        public string ErrorCode { get; }

        /// <summary>
        /// Gets the HTTP status code that should be returned to the client
        /// when this exception is raised.
        /// </summary>
        public int StatusCode { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ReplayAttackException"/> class.
        /// </summary>
        /// <param name="message">
        /// A human-readable description of the error.
        /// </param>
        /// <param name="errorCode">
        /// An application-specific error code identifying the failure type
        /// (for example, RP-001, RP-002).
        /// </param>
        /// <param name="statusCode">
        /// The HTTP status code that should be returned to the client.
        /// Defaults to 400 (Bad Request).
        /// </param>
        public ReplayAttackException(
            string message,
            string errorCode,
            int statusCode = 400)
            : base(message)
        {
            ErrorCode = errorCode;
            StatusCode = statusCode;
        }
    }
}
