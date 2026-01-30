using Hrithik.Security.ReplayProtection.Abstractions;
using Hrithik.Security.ReplayProtection.Middleware;
using Hrithik.Security.ReplayProtection.Options;
using Hrithik.Security.ReplayProtection.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Hrithik.Security.ReplayProtection.Extensions
{
    /// <summary>
    /// Provides extension methods for registering and enabling
    /// replay attack protection in an ASP.NET Core application.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers replay attack protection services and configuration
        /// with the dependency injection container.
        /// </summary>
        /// <param name="services">
        /// The service collection to add the replay protection services to.
        /// </param>
        /// <param name="configure">
        /// An optional action to configure <see cref="ReplayProtectionOptions"/>.
        /// If not provided, default options will be used.
        /// </param>
        /// <returns>
        /// The same <see cref="IServiceCollection"/> instance so that
        /// additional calls can be chained.
        /// </returns>
        /// <remarks>
        /// By default, an in-memory nonce store is registered.
        /// For production and distributed systems, it is recommended
        /// to replace it with a distributed implementation such as
        /// <see cref="DistributedCacheNonceStore"/>.
        /// </remarks>
        public static IServiceCollection AddReplayProtection(
            this IServiceCollection services,
            Action<ReplayProtectionOptions>? configure = null)
        {
            if (configure != null)
            {
                services.Configure(configure);
            }
            else
            {
                services.Configure<ReplayProtectionOptions>(_ => { });
            }

            services.AddSingleton<INonceStore, InMemoryNonceStore>();

            return services;
        }

        /// <summary>
        /// Adds the replay protection middleware to the HTTP request pipeline.
        /// </summary>
        /// <param name="app">
        /// The application builder used to configure the request pipeline.
        /// </param>
        /// <returns>
        /// The same <see cref="IApplicationBuilder"/> instance so that
        /// additional middleware can be chained.
        /// </returns>
        /// <remarks>
        /// This middleware should be registered early in the pipeline,
        /// before endpoint execution, to ensure all protected requests
        /// are validated.
        /// </remarks>
        public static IApplicationBuilder UseReplayProtection(
            this IApplicationBuilder app)
        {
            return app.UseMiddleware<ReplayProtectionMiddleware>();
        }
    }
}
