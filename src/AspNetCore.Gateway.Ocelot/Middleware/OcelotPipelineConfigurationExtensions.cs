using Microsoft.Extensions.DependencyInjection;
using Ocelot.Middleware;
using System;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace AspNetCore.Gateway.Ocelot
{
    public static class OcelotPipelineConfigurationExtensions
    {
        internal const string InvokeMethodName = "Invoke";
        internal const string InvokeAsyncMethodName = "InvokeAsync";

        public static OcelotPipelineConfiguration UsePreSSLAuthentication(this OcelotPipelineConfiguration configuration,
            IServiceProvider serviceProvider)
        {
            if (serviceProvider == null)
                throw new ArgumentNullException(nameof(serviceProvider));

            configuration.PreAuthenticationMiddleware = 
                CompileOcelotMiddleware<SSLAuthenticationMiddleware>(serviceProvider).AsPipelineConfigurationMiddleware();

            return configuration;
        }

        public static OcelotPipelineConfiguration UseRSAConfiguration(this OcelotPipelineConfiguration configuration,
            string clientRequestPath)
        {
            ValidatePipelineMapPath(clientRequestPath);

            configuration.MapWhenOcelotPipeline.Add(app =>
            {
                app.UseRSAConfiguration(clientRequestPath);

                return context => context.HttpContext.Request.Path.StartsWithSegments(clientRequestPath);
            });

            return configuration;
        }

        #region Middleware Compile
        private static Func<DownstreamContext, OcelotRequestDelegate, Task> CompileOcelotMiddleware<TMiddleware>(
            IServiceProvider serviceProvider, params object[] args)
        {
            return CompileOcelotMiddleware(serviceProvider, typeof(TMiddleware), args);
        }

        private static Func<DownstreamContext, OcelotRequestDelegate, Task> CompileOcelotMiddleware(
            IServiceProvider serviceProvider, Type middleware, params object[] args)
        {
            return (context, next) =>
            {
                var methods = middleware.GetMethods(BindingFlags.Instance | BindingFlags.Public);
                var invokeMethods = methods.Where(m =>
                    string.Equals(m.Name, InvokeMethodName, StringComparison.Ordinal)
                    || string.Equals(m.Name, InvokeAsyncMethodName, StringComparison.Ordinal)
                    ).ToArray();

                if (invokeMethods.Length > 1)
                {
                    throw new InvalidOperationException("middleware exists multi invoke method");
                }

                if (invokeMethods.Length == 0)
                {
                    throw new InvalidOperationException("middleware not found any invoke method");
                }

                var methodInfo = invokeMethods[0];
                if (!typeof(Task).IsAssignableFrom(methodInfo.ReturnType))
                {
                    throw new InvalidOperationException($"middleware invoke method should return {nameof(Task)}");
                }

                var parameters = methodInfo.GetParameters();
                if (parameters.Length != 1 || parameters[0].ParameterType != typeof(DownstreamContext))
                {
                    throw new InvalidOperationException($"middleware invoke method should be only one parameter of {nameof(DownstreamContext)}");
                }

                var ctorArgs = new object[args.Length + 1];
                ctorArgs[0] = next;
                Array.Copy(args, 0, ctorArgs, 1, args.Length);

                var instance = ActivatorUtilities.CreateInstance(serviceProvider, middleware, ctorArgs);
                var requestDelegate = (OcelotRequestDelegate)methodInfo.CreateDelegate(typeof(OcelotRequestDelegate), instance);

                return requestDelegate(context);
            };
        }
        #endregion

        private static Func<DownstreamContext, Func<Task>, Task> AsPipelineConfigurationMiddleware(
            this Func<DownstreamContext, OcelotRequestDelegate, Task> ocelotMiddlewareFunction)
        {
            return (context, task) =>
            {
                OcelotRequestDelegate requestDelegate = ctx => task();

                return ocelotMiddlewareFunction(context, requestDelegate);
            };
        }

        private static void ValidatePipelineMapPath(string requestPath)
        {
            if (string.IsNullOrWhiteSpace(requestPath))
                throw new ArgumentNullException(nameof(requestPath));

            if (requestPath.Contains("?"))
                throw new ArgumentException($"{nameof(requestPath)} cannot contain query string values");

            if (!requestPath.StartsWith("/"))
                throw new ArgumentException($"{nameof(requestPath)} should start with '/'");
        }
    }
}
