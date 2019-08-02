using Drore.SSL.Ocelot;
using HEF.Extensions.Ocelot.RSAConfiguration;
using HEF.Security.BouncyCastle;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.HealthChecks;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using Ocelot.Provider.Consul;
using Ocelot.Provider.Polly;
using System.Threading.Tasks;

namespace AspNetCore.Gateway.Ocelot
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        private readonly IConfigurationSection _appSettings;

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            _appSettings = Configuration.GetSection("appSettings");
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddOcelot()
                .AddConsul()
                .AddPolly()
                .AddConsulRSAConfiguration();

            services.AddSingleton<ICryptoEncoding, Base64CryptoEncoding>();

            services.AddHealthChecks(checks =>
            {
                checks.AddValueTaskCheck("http endpoint",
                    () => new ValueTask<IHealthCheckResult>(HealthCheckResult.Healthy("Ok")));
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseOcelot(config => 
                config.UseDroreSSLAuthentication(app.ApplicationServices)
                .UseRSAConfiguration("/rsa")
            ).Wait();
        }
    }
}
