using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.HealthChecks;
using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;

namespace AspNetCore.WebApi
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
            services.AddMvcCore().AddAuthorization();

            services.AddVersionedApiExplorer(o => o.GroupNameFormat = "'v'VVV");
            services.AddApiVersioning(o => o.ReportApiVersions = true);

            services.AddMvc(options => options.AddProducesJson())
                .AddJsonOptions(options =>
                {
                    options.UseNullValueIgnore();                    
                })
                .SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            services.AddSwaggerGen(c =>
            {
                var provider = services.BuildServiceProvider().GetRequiredService<IApiVersionDescriptionProvider>();
                c.VersioningSwaggerDoc(provider, "业务Api {0}");

                var xmlPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{Assembly.GetEntryAssembly().GetName().Name}.xml");
                c.IncludeXmlComments(xmlPath);

                // add Bearer authentication
                c.AddBearerAuthentication();
            });

            services.AddHealthChecks(checks =>
            {
                checks.AddValueTaskCheck("http endpoint",
                    () => new ValueTask<IHealthCheckResult>(HealthCheckResult.Healthy("Ok")));
            });

            services.AddCors(options =>
                options.AddDefaultPolicy(builder =>
                    builder.AllowAnyOrigin()
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .AllowCredentials()
                    )
                );
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, IApiVersionDescriptionProvider provider)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseSwagger(c => c.ResolveBasePathByRequestReferer());
            app.UseSwaggerUI(c => c.VersioningSwaggerEndpoints(provider, true));

            app.UseAuthentication();

            app.UseErrorMessageExceptionHandler();

            app.UseCors();

            app.UseMvc();
        }
    }
}
