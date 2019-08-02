using HEF.Security.BouncyCastle;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace AspNetCore.ConsoleClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var hostBuilder = new HostBuilder()
                .ConfigureAppConfiguration((hostContext, configApp) =>
                {
                    configApp.SetBasePath(hostContext.HostingEnvironment.ContentRootPath);
                    configApp.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
                })
                .ConfigureServices((hostContext, services) =>
                {
                    var appSettings = hostContext.Configuration.GetSection("appSettings");

                    services.AddHttpClient("gateway", c =>
                    {
                        c.BaseAddress = new Uri(appSettings["Gateway_Address"]);
                    });

                    services.AddSingleton<ICryptoEncoding, Base64CryptoEncoding>();

                    services.AddHostedService<ClientHostedService>();
                })
                .ConfigureLogging((hostContext, configLogging) =>
                {
                    configLogging.AddConsole();
                });

            await hostBuilder.RunConsoleAsync();
        }
    }
}
