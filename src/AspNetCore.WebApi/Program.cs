using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using System;

namespace AspNetCore.WebApi
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseHealthChecks("/health", TimeSpan.FromSeconds(3))
                .UseStartup<Startup>();
    }
}
