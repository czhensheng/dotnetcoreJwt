using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Apidemo2
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var audienceConfig = Configuration.GetSection("Audience");
            var symmetricKeyAsBase64 = audienceConfig["Secret"];
            var keyByteArray = Encoding.ASCII.GetBytes(symmetricKeyAsBase64);
            var signingKey = new SymmetricSecurityKey(keyByteArray);
            //claims集合
            var tokenValidationParameters = new TokenValidationParameters
            {

                //令牌签名将使用私钥进行验证,签名密钥必须匹配！
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,

                // 验证令牌发行者（签发者）
                ValidateIssuer = true,

                ValidIssuer = audienceConfig["Issuer"],

                // 验证接收者
                ValidateAudience = true,
                ValidAudience = audienceConfig["Audience"],

                //验证token有效期
                ValidateLifetime = true,

                //有效期偏移量
                ClockSkew = TimeSpan.Zero //0.00:00:00.0
            };
            services.AddAuthentication(options =>
            {
                //默认认证方案
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                //
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(o =>
            {
                //不使用https
                //o.RequireHttpsMetadata = false;
                //token验证参数 对应上面的claims集合
                o.TokenValidationParameters = tokenValidationParameters;
            });
            // 添加到 IoC 容器
            services.AddSingleton(tokenValidationParameters);

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseMvc();

            
            
        }
    }
}
