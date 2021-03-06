﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace APIdemo
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
            //1.x项目中，认证是通过中间件配置的。为您想要支持的每种认证方案调用中间件方法
            //2.0项目中，认证是通过服务配置的。每个认证方案都在Startup.cs的ConfigureServices方法中注册。该方法被替换为。UseIdentityUseAuthentication
            //.net core2的升级改造，官方的说明，所有的 app.UseXxxAuthentication 方法都变成了 service.AddAuthentication(XxxSchema).AddXxx()
            .AddJwtBearer(o =>
            {
                //不使用https
                //o.RequireHttpsMetadata = false;
                //token验证参数 对应上面的claims集合
                //对用户传入的token进行验证，验证规则就是tokenValidationParameters
                //https://jwt.io/ 可以对token进行验证
                o.TokenValidationParameters = tokenValidationParameters;
            });

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            var audienceConfig = Configuration.GetSection("Audience");
            var symmetricKeyAsBase64 = audienceConfig["Secret"];
            var keyByteArray = Encoding.ASCII.GetBytes(symmetricKeyAsBase64);
            var signingKey = new SymmetricSecurityKey(keyByteArray);
            var SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
            var options = new TokenProviderOptions
            {
                Audience = audienceConfig["Audience"],
                Issuer = audienceConfig["Issuer"],
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
            };
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }
            app.UseHttpsRedirection();



            //localhost:xxxx/task1
            //this is 1
            app.Map("/task1", taskapp =>
            {
                taskapp.Run(async context =>
                {
                    await context.Response.WriteAsync("this is 1");
                });
            });

            app.UseAuthentication();
            app.UseMiddleware<TokenProviderMiddleware>(Options.Create(options));
            app.UseMvc();
        }
    }
}
