using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
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
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace ApiDemo3
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
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true, //是否验证Issuer
                        ValidateAudience = true, //是否验证Audience
                        ValidateLifetime = true, //是否验证失效时间
                        ValidateIssuerSigningKey = true, //是否验证SecurityKey
                        ValidAudience = "ace.com", //Audience
                        ValidIssuer = "ace.com", //Issuer，这两项和前面签发jwt的设置一致
                        IssuerSigningKey =
                            new SymmetricSecurityKey(
                                Encoding.UTF8.GetBytes("Y2F0Y2yhciUyMHdvbmclMFWfsaZlJTIwLm5ldA==")) //拿到SecurityKey
                    };
                    options.Events = new JwtBearerEvents
                    {
                        OnChallenge = context =>
                        {

                            context.Response.StatusCode = 200;
                            byte[] body = Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(new 
                            {
                                code = 401,
                                data = "",
                                msg = "登录失效，请重新登陆"
                            }));
                            context.Response.ContentType = "application/json";
                            context.Response.Body.Write(body, 0, body.Length);
                            context.HandleResponse();

                            //}
                            return Task.CompletedTask;
                        },
                   
                            OnMessageReceived = context =>
                            {
                                if (!StringValues.IsNullOrEmpty(context.Request.Headers["Authorization"]))
                                {
                                    try
                                    {
                                        //todo  验证多app登陆
                                        var startLength = "Bearer ".Length;
                                        var tokenStr = context.Request.Headers["Authorization"].ToString();
                                        var token = new JwtSecurityTokenHandler().ReadJwtToken(tokenStr.Substring(startLength, tokenStr.Length - startLength));
                                        string userName = token.Claims.ToList().First(o => o.Type == System.Security.Claims.ClaimTypes.Name).Value.ToString();
                                        string clientId = token.Claims.ToList().First(o => o.Type == "ClientId").Value.ToString();
                            
                                        if (userName=="czs")//验证逻辑根据业务实现
                                            context.Request.Headers["Authorization"] = string.Empty;
                                    }
                                    catch (Exception ex)
                                    {
                                        context.Request.Headers["Authorization"] = string.Empty;
                                    }

                                }
                                return Task.CompletedTask;
                            }
                        
                };
                });

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

        app.UseAuthentication();
        app.UseHttpsRedirection();
        app.UseMvc();
    }
}
}
