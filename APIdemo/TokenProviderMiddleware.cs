using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace APIdemo
{
    public class TokenProviderMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly TokenProviderOptions _options;
        public TokenProviderMiddleware(
            RequestDelegate next,
            IOptions<TokenProviderOptions> options,
             IAuthenticationSchemeProvider schemes)
        {
            _next = next;
            _options = options.Value;
            Schemes = schemes;
        }
        public IAuthenticationSchemeProvider Schemes { get; set; }

        /// <summary>
        /// invoke the middleware
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task Invoke(HttpContext context)
        {
            //
            context.Features.Set<IAuthenticationFeature>(new AuthenticationFeature
            {
                OriginalPath = context.Request.Path,
                OriginalPathBase = context.Request.PathBase
            });
            //获取默认方案（或者AuthorizeAttribute指定的方案）的AuthenticationHandler
            var handlers = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
            //这一端是啥我也不知道
            foreach (var scheme in await Schemes.GetRequestHandlerSchemesAsync())
            {
                var handler = await handlers.GetHandlerAsync(context, scheme.Name) as IAuthenticationRequestHandler;
                if (handler != null && await handler.HandleRequestAsync())
                {
                    return;
                }
            }

            var defaultAuthenticate = await Schemes.GetDefaultAuthenticateSchemeAsync();
            if (defaultAuthenticate != null)
            {

                var result = await context.AuthenticateAsync(defaultAuthenticate.Name);
                //一个Principal可以持有多个ClaimsIdentity
                //一组claims构成了一个identity
                //claims的identity就是 ClaimsIdentity
                //ClaimsIdentity理解为“证件”，驾照是一种证件，护照也是一种证件,证件里的信息就是claim，身份证号码：xxx”是一个claim，“姓名：xxx”是另一个claim持有者就是 ClaimsPrincipal
                if (result?.Principal != null)
                {
                    context.User = result.Principal;
                }
            }
            //


            if (!context.Request.Path.Equals(_options.Path, StringComparison.Ordinal))
            {
                await _next(context);
                return;
            }
            // Request must be POST with Content-Type: application/x-www-form-urlencoded
            //必须是post请求，而且  Content-Type: application/x-www-form-urlencoded
            //context.Request.HasFormContentType：检查表单类型的Content-Type
            if (!context.Request.Method.Equals("POST")
               || !context.Request.HasFormContentType)
            {
                await ReturnBadRequest(context);
                return;
            }

            await GenerateAuthorizedResult(context);
        }

        /// <summary>
        /// 验证结果并得到token
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private async Task GenerateAuthorizedResult(HttpContext context)
        {
            var username = context.Request.Form["username"];
            var password = context.Request.Form["password"];
            //验证用户名与密码
            var identity = await GetIdentity(username, password.ToString().Replace("\r", String.Empty).Replace("\n", String.Empty));
            if (identity == null)
            {
                await ReturnBadRequest(context);
                return;
            }

            // Serialize and return the response
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(GetJwt(username));
            await Task.CompletedTask;
        }

        /// <summary>
        /// 验证用户
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private Task<ClaimsIdentity> GetIdentity(string username, string password)
        {
            var isValidated = username == "czs" && password == "123456";
            if (isValidated)
            {
                //Task.FromResult用来创建一个带返回值的、已完成的Task
                return Task.FromResult(
                    new ClaimsIdentity(
                        new System.Security.Principal.GenericIdentity(username, "Token"),
                        new Claim[] { })
                        );

            }
            return Task.FromResult<ClaimsIdentity>(null);
        }

        /// <summary>
        /// return the bad request (200)
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private async Task ReturnBadRequest(HttpContext context)
        {
            context.Response.StatusCode = 200;
            await context.Response.WriteAsync(JsonConvert.SerializeObject(new
            {
                Status = false,
                Message = "认证失败"
            }));
        }

        /// <summary>
        /// 创建jwt
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private string GetJwt(string username)
        {
            //计算机上的当前日期和时间，表示为协调世界时 (UTC)。通俗点就是格林威治时间的当前时间。以英国格林威治 天文台旧址为标准的零度经线算的时间
            var now = DateTime.UtcNow;

            var claims = new Claim[]
            {
                //jwt所面向的用户
                new Claim(JwtRegisteredClaimNames.Sub, username),
                //jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                //jwt的签发时间
                new Claim(JwtRegisteredClaimNames.Iat, now.ToUniversalTime().ToString(),
                          ClaimValueTypes.Integer64),
                //用户名
                new Claim(ClaimTypes.Name,username),
                //角色
                new Claim(ClaimTypes.Role,"a")
            };

            //JwtSecurityToken 类生成jwt
            var jwt = new JwtSecurityToken(
                issuer: _options.Issuer, //签发者
                audience: _options.Audience, //接收者
                claims: claims, //identity 详情请看上面
                notBefore: now, //如果在之前没有jwt 则添加 { nbf, 'value' } claim
                expires: now.Add(_options.Expiration), //过期时间
                signingCredentials: _options.SigningCredentials //加密数字签名证书
            );
            //JwtSecurityTokenHandler将jwt编码
            //WriteToken 将jwt编码并序列化
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                Status = true,
                access_token = encodedJwt,
                expires_in = (int)_options.Expiration.TotalSeconds,
                token_type = "Bearer"
            };
            //对象的json化  Formatting :  设置序列化时key为驼峰样式 
            return JsonConvert.SerializeObject(response, new JsonSerializerSettings { Formatting = Formatting.Indented });
        }
    }
}
