using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace Apidemo2.Controllers
{
    [Route("api/[controller]")]
    public class TokenController : Controller
    {
        private readonly TokenProviderOptions _options;

        public TokenController(IOptions<TokenProviderOptions> options)
        {
            _options = options.Value;
        }

        /// <summary>
        /// 用户登录
        /// </summary>
        /// <param name="user">用户登录信息</param>
        /// <param name="audience">要访问的网站</param>
        /// <returns></returns>
        [HttpPost("{audience}")]
        public IActionResult Post(string username, string password)
        {
            if (username == "czs" && password == "123456")
            {
                return Json(new { Token = CreateToken(username) });
            }
            else
            {
                return Json(new { Error = "用户名或密码错误" });
            }

        }

        private string CreateToken(string username)
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