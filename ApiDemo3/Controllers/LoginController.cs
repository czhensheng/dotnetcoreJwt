using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace ApiDemo3.Controllers
{

    [Route("api/[controller]")]
    public class LoginController : ControllerBase
    {

        [HttpPost]

        public IActionResult Login(string userName,string password)
        {
                
  
            if (userName == "czs" && password == "123456")
            {
                return Ok(CreateToken(userName));
            }
            else
            {
                return BadRequest("wrong username or password");
            }
        }
        private string CreateToken(string username)
        {
            var now = DateTime.UtcNow;
            var claims = new[]
            {
                //可以添加一些需要的信息
                new Claim(ClaimTypes.Name, username),
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
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("Y2F0Y2yhciUyMHdvbmclMFWfsaZlJTIwLm5ldA=="));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            /**
                Claims 部分包含了一些跟这个 token 有关的重要信息。 JWT 标准规定了一些字段，下面节选一些字段:

                iss: The issuer of the token，token 是给谁的
                sub: The subject of the token，token 主题
                exp: Expiration Time。 token 过期时间，Unix 时间戳格式
                iat: Issued At。 token 创建时间， Unix 时间戳格式
                jti: JWT ID。针对当前 token 的唯一标识
                除了规定的字段外，可以包含其他任何 JSON 兼容的字段。
             * */
            var token = new JwtSecurityToken(
                issuer: "ace.com",
                audience: "ace.com",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds
                );

            var encodeJwt = new JwtSecurityTokenHandler().WriteToken(token);
            return encodeJwt;
        }
    }


}