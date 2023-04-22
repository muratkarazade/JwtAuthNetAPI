using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Enoca.Task.Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        // JWT belirteçlerinin imzalanması için kullanılan gizli anahtar.
        string signinKey = "BuBirGüvenlikÖnlemi";

        // Kullanıcı adı, şifre alan ve JWT token'i döndüren metot.
        [HttpGet]
        public string Login(string userName, string password)
        {
            // Payload
            var claims = new[]
            {   // token içinde taşınacak  veriler.(claims)
                new Claim(ClaimTypes.Name, userName),
                new Claim(JwtRegisteredClaimNames.Email,userName)
            };

            //Signature
            // signinKey kullanarak simetrik bir güvenlik anahtarı oluşturulması ve imzalama kimlik bilgilerini belirleme
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signinKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            //Header
            // Gerekli bilgilerle (yayıncı, dinleyici, talepler, sona erme süresi ve imzalama kimlik bilgileri) bir JWT güvenlik belirteci oluşturulması.            
            var jwtSecurityToken = new JwtSecurityToken(
                    issuer: "https://www.muratkara.com",
                    audience: "deneme123",
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(10),
                    notBefore: DateTime.Now,
                    signingCredentials: credentials
                );

            //Token oluşturması
            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            return token;
        }

        [HttpGet("ValidateToken")]
        public  bool ValidateToken(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signinKey));
            try
            {
                // JwtSecurityTokenHandler oluşturur ve verilen parametrelerle token'i doğrular.
                JwtSecurityTokenHandler handler = new();
                handler.ValidateToken(token, new TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = securityKey,
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                }, out SecurityToken validatedToken);

                // Token geçerliliği  JwtSecurityToken ile kontrolü .
                var jwtToken = (JwtSecurityToken)validatedToken;
                var claims = jwtToken.Claims.ToList();
                return true;
            }
            catch (Exception)
            {
                return false;                
            }
        }

    }
}
