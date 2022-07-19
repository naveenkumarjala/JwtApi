using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]

        public async Task<ActionResult<User>> Register(Userdto request)
        {
            CreatePasswordHash(request.Password ,out byte[] passwordHash , out byte[] passwordSalt);

            user.UserName = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }
        private void CreatePasswordHash(string Password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using( var hmac= new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash=hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));    
            }
        }

        [HttpPost("Login")]
        public async Task<ActionResult<string>> login(Userdto request)
        {
            if(user.UserName != request.Username)
            {
                return BadRequest("User Not found");
            }
            if(!verifyPasswordHash(request.Password,user.PasswordHash,user.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }
            string token = CerateToken(user);
             return Ok(token);
           // return "hi";
        }

        private bool verifyPasswordHash(string Password,  byte[] PasswordHash,  byte[] PasswordSalt)
        {
            using (var hmac = new HMACSHA512(PasswordSalt))
            {
                var computeHash=hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));
                return computeHash.SequenceEqual(PasswordHash);
            }
        }

        private string CerateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims:claims,
                expires:DateTime.Now.AddDays(1),
                signingCredentials: creds);
            var jwt=new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;


        }

    }
}
