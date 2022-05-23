using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Application;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : Controller
    {
        public static User user = new User();

        private readonly IConfiguration _configuration;

        public AuthController (IConfiguration configuration)
        {
            _configuration = configuration;
        }


       
        // POST api/values
        [HttpPost("register")]
        public async Task< ActionResult<User>> Register(UserDto request)
        {
            createPasswordHash(request.password, out Byte[] passwordHash, out Byte[] passwordSalt);
            user.username = request.username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);

        }

        [HttpPost("login")]
        public async Task <ActionResult<string>> Login (UserDto request)
        {
            if(user.username != request.username)
            {
                return BadRequest("User not found");
            }

            if (!VerfiyPasswordHash(request.password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong Pasword. ");
            }
            string token = CreateToken(user);

            return Ok(token);
        }
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.username)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken (
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            
            return jwt;
        }
        private void createPasswordHash( string password, out Byte[] passwordHash, out Byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        // checks if user password is the same as password stored.(validity of user)
        //using the password param and the computed hash to get the stored data in "database"
        //checks if resulting password hash same as stored password hash
        private bool VerfiyPasswordHash(String password, byte[] passwordHash, byte [] passwordSalt)
        {
            using (var hmac = new HMACSHA512(user.PasswordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
       
    }
}

