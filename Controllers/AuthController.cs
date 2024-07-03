using JWTAuthAspNet7WebApi.Core.Dtos;
using JWTAuthAspNet7WebApi.Core.OtherObject;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text;

namespace JWTAuthAspNet7WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleMaganger;
        private readonly IConfiguration _configuration;
        

        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleMaganger = roleManager;
            _configuration = configuration;
        }

        //route for seeding my roles to DB
        [HttpPost]
        [Route("seed-roles")]

        public async Task<IActionResult> SeedRoles()
        {
            bool isOwnerRoleExists = await _roleMaganger.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isUserRoleExits = await _roleMaganger.RoleExistsAsync(StaticUserRoles.USER);
            bool isAdminRoleExits = await _roleMaganger.RoleExistsAsync(StaticUserRoles.ADMIN);

            if (isOwnerRoleExists && isUserRoleExits &&  isAdminRoleExits)
            {
                return Ok("Roles Seeding is already Done");
            }
            await _roleMaganger.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleMaganger.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await _roleMaganger.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));

            return Ok("Role seeding Done Successfully");
        }

        //Route -> Register
        [HttpPost]
        [Route("register")]

        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var isExitUser = await _userManager.FindByNameAsync(registerDto.UserName);

            if (isExitUser != null)
            {
                return BadRequest("UserName already Exits!");
            }

            IdentityUser newUser = new IdentityUser()
            {
                Email = registerDto.Email,
                UserName = registerDto.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);
            
            if(!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed Because: ";
                foreach(var error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                return BadRequest(errorString);

            }
            //Add a default user role to all isers
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return Ok("User Created Successfully.");
        }

        //Route -> Login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto logindto)
        {
            var user = await _userManager.FindByNameAsync(logindto.UserName);
            if (user is null)
                return Unauthorized("Invalid Credentials");

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, logindto.Password);

            if (!isPasswordCorrect)
                return Unauthorized("Invalid Credentials");

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
            };

            foreach(var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);

            return Ok(token);
        }

        private string GenerateNewJsonWebToken(List<Claim> claims) 
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims: claims,
                    signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;
        }

        //Route -> make user -> admin
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return Unauthorized("Invalid User Name");

            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return Ok("User is now an ADMIN");
        }

        //Route -> make user -> owner
        [HttpPost]
        [Route("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return Unauthorized("Invalid User Name");

            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            return Ok("User is now an Owner");
        }
    }
}

