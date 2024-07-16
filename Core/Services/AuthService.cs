using JWTAuthAspNet7WebApi.Core.Dtos;
using JWTAuthAspNet7WebApi.Core.Entities;
using JWTAuthAspNet7WebApi.Core.Interfaces;
using JWTAuthAspNet7WebApi.Core.OtherObject;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthAspNet7WebApi.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleMaganger;
        private readonly IConfiguration _configuration;


        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleMaganger = roleManager;
            _configuration = configuration;
        }
        public async Task<AuthServiceResponseDto> LoginAsync(LoginDto logindto)
        {
            var user = await _userManager.FindByEmailAsync(logindto.Email);
            if (user is null || user.isDeleted == true)
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials!"
                };

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, logindto.Password);

            if (!isPasswordCorrect)
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials!"
                };

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName", user.LastName),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = token,
            };
        }


        public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid UserName!"
                };

            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User is now an ADMIN",
            };
        }

        public async Task<AuthServiceResponseDto> MakeHeadmanAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid User Name"
                };

            await _userManager.AddToRoleAsync(user, StaticUserRoles.HEADMAN);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User is now an headman",
            };
        }

        public async Task<AuthServiceResponseDto> MakeVitimAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid User Name"
                };

            await _userManager.AddToRoleAsync(user, StaticUserRoles.VITIM);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User is now a Vitim.",
            };
        }

        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {

            var isExitUser = await _userManager.FindByNameAsync(registerDto.UserName);

            if (isExitUser != null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "UserName Already Exits!"
                };
            }

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                Email = registerDto.Email,
                UserName = registerDto.UserName,
                PasswordHash = registerDto.Password,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed Because: ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = errorString,
                };

            }
            //Add a default user role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User Created Successfully!"
            };
        }

        public async Task<AuthServiceResponseDto> SeedRolesAsync()
        {
            bool isHeadManRoleExists = await _roleMaganger.RoleExistsAsync(StaticUserRoles.HEADMAN);
            bool isUserRoleExits = await _roleMaganger.RoleExistsAsync(StaticUserRoles.USER);
            bool isAdminRoleExits = await _roleMaganger.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isVitmRoleExits = await _roleMaganger.RoleExistsAsync(StaticUserRoles.VITIM);


            if (isHeadManRoleExists && isUserRoleExits && isAdminRoleExits && isVitmRoleExits)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = true,
                    Message = "Roles Seeding is already done."
                };
            }
            await _roleMaganger.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleMaganger.CreateAsync(new IdentityRole(StaticUserRoles.HEADMAN));
            await _roleMaganger.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleMaganger.CreateAsync(new IdentityRole(StaticUserRoles.VITIM));

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "Roles Seeding Done Successfully."
            };
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

        //public async Task<AuthServiceResponseDto> UpdateAsync(RegisterDto registerDto)
        //{

        //    var isExitUser = await _userManager.FindByNameAsync(registerDto.UserName);

        //    if (isExitUser == null)
        //    {
        //        return new AuthServiceResponseDto()
        //        {
        //            IsSucceed = false,
        //            Message = "UserName Does not exist!"
        //        };
        //    }

        //    ApplicationUser newUser = new ApplicationUser()
        //    {
        //        FirstName = registerDto.FirstName,
        //        LastName = registerDto.LastName,
        //        Email = registerDto.Email,
        //        UserName = registerDto.UserName,               
        //        SecurityStamp = Guid.NewGuid().ToString(),
        //    };

        //    var updateResult = await _userManager.UpdateAsync(newUser);

        //    if (!updateResult.Succeeded)
        //    {
        //        var errorString = "User Creation Failed Because: ";
        //        foreach (var error in updateResult.Errors)
        //        {
        //            errorString += " # " + error.Description;
        //        }
        //        return new AuthServiceResponseDto()
        //        {
        //            IsSucceed = false,
        //            Message = errorString,
        //        };


        //    }
        //    await _userManager.UpdateAsync(newUser);

            //return new AuthServiceResponseDto()
            //{
            //    IsSucceed = true,
            //    Message = "User Updated Successfully!"
            //};

        //}
    }
}
