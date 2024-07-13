using JWTAuthAspNet7WebApi.Core.Dtos;
using JWTAuthAspNet7WebApi.Core.Entities;
using JWTAuthAspNet7WebApi.Core.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthAspNet7WebApi.Core.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        public UserService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }
        public async Task<AuthServiceResponseDto> UpdateUserAsync([FromBody] RegisterDto updateDto)
        {
            var user = await _userManager.FindByEmailAsync(updateDto.Email);
            if (user == null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "User not found!"
                };
            }

            user.FirstName = updateDto.FirstName;
            user.LastName = updateDto.LastName;
            user.UserName = updateDto.UserName;
            user.Email = updateDto.Email;
            user.PasswordHash = updateDto.Password;
            user.SecurityStamp = Guid.NewGuid().ToString();

            var updateResult = await _userManager.UpdateAsync(user);
            
            if(!updateResult.Succeeded)
            {
                var errorString = "User Update Failed Because: ";
                foreach (var error in updateResult.Errors)
                {
                    errorString += "#" + error.Description;
                }
            }
            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User Updated Successfully!"
            };
        }
    }
}
