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

        public async Task<AuthServiceResponseDto> DeleteUserAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return new AuthServiceResponseDto
                {
                    IsSucceed = false,
                    Message = "User not found."
                };
            }

            user.isDeleted = true;
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded) 
            {
                var errorString = "User Deletion Failed Because: ";
                foreach (var error in result.Errors)
                {
                    errorString += "#" + error.Description;
                }
                return new AuthServiceResponseDto
                {
                    IsSucceed = false,
                    Message = errorString
                };
            }
            return new AuthServiceResponseDto
            {
                IsSucceed = true,
                Message = "User marked as deleted successfully."
            };
        }
    }
}
