using JWTAuthAspNet7WebApi.Core.Dtos;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthAspNet7WebApi.Core.Interfaces
{
    public interface IUserService
    {
        Task<AuthServiceResponseDto> UpdateUserAsync(RegisterDto updateDto);
        Task<AuthServiceResponseDto> DeleteUserAsync(string email);
    }
}
