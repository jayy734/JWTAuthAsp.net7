﻿using JWTAuthAspNet7WebApi.Core.Dtos;

namespace JWTAuthAspNet7WebApi.Core.Interfaces
{
    public interface IAuthService
    {
        Task<AuthServiceResponseDto> SeedRolesAsync();
        Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto);
        Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto);
        Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto);
        Task<AuthServiceResponseDto> MakeHeadmanAsync(UpdatePermissionDto updatePermissionDto);
        Task<AuthServiceResponseDto> MakeVitimAsync(UpdatePermissionDto updatePermissionDto);

        //Task<AuthServiceResponseDto> UpdateAsync(RegisterDto updateDto);
    }
}

