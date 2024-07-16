using JWTAuthAspNet7WebApi.Core.Dtos;
using JWTAuthAspNet7WebApi.Core.Entities;
using JWTAuthAspNet7WebApi.Core.Interfaces;
using JWTAuthAspNet7WebApi.Core.OtherObject;
using Microsoft.AspNetCore.Authorization;
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
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        //route for seeding my roles to DB
        [HttpPost]
        [Route("seed-roles")]

        public async Task<IActionResult> SeedRoles()
        {
            var seedRoles = await _authService.SeedRolesAsync();
            return Ok(seedRoles);
        }

        //Route -> Register
        [HttpPost]
        [Route("register")]

        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        { 
            var registerResult = await _authService.RegisterAsync(registerDto);

            if(registerResult.IsSucceed)
                return Ok(registerResult);

            return BadRequest(registerResult);
        }

        //Route -> Login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto logindto)
        {
            var loginResult = await _authService.LoginAsync(logindto);

            if (loginResult.IsSucceed)
                return Ok(loginResult);

            return BadRequest(loginResult);
        }

        //[Authorize]
        //[HttpPut]
        //[Route("update")]
        //[Authorize(Roles = StaticUserRoles.USER)]

        //public async Task<IActionResult> Update([FromBody] RegisterDto updatedto)
        //{
        //    var updateResult = await _authService.UpdateAsync(updatedto);
        //    if (updateResult.IsSucceed)
        //        return Ok(updateResult);
        //    return BadRequest(updateResult);
        //}
        

        //Route -> make user -> admin
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var makeAdminResult = await _authService.MakeAdminAsync(updatePermissionDto);

            if(makeAdminResult.IsSucceed)
                return Ok(makeAdminResult);

            return BadRequest(makeAdminResult);
        }

        //Route -> make user -> owner
        [HttpPost]
        [Route("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var makeOwnerResult = await _authService.MakeOwnerAsync(updatePermissionDto);

            if(makeOwnerResult.IsSucceed)
                return Ok(makeOwnerResult);

            return BadRequest(makeOwnerResult);
        }
    }
}

