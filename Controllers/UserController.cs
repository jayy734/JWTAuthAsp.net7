using JWTAuthAspNet7WebApi.Core.Dtos;
using JWTAuthAspNet7WebApi.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JWTAuthAspNet7WebApi.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPut]
        [Route("update")]
        public async Task<IActionResult> Update([FromBody] RegisterDto updateDto)
        {
            var email = User.FindFirstValue(ClaimTypes.Email);
            if (email == null)
            {
                return Unauthorized(new { Message = "Email claim not found in the token" });
            }
            var updateResult = await _userService.UpdateUserAsync(updateDto);

            if (updateResult.IsSucceed)
            {
                return Ok(updateResult);
            }
            return BadRequest(updateResult);
        }

        [HttpDelete]
        [Route("delete")]
        public async Task<IActionResult> DeleteUser([FromBody] string email)
        {
            var result = await _userService.DeleteUserAsync(email);

            if (result.IsSucceed)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }
    }

}
