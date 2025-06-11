using AuthService.DTOs;
using AuthService.Managers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using static AuthService.DTOs.ResponseDTO;

namespace AuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthManager _authManager;

        public AuthController(AuthManager authManager)
        {
            _authManager = authManager;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO request)
        {
            ResultDTO result = await _authManager.RegisterAsync(request);
            if (result.Success)
            {
                return Ok(new { message = result.Message });
            }
            return BadRequest(new { message = string.IsNullOrEmpty(result.Message) ? "User registration failed" : result.Message});
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO request)
        {
            AuthResponse result = await _authManager.LoginAsync(request, HttpContext.Response);
            if (result != null)
            {
                return Ok(result);
            }
            return Unauthorized(new { message = "Invalid credentials" });
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            AuthResponse result = await _authManager.RefreshTokenAsync(Request, Response);
            if (result != null)
            {
                return Ok(result);
            }
            return Unauthorized(new { message = "Invalid refresh token" });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout(LogoutDTO user)
        {
            ResultDTO result = await _authManager.LogoutAsync(user, Response);
            if (result.Success)
            {
                return Ok(new { message = result.Message });
            }
            return BadRequest(new { message = "User logout failed" });
        }
    }
}
