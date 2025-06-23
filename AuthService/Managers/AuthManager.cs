using AuthService.Database;
using AuthService.DTOs;
using AuthService.Helpers;
using AuthService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using static AuthService.DTOs.ResponseDTO;

namespace AuthService.Managers
{
    public class AuthManager
    {
        private readonly AuthDbContext _context;
        private readonly JwtTokenHelper _jwtTokenGenerator;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthManager> _logger;
        private readonly PasswordHasher<User> _hasher;


        public AuthManager(AuthDbContext authDbContext, JwtTokenHelper jwtTokenGenerator, ILogger<AuthManager> logger, IConfiguration configuration)
        {
            _context = authDbContext;
            _jwtTokenGenerator = jwtTokenGenerator;
            _logger = logger;
            _hasher = new PasswordHasher<User>();
            _configuration = configuration;
        }
        public async Task<ResultDTO> RegisterAsync(RegisterDTO user)
        {
            try
            {
                var registeredUser = await _context.Users.FirstOrDefaultAsync(x => x.Email == user.Email);
                if (registeredUser != null)
                {
                    _logger.LogError("User already registered with this email");
                    return new ResultDTO
                    {
                        Success = false,
                        Message = "User already registered with this email"
                    }; ;
                }
                var newUser = new User
                {
                    UserId = Guid.NewGuid(),
                    Username = user.Username,
                    Email = user.Email,
                    PhoneNumber = user.PhoneNumber,
                };
                newUser.Password = _hasher.HashPassword(newUser, user.Password);
                newUser.CreatedAt = DateTime.UtcNow;
                _context.Users.Add(newUser);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception occur in register ", ex);
                return new ResultDTO
                {
                    Success = false,
                    Message = "Something went wrong!"
                }; ;
            }
            return new ResultDTO
            {
                Success = true,
                Message = "User registered successfully"
            };
        }

        public async Task<AuthResponse> LoginAsync(LoginDTO request, HttpResponse response)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == request.Email);
                if (user == null){
                    _logger.LogError("User not found with this email");
                    return null;
                }
                var result = _hasher.VerifyHashedPassword(user, user.Password, request.Password);
                if (result == PasswordVerificationResult.Failed)
                {
                    _logger.LogError("Password is incorrect");
                    return null;
                }
                string token = await HandleTokenCreation(user, response);
                return new AuthResponse
                {
                    Email = user.Email,
                    PhoneNumber = user.PhoneNumber,
                    Username = user.Username,
                    Token = token
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occurred in LoginAsync");
                return null;
            }
        }

        public async Task<ResultDTO> LogoutAsync(LogoutDTO request, HttpResponse response)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == request.Email);
                if (user == null)
                {
                    _logger.LogError("User not found with this email");
                    return new ResultDTO
                    {
                        Success = false,
                        Message = "User not found with this email"
                    }; ;
                }
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;
                _context.Users.Update(user);
                await _context.SaveChangesAsync();

                response.Cookies.Delete("accessToken");
                response.Cookies.Delete("refreshToken");
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception occur in logout ", ex);
                return new ResultDTO
                {
                    Success = false,
                    Message = "Something went wrong!"
                };
            }
            return new ResultDTO { 
                Success = true,
                Message = "User logged out successfully"
            };
        }

        public async Task<AuthResponse> RefreshTokenAsync(HttpRequest request, HttpResponse response)
        {
            try
            {
                var refreshTokenCookie = request.Cookies["refreshToken"];
                if(string.IsNullOrEmpty(refreshTokenCookie))
                {
                    return null;
                }
                var refreshKey = _configuration["EncryptionKey"];
                string refreshToken = _jwtTokenGenerator.Decrypt(refreshTokenCookie, refreshKey);

                if (string.IsNullOrEmpty(refreshToken))
                {
                    return null;
                }

                var user = await _context.Users.FirstOrDefaultAsync(x => x.RefreshToken == refreshToken);
                if (user == null)
                {
                    _logger.LogError("User not found with this refresh token");
                    return null;
                }
                string token = await HandleTokenCreation(user, response);
                return new AuthResponse
                {
                    Email = user.Email,
                    PhoneNumber = user.PhoneNumber,
                    Username = user.Username,
                    Token = token
                };
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception occur in refresh token ", ex);
                return null;
            }
        }

        private async Task<string> HandleTokenCreation(User user, HttpResponse response)
        {
            string token = _jwtTokenGenerator.GenerateUserToken(user);
            response.Cookies.Append("accessToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            });

            string refreshToken = string.Empty;
            string encryptedRefreshToken = _jwtTokenGenerator.CreateNewRefreshToken(out refreshToken);
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            _context.Users.Update(user);
            await _context.SaveChangesAsync();


            response.Cookies.Append("refreshToken", encryptedRefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = user.RefreshTokenExpiryTime
            });
            return token;
        }
    }
}
