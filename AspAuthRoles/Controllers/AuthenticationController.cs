using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using AspAuthRoles.Dtos;
using AspAuthRoles.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace AspAuthRoles.Controllers
{
    [ApiController]
    [Route("api/v1/authenticate")]
    public class AuthenticationController: ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;

        [HttpPost]
        [Route("roles/add")]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request) {
            var appRole = new ApplicationRole { Name = request.Role };
            var createRole = await _roleManager.CreateAsync(appRole);

            return Ok(new { Message = "Role created" });
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await RegisterAsync(request);

            return result.Success ? Ok(result) : BadRequest(result.Message);
        }

        private async Task<RegisterResponse> RegisterAsync(RegisterRequest request)
        {
            try { 
                var userExists = await _userManager.FindByEmailAsync(request.Email);
                if(userExists != null) 
                    return new RegisterResponse { Message = "User alredy exists", Success = false };

                userExists = new ApplicationUser { 
                    FullName = request.FullName,
                    Email = request.Email,
                    ConcurrencyStamp = Guid.NewGuid().ToString(),
                    UserName = request.Email,
                };
                var createdUserResult = await _userManager.CreateAsync(userExists, request.Password);
                if(!createdUserResult.Succeeded)
                    return new RegisterResponse { Message = $"Create user failed {createdUserResult.Errors.First().Description}", Success = false };

                var addUserRoleResult = await _userManager.AddToRoleAsync(userExists, "USER");
                if(!addUserRoleResult.Succeeded)
                    return new RegisterResponse { Message = $"Create user succeeded but user role failed {addUserRoleResult.Errors.First().Description}", Success = false };

                return new RegisterResponse { 
                    Success = true,
                    Message = "User registered successfully",
                };
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
                return new RegisterResponse
                {
                    Success = false,
                    Message = e.Message
                };
            }
        }

        [HttpPost]
        [Route("login")]
        [ProducesResponseType((int) HttpStatusCode.OK, Type = typeof(LoginResponse))]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var result = await LoginAsync(request);

            return result.Success? Ok(result) : BadRequest(result.Message);
        }

        private async Task<LoginResponse> LoginAsync(LoginRequest request) {
            try
            {
                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                    return new LoginResponse { Message = "Invalid Email/Password", Success = false };
                var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };
                var roles = await _userManager.GetRolesAsync(user);
                var roleClaims = roles.Select(x => new Claim(ClaimTypes.Role, x));
                claims.AddRange(roleClaims);

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secretkey"));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var expires = DateTime.Now.AddMinutes(30);
                var token = new JwtSecurityToken(
                    issuer: "http://localhost:5001",
                    audience: "http://localhost:5001",
                    claims: claims,
                    expires, expires,
                    signingCredentials: creds
                );

                return new LoginResponse
                {
                    AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                    Message = "Login successful",
                    Success = true,
                    UserId = user.Id.ToString(),
                    Email = user.Email,
                };
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return new LoginResponse
                {
                    Success = false,
                    Message = e.Message
                };
            }
        }
    }
}
