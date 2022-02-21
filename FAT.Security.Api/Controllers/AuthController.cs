using FAT.Security.Api.Extensions;
using FAT.Security.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace FAT.Security.Api.Controllers
{
    [Route("api/Security")]
    public class AuthController : MainController
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppSettings _appSettings;
        private readonly ILogger<AuthController> _logger;

        public AuthController( SignInManager<IdentityUser> signInManager,
                               UserManager<IdentityUser> userManager,
                               IOptions<AppSettings> appSettings,
                               ILogger<AuthController> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _appSettings = appSettings.Value;
            _logger = logger;
        }

        [HttpPost("Register")]
        public async Task<ActionResult> Register(RegisterUserViewModel registerUserViewModel)
        {
            if (!ModelState.IsValid) return CustomResponse(ModelState);

            var user = new IdentityUser { UserName = registerUserViewModel.Email, Email = registerUserViewModel.Email, EmailConfirmed = true };

            var result = await _userManager.CreateAsync(user, registerUserViewModel.Password);

            if (result.Succeeded)
            {
                return CustomResponse(await GenerateJwt(user.Email));
            }
            foreach (var error in result.Errors)
            {
                AddErrorMessage(error.Description);
            }

            return CustomResponse(registerUserViewModel);
        }

        [HttpPost("Login")]
        public async Task<ActionResult> Login(LoginUserViewModel loginUserViewModel)
        {
            if (!ModelState.IsValid) return CustomResponse(ModelState);

            var result = await _signInManager.PasswordSignInAsync(loginUserViewModel.Email, loginUserViewModel.Password, false, true);

            if (result.Succeeded)
            {
                _logger.LogInformation("Successful Login!");
                return CustomResponse(await GenerateJwt(loginUserViewModel.Email));
            }
            if (result.IsLockedOut)
            {
                AddErrorMessage("User blocked for invalid login attempts");
                return CustomResponse(loginUserViewModel);
            }

            AddErrorMessage("User or password invalid");

            return CustomResponse(loginUserViewModel);
        }

        private async Task<ClaimsIdentity> GetUserClaims(ICollection<Claim> claims, IdentityUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            // More detais about the configuration: https://datatracker.ietf.org/doc/html/rfc7519#section-4
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64));
            foreach (var userRole in userRoles)
            {
                claims.Add(new Claim("role", userRole));
            }

            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);

            return identityClaims;
        }

        private async Task<LoginResponseViewModel> GenerateJwt(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var claims = await _userManager.GetClaimsAsync(user);

            var identityClaims = await GetUserClaims(claims, user);

            var encodedToken = WriteToken(identityClaims);

            var response = GetLoginResponse(user, claims, encodedToken);

            return response;
        }

        private LoginResponseViewModel GetLoginResponse(IdentityUser user, IList<Claim> claims, string encodedToken)
        {
            return new LoginResponseViewModel
            {
                AccessToken = encodedToken,
                ExpiresIn = TimeSpan.FromHours(_appSettings.ExpirationHours).TotalSeconds,
                UserToken = new UserTokenViewModel
                {
                    Id = user.Id,
                    Email = user.Email,
                    Claims = claims.Select(c => new ClaimViewModel { Type = c.Type, Value = c.Value })
                }
            };
        }

        private string WriteToken(ClaimsIdentity identityClaims)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _appSettings.Issuer,
                Audience = _appSettings.Audience,
                Expires = DateTime.UtcNow.AddHours(_appSettings.ExpirationHours),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Subject = identityClaims
            });

            return tokenHandler.WriteToken(token);
        }

        private static long ToUnixEpochDate(DateTime date)
           => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}
