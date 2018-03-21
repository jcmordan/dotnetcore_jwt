using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebApi.Configurations;
using WebApi.Models;

namespace WebApi.Rules
{
    public class AccountRules
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly JwtTokenCache _tokenCache;
        private readonly JwtOptions _jwtOptions;
        private readonly ILogger<AccountRules> _logger;

        public AccountRules (UserManager<User> userManager, SignInManager<User> signInManager,
            IOptions<JwtOptions> jwtOptions, ILoggerFactory loggerFactory, JwtTokenCache tokenCache)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tokenCache = tokenCache;
            _jwtOptions = jwtOptions.Value;
            _logger = loggerFactory.CreateLogger<AccountRules> ();

            ThrowIfInvalidOptions (_jwtOptions);
        }

        static void ThrowIfInvalidOptions (JwtOptions options)
        {
            if (options == null) throw new ArgumentNullException (nameof (options));

            if (options.ValidFor <= TimeSpan.Zero)
            {
                throw new ArgumentException ("Must be a non-zero TimeSpan.", nameof (JwtOptions.ValidFor));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException (nameof (JwtOptions.SigningCredentials));
            }

            if (options.JtiGenerator == null)
            {
                throw new ArgumentNullException (nameof (JwtOptions.JtiGenerator));
            }
        }

        public async Task<UserProfile> LoginAsync (LoginRequest request)
        {
            User user = await TryLoginAsync (request);

            var claims = new List<Claim>
            {
                new Claim (JwtRegisteredClaimNames.Sub, request.UserName),
                new Claim (JwtRegisteredClaimNames.Jti, await _jwtOptions.JtiGenerator ()),
                new Claim (JwtRegisteredClaimNames.Iat, ToUnixEpochDate (_jwtOptions.IssuedAt).ToString (), ClaimValueTypes.Integer64)
            };

            // add database name claim
            claims.Add (new Claim (_jwtOptions.InstanceClaimName, user.InstanceName));

            // add user claims
            ICollection<Claim> userClaims = await _userManager.GetClaimsAsync (user);
            claims.AddRange (userClaims);

            // Create the JWT security token and encode it.
            var jwt = new JwtSecurityToken (
                issuer : _jwtOptions.Issuer,
                audience : _jwtOptions.Audience,
                claims : claims,
                notBefore : _jwtOptions.NotBefore,
                expires : _jwtOptions.Expiration,
                signingCredentials : _jwtOptions.SigningCredentials);

            var tokenHandler = new JwtSecurityTokenHandler ();
            string encodedJwt = tokenHandler.WriteToken (jwt);

            _tokenCache.Add (jwt.Id);

            // Serialize and return the response
            var response = new UserProfile
            {
                UserName = user.UserName,
                InstanceName = user.InstanceName,
                Access = userClaims.Select (c => c.Value).ToList (),
                Token = encodedJwt,
                TokenExpirationDate = DateTime.Now.AddSeconds ((int) _jwtOptions.ValidFor.TotalSeconds)
            };

            _logger.LogInformation ("User logged in.");
            return response;
        }
        static long ToUnixEpochDate (DateTime date) => (long) Math.Round ((date.ToUniversalTime () - new DateTimeOffset (1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);

        async Task<User> TryLoginAsync (LoginRequest request)
        {
            var user = await _userManager.FindByNameAsync (request.UserName);
            if (user == null)
            {
                _logger.LogInformation ("User logged in.");
                return await Task.FromResult<User> (null);
            }

            // check the credentials  
            var result = await _signInManager.CheckPasswordSignInAsync (user, request.Password, true);
            if (!result.Succeeded)
            {
                return await Task.FromResult<User> (null);
            }
            return user;
        }

        public async Task LogoutAsync (UserProfile profile, HttpContext httpContext)
        {
            string token = await TryGetToken (profile, httpContext);
            var tokenHandler = new JwtSecurityTokenHandler ();
            if (!tokenHandler.CanReadToken (token))
            {
                return;
            }
            var jwtToken = tokenHandler.ReadJwtToken (token);

            _tokenCache.Remove (jwtToken.Id);
            _logger.LogInformation ("User logged out.");
            return;
        }

        private async Task<string> TryGetToken (UserProfile profile, HttpContext httpContext) => profile?.Token ?? await httpContext.GetTokenAsync ("access_token");

        public async Task Register (AccessRequest accessRequest)
        {
            var user = accessRequest.Map<AccessRequest, User>();
            IdentityResult result = await _userManager.CreateAsync (user, accessRequest.Password);

            if (!result.Succeeded)
            {
                throw new ArgumentException (string.Join (',', result.Errors.Select(e => e.Code).ToHashSet()));
            }

            return;
        }
    }
}