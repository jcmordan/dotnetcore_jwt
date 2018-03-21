using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebApi.Configurations;
using WebApi.Models;
using WebApi.Rules;

namespace WebApi.Controllers
{
    [AllowAnonymous]
    [Route ("api/accounts")]
    public class AccountsController : Controller
    {
        private readonly AccountRules _accountRules;

        public AccountsController (AccountRules accountRules)
        {
            _accountRules = accountRules;
        }

        [HttpPost]
        [Route ("access-request")]
        public async Task Register ([FromBody] AccessRequest accessRequest) 
            => await _accountRules.Register (accessRequest);

        [HttpPost]
        [Route ("login")]
        public async Task<IActionResult> LoginAsync ([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest ("InvalidCredentials");
            }

            UserProfile response = await _accountRules.LoginAsync (request);
            return Ok (response);
        }

        [HttpPost]
        [Route ("logout")]
        public async Task LogoutAsync ([FromBody] UserProfile profile)
           => await _accountRules.LogoutAsync (profile, HttpContext);
    }
}