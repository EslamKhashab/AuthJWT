using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UserMangement.BAL.Services.AuthenticateService;
using UserMangement.BAL.Services.AuthenticateService.DTOS;

namespace UserMangement.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthenticateService _authenticateService;
        public AuthController(IAuthenticateService authenticateService)
        {
            _authenticateService = authenticateService;
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(string email, string password)
        {
            return Ok(await _authenticateService.Login(email, password));
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterDto payload)
        {
            return Ok(await _authenticateService.Register(payload));
        }
        [HttpGet("ListUser")]
        public async Task<IActionResult> ListUser()
        {
            var result = await _authenticateService.ListUser();
            return Ok(result);
        }
        [HttpGet("GetRolesDropDown")]
        //[Authorize(Roles = "Admin")]
        [ProducesResponseType(typeof(IEnumerable<RoleDropDownDto>), 200)]

        public IActionResult GetRolesDropDown()
        {
            return Ok(_authenticateService.RoleDropDown());
        }

        [HttpGet("GetUserDropDown")]
        //[Authorize(Roles = "Admin")]
        [ProducesResponseType(typeof(IEnumerable<UserDropdownDto>), 200)]

        public IActionResult GetUserDropDown()
        {
            return Ok(_authenticateService.ListUserDropDown());
        }

        [HttpPost("AddUserRole")]
        //[Authorize(Roles = "Admin")]
        [ProducesResponseType(typeof(bool), 200)]

        public async Task<IActionResult> AddUserRole(Guid UserId, List<string> Roles)
        {
            return Ok(await _authenticateService.AddUserRole(UserId, Roles));
        }

        [HttpPost("DeleteUser/{Id}")]
        //[Authorize(Roles = "Admin")]
        [ProducesResponseType(typeof(bool), 200)]
        public async Task<IActionResult> DeleteUser(Guid Id)
        {
            return Ok(await _authenticateService.DeleteUser(Id));
        }


        [HttpPost("ChangePassword")]
        //[Authorize(Roles = "Admin")]
        [ProducesResponseType(typeof(bool), 200)]
        public async Task<IActionResult> ChangePassword(ChangeUserPasswordDto payload)
        {
            var result = await _authenticateService.ChangePassword(payload);
            return Ok(result);
        }

        [HttpPost("AddRole")]
        //[Authorize(Roles = "Admin")]
        [ProducesResponseType(typeof(bool), 200)]
        public async Task<IActionResult> AddRole(string RoleName)
        {
            var result = await _authenticateService.AddRole(RoleName);
            return Ok(result);
        }

        [HttpPost("AddRoleClaims")]
        //[Authorize(Roles = "Admin")]
        [ProducesResponseType(typeof(bool), 200)]

        public async Task<IActionResult> AddRoleClaims(string RoleName, List<string> Claims)
        {
            return Ok(await _authenticateService.AddRoleClaims(RoleName, Claims));
        }
    }
}
