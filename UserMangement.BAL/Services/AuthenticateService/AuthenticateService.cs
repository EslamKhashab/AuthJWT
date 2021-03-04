using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using UserMangement.BAL.Services.AuthenticateService.DTOS;

namespace UserMangement.BAL.Services.AuthenticateService
{
    public class AuthenticateService : IAuthenticateService
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IMapper _mapper;
        private readonly UserManager<IdentityUser> _userManager;
        private IConfiguration _config;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthenticateService(IConfiguration iConfig, SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IMapper mapper)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _config = iConfig;
            _roleManager = roleManager;
            _mapper = mapper;
        }
        private async Task<string> GenerateJSONWebToken(IdentityUser User)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userRoles = await _userManager.GetRolesAsync(User);
            var claims = new List<Claim> {
                                new Claim("UserId", User.Id),
                                new Claim("UserName", User.UserName),
                                //new Claim(ClaimTypes.Role, "Admin")
                               };
            foreach (var item in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, item));
            }
            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
             _config["Jwt:Issuer"],
             claims,
             expires: DateTime.Now.AddDays(1),
             signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        public async Task<object> Login(string email,string password)
        {
            var User = await _userManager.FindByEmailAsync(email);



            if (User != null)
            {
                var result = await _signInManager.PasswordSignInAsync(User.UserName, password, true, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    var tokenString = await GenerateJSONWebToken(User);
                    var Final = new TokenDto();
                    Final.Token = tokenString;
                    Final.UserName = User.UserName;
                    return Final;
                }
            }
            return false;
        }
      
        public async Task<IEnumerable<object>> ListUser()
        {
            var Users = _userManager.Users;
            return /*mapper.Map<List<DropDownDto>>(*/ Users;
        }

        public async Task<object> Register(RegisterDto registerDto)
        {

            var user = new IdentityUser { UserName = registerDto.UserName, Email = registerDto.Email };
            var result = await _userManager.CreateAsync(user, registerDto.Password);
            if (result.Succeeded)
            {
                return true;
                //return new object { Result = true, IsError = false, Message = "User Created", StatusCode = 200 };
            }
            return false;
            //return new ApiResponse { Result = false, IsError = true, Message = result.Errors.ToString(), StatusCode = 400 };
        }
        public IEnumerable<object> RoleDropDown()
        {
            var roles = _roleManager.Roles;
            var result = _mapper.Map<List<RoleDropDownDto>>(roles);
            return result;
        }

        public IEnumerable<object> ListUserDropDown()
        {
            var Users = _userManager.Users;
            var result = _mapper.Map<List<UserDropdownDto>>(Users);
            return result;
        }

        public async Task<object> AddUserRole(Guid UserId, List<string> Roles)
        {
            var User = await _userManager.FindByIdAsync(UserId.ToString());
            if (User != null)
            {
                var UserRoles = await _userManager.GetRolesAsync(User);
                foreach (var item in Roles)
                {
                    if (!UserRoles.Any(x => x.Contains(item)))
                    {
                        await _userManager.AddToRoleAsync(User, item.ToLower());
                    }
                }
                return true;
            }
            return false;
        }

        public async Task<object> DeleteUser(Guid UserId)
        {
            var User = await _userManager.FindByIdAsync(UserId.ToString());
            await _userManager.DeleteAsync(User);
            return true;
        }

        public async Task<bool> ChangePassword(ChangeUserPasswordDto payload)
        {
            var User = await _userManager.FindByIdAsync(payload.UserId.ToString());
            var result = await _userManager.ChangePasswordAsync(User, payload.CurrentPassword, payload.NewPassword);
            if (result.Succeeded)
            {
                return true;
            }
            return false;
            //throw new ApiException(result.Errors.FirstOrDefault().Description, 400);
        }

        public async Task<bool> UnlockUser(Guid UserId)
        {
            var User = await _userManager.FindByIdAsync(UserId.ToString());
            if (User != null)
            {
                User.LockoutEnd = null;
                User.LockoutEnabled = !User.LockoutEnabled;
                await _signInManager.UserManager.UpdateAsync(User);
                return true;
            }
            return false;

        }
        public async Task<bool> AddRole(string RoleName)
        {
            var Role = new IdentityRole();
            Role.Name = RoleName;

            await _roleManager.CreateAsync(Role);
            return true;

        }

        public async Task<bool> AddRoleClaims(string RoleName, List<string> Claims)
        {
            var role = await _roleManager.FindByNameAsync(RoleName);
            foreach (var item in Claims)
            {
                await _roleManager.AddClaimAsync(role, new Claim("Permission", item));
            }
            return true;
        }
    }
}
