using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using UserMangement.BAL.Services.AuthenticateService.DTOS;

namespace UserMangement.BAL.Services.AuthenticateService
{
    public interface IAuthenticateService
    {
        Task<object> Login(string email, string password);
        Task<IEnumerable<object>> ListUser();
        Task<object> Register(RegisterDto registerDto);
        IEnumerable<object> RoleDropDown();
        IEnumerable<object> ListUserDropDown();
        Task<object> AddUserRole(Guid UserId, List<string> Roles);
        Task<object> DeleteUser(Guid UserId);
        Task<bool> ChangePassword(ChangeUserPasswordDto payload);
        Task<bool> UnlockUser(Guid UserId);
        Task<bool> AddRole(string RoleName);
        Task<bool> AddRoleClaims(string RoleName, List<string> Claims);
    }
}
