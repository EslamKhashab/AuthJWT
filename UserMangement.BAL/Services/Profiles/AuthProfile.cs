using AutoMapper;
using Microsoft.AspNetCore.Identity;
using UserMangement.BAL.Services.AuthenticateService.DTOS;

namespace UserMangement.BAL.Services.Profiles
{
    public class AuthProfile : Profile
    {
        public AuthProfile()
        {
            CreateMap<IdentityRole, RoleDropDownDto>()
                   .ReverseMap();

            CreateMap<IdentityUser, UserDropdownDto>()
                    .ReverseMap();
        }

    }
}
