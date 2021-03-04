using System;

namespace UserMangement.BAL.Services.AuthenticateService.DTOS
{
    public class UserDropdownDto
    {
        public Guid Id { get; set; }
        public string Email { get; set; }
        public string UserName { get; set; }
    }
}
