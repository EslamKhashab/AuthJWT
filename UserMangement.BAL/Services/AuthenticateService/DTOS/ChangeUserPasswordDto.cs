using System;

namespace UserMangement.BAL.Services.AuthenticateService.DTOS
{
    public class ChangeUserPasswordDto
    {
        public Guid UserId { get; set; }
        public string NewPassword { get; set; }
        public string CurrentPassword { get; set; }
    }
}
