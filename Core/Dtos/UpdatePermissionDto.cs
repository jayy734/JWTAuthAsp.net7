using System.ComponentModel.DataAnnotations;

namespace JWTAuthAspNet7WebApi.Core.Dtos
{
    public class UpdatePermissionDto
    {

        [Required(ErrorMessage = "UserName is required")]
        public string UserName { get; set; }
    }
}
