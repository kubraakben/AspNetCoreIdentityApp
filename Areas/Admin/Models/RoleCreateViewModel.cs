using System.ComponentModel.DataAnnotations;

namespace AspNetCoreIdentityApp.Areas.Admin.Models
{
    public class RoleCreateViewModel
    {
        [Required(ErrorMessage = "Rol alanı zorunludur.")]
        [Display(Name = "Rol :")]

        public string Name { get; set; }
    }
}
