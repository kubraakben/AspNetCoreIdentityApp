using System.ComponentModel.DataAnnotations;

namespace AspNetCoreIdentityApp.Areas.Admin.Models
{
    public class RoleUpdateViewModel
    {
        public string Id { get; set; }
        [Required(ErrorMessage = "Rol alanı zorunludur.")]
        [Display(Name = "Rol :")]

        public string Name { get; set; }
    }
}
