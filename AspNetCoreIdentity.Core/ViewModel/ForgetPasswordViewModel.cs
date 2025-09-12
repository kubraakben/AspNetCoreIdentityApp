using System.ComponentModel.DataAnnotations;

namespace AspNetCoreIdentityApp.Core.ViewModel
{
    public class ForgetPasswordViewModel
    {
        [EmailAddress(ErrorMessage = "Lütfen geçerli bir email adresi giriniz.")]
        [Required(ErrorMessage = "Email alanı zorunludur.")]
        [Display(Name = "Email:")]
        public string Email { get; set; }

    }
}
