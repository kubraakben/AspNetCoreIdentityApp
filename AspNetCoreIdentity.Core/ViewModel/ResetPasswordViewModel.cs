using System.ComponentModel.DataAnnotations;

namespace AspNetCoreIdentityApp.Core.ViewModel
{
    public class ResetPasswordViewModel
    {
        [DataType(DataType.Password)]
        [Required(ErrorMessage = "Şifre alanı zorunludur.")]
        [Display(Name = "Yeni Şifre:")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Şifreler eşleşmiyor.")]
        [Required(ErrorMessage = "Şifre Tekrar alanı zorunludur.")]
        [Display(Name = "Yeni Şifre Tekrar:")]
        public string PasswordConfirm { get; set; }

    }
}
