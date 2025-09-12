using System.ComponentModel.DataAnnotations;

namespace AspNetCoreIdentityApp.Core.ViewModel
{
    public class PasswordChangeViewModel
    {
        [DataType(DataType.Password)]
        [Required(ErrorMessage = "Eski Şifre alanı zorunludur.")]
        [Display(Name = "Eski Şifre:")]
        public string PasswordOld { get; set; } = null;

        [DataType(DataType.Password)]
        [Required(ErrorMessage = "Yeni Şifre alanı zorunludur.")]
        [Display(Name = "Yeni Şifre:")]
        [MinLength(6, ErrorMessage = "Şifreniz en az 6 karakterli olmalıdır.")]
        public string PasswordNew { get; set; } = null;

        [DataType(DataType.Password)]
        [Compare("PasswordNew", ErrorMessage = "Şifreler eşleşmiyor.")]
        [Required(ErrorMessage = "Şifre Tekrar alanı zorunludur.")]
        [Display(Name = "Şifre Tekrar:")]
        public string PasswordConfirm { get; set; } = null;
    }
}
