using System.ComponentModel.DataAnnotations;

namespace AspNetCoreIdentityApp.Core.ViewModel
{
    public class SignUpViewModel
    {
        [Required(ErrorMessage = "Kullanıcı Adı alanı zorunludur.")]
        [Display(Name ="Kullanıcı Adı:")]
        public string UserName { get; set; }

        [EmailAddress(ErrorMessage = "Lütfen geçerli bir email adresi giriniz.")]
        [Required(ErrorMessage = "Email alanı zorunludur.")]
        [Display(Name = "Email:")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [Required(ErrorMessage = "Şifre alanı zorunludur.")]
        [Display(Name = "Şifre:")]
        [MinLength(6, ErrorMessage = "Şifreniz en az 6 karakterli olmalıdır.")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Şifreler eşleşmiyor.")]
        [Required(ErrorMessage = "Şifre Tekrar alanı zorunludur.")]
        [Display(Name = "Şifre Tekrar:")]
        public string PasswordConfirm { get; set; }


        [Required(ErrorMessage = "Telefon alanı zorunludur.")]
        [Display(Name = "Telefon:")]
        public string Phone { get; set; }
    }
}
