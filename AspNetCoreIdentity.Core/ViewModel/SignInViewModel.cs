using System.ComponentModel.DataAnnotations;

namespace AspNetCoreIdentityApp.Core.ViewModel
{
    public class SignInViewModel
    {
        public SignInViewModel() { }
        public SignInViewModel(string email, string password)
        {
            Email = email;
            Password = password;
        }
        [EmailAddress(ErrorMessage = "Lütfen geçerli bir email adresi giriniz.")]
        [Required(ErrorMessage = "Email alanı zorunludur.")]
        [Display(Name = "Email:")]
        public string Email { get; set; }
        
        [Required(ErrorMessage = "Şifre alanı zorunludur.")]
        [Display(Name = "Şifre:")]
        public string Password { get; set; }
        [Display(Name = "Beni Hatırla")]
        public bool RememberMe { get; set; }
    }
}
