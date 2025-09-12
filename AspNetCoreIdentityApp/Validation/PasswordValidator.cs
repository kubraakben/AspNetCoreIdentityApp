using AspNetCoreIdentityApp.Repository.Models;
using Microsoft.AspNetCore.Identity;

namespace AspNetCoreIdentityApp.Validation
{
    public class PasswordValidator : IPasswordValidator<User>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<User> manager, User user, string? password)
        {
            var errors=new List<IdentityError>();   
            if (password!.ToLower().Contains(user.UserName!.ToLower()))
            {
                errors.Add(new IdentityError { Code= "PasswordContainsUserName", Description = "Şifre, kullanıcı adını içermemelidir." });
            }
            if (password.ToLower().StartsWith("1234"))
            {
                errors.Add(new IdentityError { Code = "PasswordStartsWith1234", Description = "Şifre 1234 ile başlamamalıdır." });
            }
            if (!errors.Any())
            {
                return Task.FromResult(IdentityResult.Success);
            }
            return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
        }
    }
}
