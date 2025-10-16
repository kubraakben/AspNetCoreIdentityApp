using AspNetCoreIdentityApp.Repository.Models;
using Microsoft.AspNetCore.Identity;

namespace AspNetCoreIdentityApp.Validation
{
    public class UserValidator : IUserValidator<User>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<User> manager, User user)
        {
            var errors = new List<IdentityError>();
            var isNumeric = int.TryParse(user.UserName[0]!.ToString(), out _);

            if (isNumeric)
            {
                errors.Add(new IdentityError
                {
                    Code = "UserNameStartsWithNumber",
                    Description = "Kullanıcı adı sayısal bir karakterle başlayamaz."
                });
            }
            if (!errors.Any())
            {
                return Task.FromResult(IdentityResult.Success);
            }
            return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
        }
    }
}
