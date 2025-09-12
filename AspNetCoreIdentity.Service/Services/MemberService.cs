using AspNetCoreIdentityApp.Core.ViewModel;
using AspNetCoreIdentityApp.Repository.Models;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AspNetCoreIdentity.Service.Services
{
    public class MemberService : IMemberService
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public MemberService(UserManager<User> userManager, SignInManager<User> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }
        public async Task<UserViewModel> GetUserViewModelByUserName(string userName)
        {
            var currentUser = await _userManager.FindByNameAsync(userName);
            var userViewModel = new UserViewModel
            { Email = currentUser!.Email, UserName = currentUser!.UserName, PhoneNumber = currentUser!.PhoneNumber };
            return userViewModel;
        }
        public async Task Logout()
        {
            await _signInManager.SignOutAsync();
        }

        public async Task<bool> CheckPasswordAsync(string userName, string password)
        {
            var currentUser = await _userManager.FindByNameAsync(userName);

            return  await _userManager.CheckPasswordAsync(currentUser, password);

        }
        public async Task<(bool, IEnumerable<IdentityError>)> ChangePasswordAsync(string userName, string oldPassword, string newPassword)
        {
            var currentUser = await _userManager.FindByNameAsync(userName);

            var result = await _userManager.ChangePasswordAsync(currentUser, oldPassword, newPassword);
            if (!result.Succeeded)
            {
                return (false, result.Errors);
            }
            await _userManager.UpdateSecurityStampAsync(currentUser);
            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(currentUser, newPassword, true, false);

            return (result.Succeeded, null);

        }
    }
}
