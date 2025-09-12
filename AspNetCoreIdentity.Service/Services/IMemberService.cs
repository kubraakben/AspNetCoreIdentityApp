using AspNetCoreIdentityApp.Core.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace AspNetCoreIdentity.Service.Services
{
    public interface IMemberService
    {
        Task<UserViewModel> GetUserViewModelByUserName(string userName);
        Task Logout();
        Task<bool> CheckPasswordAsync(string userName, string password);
        Task<(bool, IEnumerable<IdentityError>)> ChangePasswordAsync(string userName, string oldPassword, string newPassword);
    }
}
