using AspNetCoreIdentityApp.Localization;
using AspNetCoreIdentityApp.Repository.Models;
using AspNetCoreIdentityApp.Validation;
using Microsoft.AspNetCore.Identity;

namespace AspNetCoreIdentityApp.Extension
{
    public static class StartUpExtensions
    {
        public static void AddIdentityWithExt(this IServiceCollection services)
        {

            services.Configure<DataProtectionTokenProviderOptions>(opt => {

                opt.TokenLifespan = TimeSpan.FromHours(2); // Set the token lifespan to 2 hours
            });
            services.AddIdentity<User, Role>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 6;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;

                options.Lockout.DefaultLockoutTimeSpan= TimeSpan.FromMinutes(5);// 5 dk kitlenme süresi
                options.Lockout.MaxFailedAccessAttempts = 3;// 3 kez başarısız giriş denemesi sonrası kitlenme


            }).AddPasswordValidator<PasswordValidator>()
              .AddUserValidator<UserValidator>()
              .AddErrorDescriber<LocalizationIdentityErrorDescriber>()
              .AddDefaultTokenProviders()
              .AddEntityFrameworkStores<AppDbContext>();

        }
    }
}
