using AspNetCoreIdentityApp.Core.Permission;
using AspNetCoreIdentityApp.Repository.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AspNetCoreIdentityApp.Repository.Seed
{
    public class PermissionSeed
    {
        public static async Task Seed(RoleManager<Role> roleManager)
        {
            var hasBasicRole = await roleManager.RoleExistsAsync("Basic");
            var hasAdvancedRole = await roleManager.RoleExistsAsync("AdvancedRole");
            var hasAdminRole = await roleManager.RoleExistsAsync("AdminRole");

            if (!hasBasicRole)
            {
                var role = new Role { Name = "Basic", NormalizedName = "BASIC" };
                await roleManager.CreateAsync(role);
                await AddReadPermission(role, roleManager);
            }
            if (!hasAdvancedRole)
            {
                var role = new Role { Name = "AdvancedRole", NormalizedName = "ADVANCED" };
                await roleManager.CreateAsync(role);
                await AddReadPermission(role, roleManager);
                await AddUpdateAndCreatePermission(role, roleManager);
            }
            if (!hasAdminRole)
            {
                var role = new Role { Name = "AdminRole", NormalizedName = "ADMINROLE" };
                await roleManager.CreateAsync(role);
                await AddReadPermission(role, roleManager);
                await AddUpdateAndCreatePermission(role, roleManager);
                await AddDeletePermission(role, roleManager);
            }

        }
        public static async Task AddReadPermission(Role role, RoleManager<Role> roleManager)
        {

            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Stock.View));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Order.View));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Catalog.View));
        }
        public static async Task AddUpdateAndCreatePermission(Role role, RoleManager<Role> roleManager)
        {

            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Stock.Create));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Order.Create));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Catalog.Create));


            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Stock.Edit));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Order.Edit));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Catalog.Edit));
        }
        public static async Task AddDeletePermission(Role role, RoleManager<Role> roleManager)
        {

            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Stock.Delete));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Order.Delete));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Catalog.Delete));


            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Stock.Delete));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Order.Delete));
            await roleManager.AddClaimAsync(role, new Claim("Permission", Permission.Catalog.Delete));
        }
    }
}
