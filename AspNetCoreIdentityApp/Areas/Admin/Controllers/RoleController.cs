using AspNetCoreIdentityApp.Areas.Admin.Models;
using AspNetCoreIdentityApp.Extension;
using AspNetCoreIdentityApp.Repository.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AspNetCoreIdentityApp.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class RoleController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<Role> _roleManager;
        public RoleController(UserManager<User> userManager, RoleManager<Role> roleManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }
        public async Task<IActionResult> Index()
        {
            var roles = await _roleManager.Roles.Select(x => new RoleViewModel
            {
                Id = x.Id,
                Name = x.Name
            }).ToListAsync();

            return View(roles);
        }
        [Authorize(Roles = "admin")]
        public IActionResult RoleCreate()
        {
            return View();
        }
        [HttpPost]
        [Authorize(Roles = "admin")]
        public async Task<IActionResult> RoleCreate(RoleCreateViewModel request)
        {
            var result = await _roleManager.CreateAsync(new Role
            {
                Name = request.Name
            });
            if (!result.Succeeded)
            {
                ModelState.AddModelErrorList(result.Errors.Select(x => x.Description).ToList());
            }
            return RedirectToAction(nameof(RoleController.Index));
        }
        [Authorize(Roles = "admin")]
        public async Task<IActionResult> RoleUpdate(string id)
        {
            var role = await _roleManager.Roles.FirstOrDefaultAsync(x => x.Id == id);
            if (role == null)
            {
                return NotFound();
            }
            var model = new RoleUpdateViewModel
            {
                Id = role.Id,
                Name = role.Name
            };
            return View(model);
        }
        [HttpPost]
        [Authorize(Roles = "admin")]
        public async Task<IActionResult> RoleUpdate(RoleUpdateViewModel request)
        {
            var role = _roleManager.Roles.FirstOrDefault(x => x.Id == request.Id);
            if (role == null)
            {
                return NotFound();
            }

            role.Name = request.Name;

            var result = await _roleManager.UpdateAsync(role);


            if (!result.Succeeded)
            {
                ModelState.AddModelErrorList(result.Errors.Select(x => x.Description).ToList());
                return View(request);
            }
            ViewData["SuccessMessage"] = "Rol başarıyla güncellendi.";
            return RedirectToAction(nameof(RoleController.Index));
        }
        [Authorize(Roles = "admin")]
        public async Task<IActionResult> RoleDelete(string id)
        {
            var role = await _roleManager.Roles.FirstOrDefaultAsync(x => x.Id == id);
            if (role == null)
            {
                return NotFound();
            }
            var result = await _roleManager.DeleteAsync(role);
            if (!result.Succeeded)
            {
                ModelState.AddModelErrorList(result.Errors.Select(x => x.Description).ToList());
                return RedirectToAction(nameof(RoleController.Index));
            }
            ViewData["SuccessMessage"] = "Rol başarıyla silindi.";
            return RedirectToAction(nameof(RoleController.Index));
        }
        public async Task<IActionResult> AssignRoleToUser(string id)
        {
            var currentUser = _userManager.Users.FirstOrDefault(x => x.Id == id);
            ViewBag.UserId = id;
            if (currentUser == null)
            {
                return NotFound();
            }
            var roles = await _roleManager.Roles.ToListAsync();
            var roleViewModelList = new List<AssignRoleToUserViewModel>();

            foreach (var role in roles)
            {
                var assignRoleToUserViewModel = new AssignRoleToUserViewModel
                {
                    Id = role.Id,
                    Name = role.Name,
                    Exists = await _userManager.IsInRoleAsync(currentUser, role.Name)
                };
                roleViewModelList.Add(assignRoleToUserViewModel);
            }

            return View(roleViewModelList);
        }
        [HttpPost]
        public async Task<IActionResult> AssignRoleToUser(string userId, List<AssignRoleToUserViewModel> requestList)
        {
            var userToAssignRole = await _userManager.FindByIdAsync(userId);
            foreach (var role in requestList)
            {
                if (role.Exists)
                {
                    await _userManager.AddToRoleAsync(userToAssignRole, role.Name);
                }
                else
                {
                    await _userManager.RemoveFromRoleAsync(userToAssignRole, role.Name);
                }
            }
            return RedirectToAction(nameof(HomeController.UserList), "Home", new { area = "Admin" });
        }
    }
}
