using AspNetCoreIdentity.Service.Services;
using AspNetCoreIdentityApp.Core.ViewModel;
using AspNetCoreIdentityApp.Extension;
using AspNetCoreIdentityApp.Repository.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AspNetCoreIdentityApp.Controllers
{
    [Authorize]
    public class MemberController : Controller
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly IMemberService _memberService;
        private string userName => User.Identity!.Name!;

        public MemberController(SignInManager<User> signInManager, UserManager<User> userManager
            , IMemberService memberService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _memberService = memberService;
        }
        public async Task<IActionResult> Logout()
        {
            await _memberService.Logout();
            return RedirectToAction("Index", "Home");
        }
        public async Task<IActionResult> Index()
        {
            return View(await _memberService.GetUserViewModelByUserName(userName));
        }
        public IActionResult PasswordChange()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> PasswordChange(PasswordChangeViewModel request)
        {
            if (!ModelState.IsValid)
            {
                return View(request);
            }
            if (!(await _memberService.CheckPasswordAsync(userName, request.PasswordOld)))
            {
                ModelState.AddModelError(string.Empty, "Eski şifreniz yanlış");
            }
            var (result, errors) = await _memberService.ChangePasswordAsync(userName, request.PasswordOld, request.PasswordNew);

            if (!result)
            {
                ModelState.AddModelErrorList(errors.Select(x => x.Description).ToList());
            }

            TempData["SuccessMessage"] = "Şifre başarıyla güncellenmiştir.";

            return View();
        }
        public IActionResult AccessDenied()
        {
            string message = string.Empty;
            message = "Bu sayfayı görmeye yetkiniz yok.";
            ViewBag.message = message;
            return View();
        }
        [HttpGet]
        public IActionResult Claims()
        {
            var userClaims = User.Claims.Select(x => new ClaimViewModel
            {
                Type = x.Type,
                Value = x.Value,
                Issuer = x.Issuer
            }).ToList();
            return View(userClaims);

        }
        [Authorize(Policy = "IstanbulPolicy")]
        [HttpGet]
        public IActionResult IstanbulPage()
        {

            return View();

        }
        [Authorize(Policy = "ExchangePolicy")]
        [HttpGet]
        public IActionResult ExchangePage()
        {

            return View();

        }
        [Authorize(Policy = "ViolencePolicy")]
        [HttpGet]
        public IActionResult ViolencePage()
        {

            return View();

        }
    }
}
