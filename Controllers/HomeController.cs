using AspNetCoreIdentity.Core.ViewModel;
using AspNetCoreIdentityApp.Core.ViewModel;
using AspNetCoreIdentityApp.Extension;
using AspNetCoreIdentityApp.Repository.Models;
using AspNetCoreIdentityApp.Service.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.IdentityModel.Tokens;
using NuGet.Common;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
namespace AspNetCoreIdentityApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IEmailService _emailService;
        public HomeController(ILogger<HomeController> logger, UserManager<User> userManager,
            SignInManager<User> signInManager, IEmailService emailService)
        {
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }
        public IActionResult SignUp()
        {

            return View();
        }
        public IActionResult SignIn()
        {

            return View();
        }
        [HttpPost]
        public async Task<IActionResult> SignUp(SignUpViewModel request)
        {
            if (!ModelState.IsValid)
            {
                return View(request);
            }
            var identityResult = await _userManager.CreateAsync(new User
            {
                UserName = request.UserName,
                Email = request.Email,
                PhoneNumber = request.Phone
            }, request.Password);

            if (!identityResult.Succeeded)
            {
                ModelState.AddModelErrorList(identityResult.Errors.Select(x => x.Description).ToList());
                return View();
            }

            var exchangeExpireClaim = new Claim("ExchangeExpireDate", DateTime.Now.AddDays(10).ToString());
            var user = await _userManager.FindByNameAsync(request.UserName);
            var claimResult = await _userManager.AddClaimAsync(user!, exchangeExpireClaim);
            if (!claimResult.Succeeded)
            {
                ModelState.AddModelErrorList(claimResult.Errors.Select(x => x.Description).ToList());
                return View();
            }
            return RedirectToAction(nameof(HomeController.SignUp));


        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
        [HttpPost]
        public async Task<IActionResult> SignIn(SignInViewModel model, string? returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            returnUrl = returnUrl ?? Url.Action("Index", "Home");

            var hasUser = await _userManager.FindByEmailAsync(model.Email);

            if (hasUser == null)
            {
                ModelState.AddModelError(string.Empty, "Email ya da þifre yanlýþ");
                return View();
            }


            var signInResult = await _signInManager.PasswordSignInAsync(hasUser, model.Password, model.RememberMe, true);
            if (!signInResult.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Email ya da þifre yanlýþ");
                return View();
            }
            if (signInResult.IsLockedOut)
            {
                ModelState.AddModelErrorList(new List<string>() { "5 dk boyunca giriþ yapamazsýnýz" });
                return View();
            }

            if (hasUser.BirthDate.HasValue)
            {
                await _signInManager.SignInWithClaimsAsync(hasUser, model.RememberMe, new List<Claim> { new Claim("BirthDate", hasUser.BirthDate.Value.ToString()) });
            }

            var token = GenerateJwtToken(hasUser.UserName);
            if (returnUrl.Contains("appdiffdomain", StringComparison.OrdinalIgnoreCase))
            {
                return Redirect($"http://appDiffDomain.myappsdiff.test:5002/callback?token={token}");

            }
            else

                return Redirect(returnUrl);

            ModelState.AddModelErrorList(new List<string>() { $"Email ya da þifre yanlýþ", $"Baþarýsýz giriþ sayýsý = {await _userManager.GetAccessFailedCountAsync(hasUser)}" });

            return View();

        }
        private string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("this_is_a_super_secret_key_with_32_chars!!"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
        new Claim(JwtRegisteredClaimNames.Sub, username),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

            var token = new JwtSecurityToken(
                issuer: "AppA",
                audience: "AppC",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        public IActionResult ForgetPassword()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordViewModel request)
        {
            var hasUser = await _userManager.FindByEmailAsync(request.Email);
            if (hasUser == null)
            {
                ModelState.AddModelError(string.Empty, "Email adresi bulunamadý");
                return View(request);
            }

            string passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(hasUser);
            string passwordResetLink = Url.Action("ResetPassword", "Home",
                new { userID = hasUser.Id, email = hasUser.Email, token = passwordResetToken }, Request.Scheme);


            await _emailService.SendResetPasswordEmail(passwordResetLink, hasUser.Email);
            //https://localhost:7291/

            TempData["SuccessMessage"] = "Þifre sýfýrlama linki email adresinize gönderilmiþtir";

            return RedirectToAction(nameof(ForgetPassword));

        }
        public IActionResult ResetPassword(string userID, string email, string token)
        {
            TempData["UserID"] = userID;
            TempData["Email"] = email;
            TempData["Token"] = token;

            if (string.IsNullOrEmpty(userID) || string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
            {
                ModelState.AddModelError(string.Empty, "Geçersiz istek");
                return View();
            }
            /*var model = new ResetPasswordViewModel
            {
                UserID = userID,
                Email = email,
                Token = token
            };*/
            return View();
        }
        [HttpPost]
        public IActionResult ResetPassword(ResetPasswordViewModel request)
        {
            var userId = TempData["UserID"];
            var email = TempData["Email"];
            var token = TempData["Token"];

            if (userId == null || token == null)
            {
                throw new Exception("Bir hata meydana geldi");
            }

            var hasUser = _userManager.FindByIdAsync(userId!.ToString()).Result;
            if (hasUser == null)
            {
                ModelState.AddModelError(string.Empty, "Kullanýcý bulunamadý");
                return View(request);
            }

            var result = _userManager.ResetPasswordAsync(hasUser, token.ToString(), request.Password).Result;
            if (!result.Succeeded)
            {
                ModelState.AddModelErrorList(result.Errors.Select(x => x.Description).ToList());

            }
            else
            {
                TempData["SuccessMessage"] = "Þifreniz baþarýyla güncellenmiþtir.";
            }
            return View();
        }

        /*
        public async Task<IActionResult> GoogleResponse(string returnUrl = "/")
        {
            ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                ModelState.AddModelError(string.Empty, "Google ile giriþ baþarýsýz oldu.");
                return RedirectToAction(nameof(SignIn));
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Google ile giriþ baþarýsýz oldu. Lütfen tekrar deneyiniz.");
                return RedirectToAction(nameof(SignIn));

                Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                if (result.Succeeded)
                {
                    return Redirect(returnUrl);
                }
                User user = new User();
                user.Email = info.Principal.FindFirstValue(ClaimTypes.Email);
                string externalUserId = info.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
                if (info.Principal.HasClaim(x => x.Type == ClaimTypes.Name))
                {
                    var userName = info.Principal.FindFirstValue(ClaimTypes.Name);
                    user.UserName = userName.Replace(" ", "_").ToLower() + externalUserId.Substring(0, 5).ToString();
                }
                else
                {
                    user.UserName = info.Principal.FindFirstValue(ClaimTypes.Email);
                }
                IdentityResult createResult = await _userManager.CreateAsync(user);

                if (createResult.Succeeded)
                {
                    var loginResult = await _userManager.AddLoginAsync(user, info);
                    if (loginResult.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, true);
                        return Redirect(returnUrl);

                    }
                   
                }
               
            }
            return RedirectToAction(nameof(Error));

        }*/
        public IActionResult GoogleLogin1(string returnUrl)
        {
            string redirectUrl = Url.Action("GoogleResponse", "Home", new { returnUrl }, Request.Scheme);
            var properties = _signInManager
           .ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return new ChallengeResult("Google", properties);
            //  var properties = new AuthenticationProperties { RedirectUri = redirectUrl };

            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }
        public async Task<IActionResult> GoogleResponse1()
        {
            // var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var result = await HttpContext.AuthenticateAsync("Google");

            if (!result.Succeeded)
            {
                var error = await HttpContext.AuthenticateAsync();
                return Content("Login failed.\n\n" + error.Failure?.Message);
            }
            var claims = result.Principal.Identities
                .FirstOrDefault()?.Claims.Select(claim => new
                {
                    claim.Type,
                    claim.Value
                });

            // Örnek: Google'dan gelen kullanýcý adý ve e-posta
            var email = result.Principal.FindFirst(ClaimTypes.Email)?.Value;
            var name = result.Principal.FindFirst(ClaimTypes.Name)?.Value;

            // Kullanýcý sistemde yoksa, kaydet veya yönlendir
            // Oturum aç
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                result.Principal,
                result.Properties
            );

            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult GoogleLogin(string returnUrl = "/")
        {
            var redirectUrl = Url.Action(nameof(ExternalLoginCallbackIssuer), "Home", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return Challenge(properties, "Google");
        }
        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = "/")
        {
            // 1. Google'dan gelen bilgileri al
            var loginInfo = await _signInManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
                return RedirectToAction(nameof(SignIn));

            // 2. Kullanýcý daha önce giriþ yapmýþ mý?
            var result = await _signInManager.ExternalLoginSignInAsync(loginInfo.LoginProvider, loginInfo.ProviderKey, isPersistent: true);

            if (result.Succeeded)
            {
                return LocalRedirect(returnUrl);
            }

            // 3. Kullanýcý sistemde yoksa, bilgileri al ve kaydet
            var email = loginInfo.Principal.FindFirstValue(ClaimTypes.Email);
            var name = loginInfo.Principal.FindFirstValue(ClaimTypes.Name);
            var googleId = loginInfo.Principal.FindFirstValue(ClaimTypes.NameIdentifier); // = ProviderKey


            if (email == null)
                return Content("Google hesabýndan email bilgisi alýnamadý.");

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new User
                {
                    UserName = email,
                    Email = email,
                    //TurkuazUserId = Convert.ToInt32(googleId),
                };

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                    return Content("Kullanýcý oluþturulamadý: " + string.Join(", ", createResult.Errors.Select(e => e.Description)));
            }
            /* else if (!user.TurkuazUserId.HasValue)
             {
                 // Kullanýcý zaten varsa ama TurkuazUserId dolu deðilse güncelle
                 user.TurkuazUserId = Convert.ToInt32(googleId);
                 await _userManager.UpdateAsync(user);
             }*/

            // 4. External login bilgisini kullanýcýya baðla
            var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);
            if (!addLoginResult.Succeeded)
                return Content("External login eklenemedi.");

            // 5. Login iþlemini yap
            await _signInManager.SignInAsync(user, isPersistent: true);

            return LocalRedirect(returnUrl);
        }


        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallbackIssuer(string returnUrl = "/")
        {
            var loginInfo = await _signInManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
                return RedirectToAction(nameof(SignIn));  // veya hata sayfasý

            // Kullanýcýyý Provider ve Key ile bul
            var user = await _userManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);

            var email = loginInfo.Principal.FindFirstValue(ClaimTypes.Email);
            var name = loginInfo.Principal.FindFirstValue(ClaimTypes.Name);
            var issuer = loginInfo.Principal.Claims.FirstOrDefault()?.Issuer ?? "local";
            var turkuazUserId = loginInfo.Principal.Claims.FirstOrDefault(c => c.Type == "UserId")?.Value ?? "0";

            if (string.IsNullOrWhiteSpace(name))
            {
                name = loginInfo.Principal.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
                var id = (ClaimsIdentity)loginInfo.Principal.Identity;
                id.AddClaim(new Claim(ClaimTypes.Name, name));
            }
            if (user == null)
            {

                user = new User
                {
                    UserName = name,
                    Email = email,
                    EmailConfirmed = true,
                    AuthType = issuer,
                    TurkuazUserId = Convert.ToInt32(turkuazUserId)
                };

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                    return Content("Kullanýcý oluþturulamadý: " + string.Join(", ", createResult.Errors.Select(e => e.Description)));

                var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);
                if (!addLoginResult.Succeeded)
                    return Content("External login eklenemedi.");
            }

            // Google'dan gelen claim'leri issuer ile koruyarak kopyala
            var claims = loginInfo.Principal.Claims.Select(c => new Claim(
                c.Type,
                c.Value,
                c.ValueType,
                c.Issuer,
                c.OriginalIssuer
            )).ToList();

            // Burada cookie scheme'i veriyoruz (Identity default scheme genelde "Identity.Application")
            // Sen kendi scheme'ini kontrol et
            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme, ClaimTypes.Name, ClaimTypes.Role);
            var principal = new ClaimsPrincipal(identity);

            // Cookie ile giriþ yap
            await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);

            return LocalRedirect(returnUrl);
        }


        [HttpGet]
        public IActionResult TurkuazLogin(string returnUrl = "/")
        {
            var redirectUrl = Url.Action(nameof(ExternalLoginCallbackIssuer), "Home", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("oidc", redirectUrl);
            // return Challenge(new AuthenticationProperties { RedirectUri = "/" }, "oidc");
            return Challenge(properties, "oidc");
        }
    }

}
