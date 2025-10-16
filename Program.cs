using AspNetCoreIdentity.Service.Services;
using AspNetCoreIdentityApp.ClaimProvider;
using AspNetCoreIdentityApp.Core.OptionsModel;
using AspNetCoreIdentityApp.Core.Permission;
using AspNetCoreIdentityApp.Extension;
using AspNetCoreIdentityApp.Repository.Models;
using AspNetCoreIdentityApp.Repository.Seed;
using AspNetCoreIdentityApp.Requirement;
using AspNetCoreIdentityApp.Service.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
        sqlOptions => sqlOptions.MigrationsAssembly("AspNetCoreIdentity.Repository")));

builder.Services.AddIdentityWithExt();

builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailSettings"));
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IClaimsTransformation, UserClaimProvider>();
builder.Services.AddScoped<IAuthorizationHandler, ExchangeExpireRequirementHandler>();
builder.Services.AddScoped<IAuthorizationHandler, ViolenceRequirementHandler>();
builder.Services.AddScoped<IMemberService, MemberService>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("IstanbulPolicy", policy =>
    {
        policy.RequireClaim("city", "Ýstanbul");
    });
    options.AddPolicy("ExchangePolicy", policy =>
    {
        policy.AddRequirements(new ExchangeExpireRequirement());
    });
    options.AddPolicy("ViolencePolicy", policy =>
    {
        policy.AddRequirements(new ViolenceRequirement() { ThresholdAge = 18 });
    });
    foreach (var nested in typeof(Permission).GetNestedTypes(BindingFlags.Public | BindingFlags.Static))
    {
        var fields = nested.GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy);

        foreach (var field in fields)
        {
            // const string deðerleri almak için GetRawConstantValue kullan
            var value = field.GetRawConstantValue()?.ToString();
            if (!string.IsNullOrEmpty(value))
            {
                options.AddPolicy(value, policy =>
                {
                    policy.RequireClaim("permission", value);
                });
            }
        }
    }

    options.AddPolicy("OrderPermissionReadOrDelete", policy =>
    {
        policy.RequireClaim("permission", Permission.Order.View, Permission.Order.Edit, Permission.Order.Delete, Permission.Stock.Delete);
    });
    //options.AddPolicy("Permissions.Order.Delete", policy =>
    //{
    //    policy.RequireClaim("permission", Permission.Order.Delete);
    //});
    //options.AddPolicy("Permissions.Stock.Delete", policy =>
    //{
    //    policy.RequireClaim("permission", Permission.Stock.Delete);
    //});
});
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"C:\Shared-Keys"))
    .SetApplicationName("SharedCookieApp");

// Authentication config
builder.Services.AddAuthentication(options =>
{
    // Identity kendi cookie scheme’ini otomatik ekler, burada sadece scheme ayarlarý yapýlýr
    //options.DefaultScheme = IdentityConstants.ApplicationScheme; // "Identity.Application"
    //options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme; // "oidc"
    //options.DefaultForbidScheme = IdentityConstants.ApplicationScheme;

    options.DefaultScheme = IdentityConstants.ApplicationScheme;            // Cookie
    options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;   // Cookie
    options.DefaultForbidScheme = IdentityConstants.ApplicationScheme;
})
//.AddCookie(options =>
//{
//    options.Cookie.SameSite = SameSiteMode.None;
//    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

//})
.AddGoogle(options =>
{
    options.ClientId = "4491108361-cu2ba1tgj2g29eh5i00lmovvac1mugv8.apps.googleusercontent.com";
    options.ClientSecret = "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";
    options.CallbackPath = "/signin-google";

    options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
    options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
    options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
})
.AddOpenIdConnect("oidc", options =>
{
    options.Authority = "https://test.turkuazgo.com/iam/realms/test/";
    options.ClientId = "NetCoreApp";
    options.ClientSecret = "XsyvzVBn1M83pqyNnYnY2wwt49Vo2Fjj";

    //options.SignInScheme = IdentityConstants.ApplicationScheme; // Cookie scheme ile eþleþtir
    options.SignInScheme = IdentityConstants.ExternalScheme;
    options.ResponseType = "code";
    options.RequireHttpsMetadata = false;
    //options.CallbackPath = "/signin-oidc";
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");

    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "preferred_username",
        RoleClaimType = "roles"
    };
})
.AddJwtBearer("JwtScheme", options =>
{
    options.Authority = "http://appA.myapps.test"; // AppA AuthServer
    options.Audience = "AppC";                       // AppC için
    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "name",
        RoleClaimType = "role"
    };
});

//builder.Services.AddAuthentication()
//builder.WebHost.ConfigureKestrel(options =>
//{
//    options.ListenAnyIP(5001, listenOptions =>
//    {
//        listenOptions.UseHttps();
//    });
//});


// Configure Identity cookie settings here — this configures the cookie scheme added by Identity internally
builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.LoginPath = "/Home/SignIn";
    opt.LogoutPath = "/Member/Logout";
    opt.AccessDeniedPath = "/Member/AccessDenied";

    opt.ExpireTimeSpan = TimeSpan.FromDays(60);
    opt.SlidingExpiration = true;

    // Cookie adý Identity.Application olmalý, default zaten böyle, ama burada açýk yazdýk
    //opt.Cookie.Name = IdentityConstants.ApplicationScheme;// cookie diðer uygulama ile kullanýlsýn diye deðiþtirildi.

    opt.Cookie.Name = ".AspNet.SharedCookie";

    // Localhost subdomain testleri için domain ayarý
    opt.Cookie.Domain = ".myapps.test";

    // Localhost testinde HTTPS yoksa
    opt.Cookie.SecurePolicy = CookieSecurePolicy.None;// sadece localhost için böyle olmalý CookieSecurePolicy.Always; olarak deðiþmeli prod için
});

builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.ValidationInterval = TimeSpan.FromMinutes(10);
});

var app = builder.Build();

// Seed roles on startup
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<Role>>();
    await PermissionSeed.Seed(roleManager);
}

// Middleware pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// Program.cs veya ayrý bir controller'da
app.MapControllerRoute(
    name: "areas",
    pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
