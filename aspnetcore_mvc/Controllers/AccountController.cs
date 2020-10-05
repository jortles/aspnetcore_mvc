using aspnetcore_mvc.Email;
using aspnetcore_mvc.Models;
using aspnetcore_mvc.Models.Account;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace aspnetcore_mvc.Controllers
{
    public class AccountController : Controller
    {
        private readonly IMapper _mapper;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AccountController> _logger;
        private readonly IEmailSender _emailSender;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<AccountController> logger, IMapper mapper, IEmailSender emailSender)
        {
            _mapper = mapper;
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = _mapper.Map<ApplicationUser>(model);


            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }

                return View(model);
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            var confirmationLink = Url.Action(nameof(ConfirmEmail), "Account", new { token, email = user.Email }, Request.Scheme);

            var message = new Message(new string[] { user.Email }, "Confirmation email link", confirmationLink, null);
            await _emailSender.SendEmailAsync(message);

            return RedirectToAction(nameof(SuccessRegistration));

        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return View("Error");

            var result = await _userManager.ConfirmEmailAsync(user, token);
            return View(result.Succeeded ? nameof(ConfirmEmail) : "Error");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Error()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult SuccessRegistration()
        {
            return View();
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel userModel, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {

                ApplicationUser user = _userManager.Users.SingleOrDefault(u => u.UserName == userModel.Email);
                if (user != null)
                {
                    HttpContext.Session.SetString("Username", user.UserName);

                    return await Task.FromResult(RedirectToAction(nameof(EnterPassword)));
                }
                else
                {
                    return await Task.FromResult(RedirectToAction(nameof(EnterPassword)));
                }
            }

            return await Task.FromResult(RedirectToAction(nameof(EnterPassword)));
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> EnterPassword()
        {
            string username = HttpContext.Session.GetString("Username");
            if (username != null)
            {
                EnterPasswordModel model = new EnterPasswordModel
                {
                    Username = username
                };
                ApplicationUser user = _userManager.Users.SingleOrDefault(u => u.UserName == username);

                if (user != null)
                {
                    return await Task.FromResult(View(model));
                }

            }
            return await Task.FromResult(View(nameof(EnterPassword)));

        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> EnterPassword(EnterPasswordModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                string username = HttpContext.Session.GetString("Username");
                if (username != null)
                {
                    ApplicationUser user = _userManager.Users.SingleOrDefault(u => u.UserName == username);
                    if (user != null)
                    {
                        Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(username, model.Password, false, false);
                        if (result.Succeeded)
                        {
                            return RedirectToAction(nameof(ManageController.Index), "Manage");
                        }
                        if (user.TwoFactorEnabled)
                        {
                            return RedirectToAction(nameof(LoginWith2fa));
                        }
                        else
                        {
                            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                            return View(model);
                        }
                    }
                }

            }
            return RedirectToAction(nameof(Login));
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWith2fa(bool rememberMe, string returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
            if (!providers.Contains("Email"))
            {
                return View(nameof(Error));
            }

            var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

            var message = new Message(new string[] { user.Email }, "Authentication token", token, null);
            await _emailSender.SendEmailAsync(message);

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faModel twofaModel, bool rememberMe, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(twofaModel);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var result = await _signInManager.TwoFactorSignInAsync("Email", twofaModel.TwoFactorCode, twofaModel.RememberMe, rememberClient: false); ;
            if (result.Succeeded)
            {
                if (User.IsInRole("Admin"))
                {
                    return RedirectToAction("ListUsers", "Administration");
                }

                return RedirectToAction(nameof(ManageController.Index), "Manage");
            }
            else if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "The account is locked out");
                return View();
            }
            else
            {
                ModelState.AddModelError("", "Invalid Login Attempt");
                return View();
            }

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null && await _userManager.IsEmailConfirmedAsync(user))
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                    var passwordResetLink = Url.Action("ResetPassword", "Account",
                            new { email = model.Email, token = token }, Request.Scheme);

                    var message = new Message(new string[] { user.Email }, "Reset password link", passwordResetLink, null);
                    await _emailSender.SendEmailAsync(message);
                }
                return View("ForgotPasswordConfirmation");
            }
            return View(model);
        }

        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string token, string email)
        {
            if (token == null || email == null)
            {
                ModelState.AddModelError("", "Invalid password reset token");
            }
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
                    if (result.Succeeded)
                    {
                        return View("ResetPasswordConfirmation");
                    }
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View(model);
                }
                return View("ResetPasswordConfirmation");
            }
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }


        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);
            else
                return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}
