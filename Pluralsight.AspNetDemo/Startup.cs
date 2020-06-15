using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using System;
using System.Web.Mvc;

[assembly: OwinStartup(typeof(Pluralsight.AspNetDemo.Startup))]
namespace Pluralsight.AspNetDemo
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.CreatePerOwinContext<UserManager<IdentityUser, string>>(
                () => DependencyResolver.Current.GetService<UserManager<IdentityUser, string>>());

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                Provider = new CookieAuthenticationProvider
                {
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser, string>, IdentityUser>(
                        validateInterval: TimeSpan.FromSeconds(3),
                        regenerateIdentity: (manager, user) => manager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie))
                }
            });

            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            //app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions
            //{
            //    ClientId = ConfigurationManager.AppSettings["google:ClientId"],
            //    ClientSecret = ConfigurationManager.AppSettings["google:ClientSecret"],
            //    Caption = "Google"
            //});
        }
    }
}
