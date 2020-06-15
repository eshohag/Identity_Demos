using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using SimpleInjector;
using SimpleInjector.Integration.Web;
using SimpleInjector.Integration.Web.Mvc;
using System;
using System.Reflection;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace Pluralsight.AspNetDemo
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            ConfigureContainer();
        }

        private static void ConfigureContainer()
        {
            var container = new Container();
            container.Options.DefaultScopedLifestyle = new WebRequestLifestyle();

            const string connectionString = @"Data Source=DESKTOP-SHOHAG;Database=IdentityDemoDb;persist security info=True; user id=sa; password=Shohag@1234; MultipleActiveResultSets=True;Connect Timeout=10000";
            container.Register(() => new IdentityDbContext(connectionString), Lifestyle.Scoped);
            container.Register(() => new UserStore<IdentityUser>(container.GetInstance<IdentityDbContext>()), Lifestyle.Scoped);
            container.Register(() =>
            {
                var usermanager = new UserManager<IdentityUser, string>(container.GetInstance<UserStore<IdentityUser>>());
                //usermanager.RegisterTwoFactorProvider("SMS", new PhoneNumberTokenProvider<IdentityUser> { MessageFormat = "Token: {0}" });
               // usermanager.SmsService = new SmsService();              
               // usermanager.EmailService = new EmailService();

                usermanager.UserValidator = new UserValidator<IdentityUser, string>(usermanager) { RequireUniqueEmail = true };
                usermanager.PasswordValidator = new PasswordValidator
                {
                    RequireDigit = true,
                    RequireLowercase = true,
                    RequireNonLetterOrDigit = true,
                    RequireUppercase = true,
                    RequiredLength = 8
                };

                usermanager.UserLockoutEnabledByDefault = true;
                usermanager.MaxFailedAccessAttemptsBeforeLockout = 2;
                usermanager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(3);

                return usermanager;
            }, Lifestyle.Scoped);

            container.Register<SignInManager<IdentityUser, string>>(Lifestyle.Scoped);

            container.Register(() => container.IsVerifying
                ? new OwinContext().Authentication
                : HttpContext.Current.GetOwinContext().Authentication,
                Lifestyle.Scoped);

            container.RegisterMvcControllers(Assembly.GetExecutingAssembly());

            container.Verify();

            DependencyResolver.SetResolver(new SimpleInjectorDependencyResolver(container));
        }
    }
}
