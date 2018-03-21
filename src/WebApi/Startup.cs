using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.Swagger;
using WebApi.Configurations;
using WebApi.Contexts;
using WebApi.Models;
using WebApi.Rules;

namespace WebApi
{
    public class Startup
    {
        public Startup (IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices (IServiceCollection services)
        {

            var sp = services.BuildServiceProvider ();
            var hostingEnv = sp.GetService<IHostingEnvironment> ();

            // Add framework services.
            services.AddOptions ();
            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor> ();

            RegisterRules (services);

            services.AddDbContext<AdminContext> (options =>
            {
                options.UseSqlServer (Configuration.GetConnectionString ("AdminConnection"));
            });

            ConfigIdentity (services, hostingEnv);

            // Use policy auth.
            // TODO: implement access role base policy
            // see this: https://stackoverflow.com/a/40824351/436494 
            // and this: http://benfoster.io/blog/asp-net-identity-role-claims //DevSkim: ignore DS137138
            // services.AddAuthorization(options =>
            // {
            //    options.AddPolicy("ApiUser",
            //        policy => policy.RequireClaim("api_user", "true"));
            // });

            // nothing after this
            services.AddMvc (config =>
            {
                // Make authentication compulsory across the board (i.e. shut
                // down EVERYTHING unless explicitly opened up).
                var policy = new AuthorizationPolicyBuilder ()
                    .RequireAuthenticatedUser ()
                    .Build ();
                config.Filters.Add (new AuthorizeFilter (policy));
            }).AddJsonOptions (JsonOptions.Configure);

            // Register the Swagger generator, defining one or more Swagger documents
            services.AddSwaggerGen (c =>
            {
                c.SwaggerDoc ("v1", new Info { Title = "WebApi api", Version = "v1" });
            });

        }

        private void RegisterRules (IServiceCollection services)
        {
            services.AddTransient<AccountRules> ();
        }

        private void ConfigIdentity (IServiceCollection services, IHostingEnvironment hostingEnv)
        {
            var jwtOptions = new JwtOptions ();
            Configuration.GetSection (nameof (JwtOptions)).Bind (jwtOptions);

            SymmetricSecurityKey signingKey = new SymmetricSecurityKey (Encoding.ASCII.GetBytes (jwtOptions.SecretKey));

            // ConfigureMaps JwtIssuerOptions
            services.Configure<JwtOptions> (options =>
            {
                options.Issuer = jwtOptions.Issuer;
                options.Audience = jwtOptions.Audience;
                options.InstanceClaimName = jwtOptions.InstanceClaimName;
                options.SigningCredentials = new SigningCredentials (signingKey, SecurityAlgorithms.HmacSha256);
            });

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtOptions.Issuer,

                ValidateAudience = true,
                ValidAudience = jwtOptions.Audience,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,

                RequireExpirationTime = true,
                ValidateLifetime = true,

                ClockSkew = TimeSpan.Zero
            };

            var tokenCache = new JwtTokenCache ();
            services.AddSingleton (tokenCache);

            services.AddAuthentication (options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer (options =>
                {
                    options.TokenValidationParameters = tokenValidationParameters;
                    options.Events = new JwtBearerEvents ()
                    {
                        OnAuthenticationFailed = OnRedirectToLogin
                    };
                });

            var identityOptions = new CustomIdentityOptions ();
            Configuration.GetSection (nameof (CustomIdentityOptions)).Bind (identityOptions);

            IdentityBuilder builder = services.AddIdentityCore<User> (options =>
            {
                options.User.RequireUniqueEmail = identityOptions.UserRequireUniqueEmail;
                options.Password.RequiredLength = identityOptions.PasswordRequiredLength;
                options.Password.RequireDigit = identityOptions.PasswordRequireDigit;
                options.Password.RequireLowercase = identityOptions.PasswordRequireLowercase;
                options.Password.RequireNonAlphanumeric = identityOptions.PasswordRequireNonAlphanumeric;
                options.Password.RequireUppercase = identityOptions.PasswordRequireUppercase;
                options.Lockout.MaxFailedAccessAttempts = identityOptions.LockoutMaxFailedAccessAttempts;
            });

            builder = new IdentityBuilder (builder.UserType, typeof (IdentityRole), builder.Services)
                .AddEntityFrameworkStores<AdminContext> ()
                .AddDefaultTokenProviders ();

            builder.AddRoleValidator<RoleValidator<IdentityRole>> ();
            builder.AddRoleManager<RoleManager<IdentityRole>> ();
            builder.AddSignInManager<SignInManager<User>> ();
            builder.AddUserValidator<UserValidator<User>> ();
        }

        private static Task OnRedirectToLogin (AuthenticationFailedContext context)
        {
            if (context.Request.Path.StartsWithSegments ("/api"))
            {
                // return 401 if not "logged in" from an API Call
                context.Response.StatusCode = (int) HttpStatusCode.Unauthorized;
            }
            else
            {
                context.Success ();
            }

            // Redirect users to login page
            return Task.CompletedTask;
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure (IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment ())
            {
                app.UseDeveloperExceptionPage ();
            }

            app.UseMiddleware(typeof(ErrorHandlingMiddleware));

            app.Use (async (context, next) =>
            {
                await next ();

                if (context.Response.StatusCode == 404 &&
                    !Path.HasExtension (context.Request.Path.Value) &&
                    !context.Request.Path.Value.StartsWith ("/api/", StringComparison.CurrentCulture))
                {
                    context.Request.Path = "/";
                    await next ();
                }
            });
            
            app.UseDefaultFiles ();
            app.UseStaticFiles ();
            app.UseAuthentication ();

            // Enable middleware to serve generated Swagger as a JSON endpoint.
            app.UseSwagger ();

            // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.), specifying the Swagger JSON endpoint.
            app.UseSwaggerUI (c =>
            {
                c.SwaggerEndpoint ("/swagger/v1/swagger.json", "WebApi");
            });

            app.UseMvc ();

            app.UseAutoMapperConfig ();
        }
    }
}