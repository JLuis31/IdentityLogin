using Aplication.Data;
using Aplication.Intrfaces;
using Aplication.Models;
using Aplication.Repositorios;
using Aplication.MapProfiles;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        ConfigureServices(builder.Services, builder.Configuration, builder);
        var app = builder.Build();
        Configure(app);
        app.Run();
    }

    public static void ConfigureServices(IServiceCollection services, IConfiguration configuration, WebApplicationBuilder builder)
    {
        // Swagger
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo { Title = "API", Version = "v1" });
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = SecuritySchemeType.Http,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "Ingresa el token JWT en este formato: {tu token}"
            });
            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme {
                        Reference = new OpenApiReference {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    new string[] {}
                }
            });
        });

        // DbContext + Identity
        services.AddDbContext<AppDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        services.AddIdentity<Usuario, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

        services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/auth/login";
    options.AccessDeniedPath = "/auth/denied";
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.SlidingExpiration = true;
});


        // Repositorios
        services.AddScoped<ILoginRegister, LoginRegister>();

        // JWT
        services.Configure<JwtSettings>(configuration.GetSection("Jwt"));
        services.AddSingleton(sp => sp.GetRequiredService<IOptions<JwtSettings>>().Value);
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        // Cookies
        services.Configure<CookiePolicyOptions>(options =>
        {
            options.MinimumSameSitePolicy = SameSiteMode.None;
            options.Secure = CookieSecurePolicy.Always;
        });
        services.Configure<CookieAuthenticationOptions>(IdentityConstants.ExternalScheme, options =>
        {
            options.ExpireTimeSpan = TimeSpan.FromMinutes(60); // Ajusta el tiempo de expiración
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });


        // Autenticación
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = configuration["Jwt:Issuer"],
                ValidAudience = configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                    configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key is not configured")
                )),
                RoleClaimType = ClaimTypes.Role,
                ClockSkew = TimeSpan.Zero
            };

            options.Events = new JwtBearerEvents
            {
                OnChallenge = context =>
                {
                    context.HandleResponse();
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "application/json";
                    var result = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        message = "No tienes permiso para acceder a este recurso",
                        status = 401
                    });
                    return context.Response.WriteAsync(result);
                },
                OnForbidden = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    context.Response.ContentType = "application/json";
                    var result = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        message = "No tienes permiso para acceder a este recurso",
                        status = 403
                    });
                    return context.Response.WriteAsync(result);
                }
            };
        })
        .AddCookie(options =>
{
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60); // Ajusta el tiempo de expiración
    options.SlidingExpiration = true; // La cookie se renueva mientras la sesión esté activa
    options.Events.OnRedirectToLogin = context =>
    {
        // No redirigir automáticamente en el flujo de autenticación externa
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
})
        .AddGoogle(googleOptions =>
        {
            googleOptions.ClientId = configuration["Authorization:Google:ClientId"]
     ?? throw new InvalidOperationException("Google ClientId is not configured");
            googleOptions.ClientSecret = configuration["Authorization:Google:ClientSecret"]
                ?? throw new InvalidOperationException("Google ClientSecret is not configured");
            googleOptions.Scope.Add("profile");
            googleOptions.Scope.Add("email");
            googleOptions.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
            googleOptions.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
            googleOptions.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
            googleOptions.SaveTokens = false;
            googleOptions.SignInScheme = IdentityConstants.ExternalScheme;
            googleOptions.Events = new OAuthEvents
            {
                OnRedirectToAuthorizationEndpoint = context =>
                {
                    Console.WriteLine("Redirigiendo a: " + context.RedirectUri);
                    context.Response.Redirect(context.RedirectUri);
                    return Task.CompletedTask;
                },
                OnTicketReceived = context =>
                {
                    Console.WriteLine("Ticket recibido de Google. Datos: " +
                                       $"LoginProvider: {context.Principal?.Identity?.AuthenticationType}");
                    return Task.CompletedTask;
                },
                OnRemoteFailure = context =>
                {
                    Console.WriteLine("Fallo en autenticación externa:");
                    Console.WriteLine($"Mensaje de error: {context.Failure?.Message}");
                    Console.WriteLine($"StackTrace: {context.Failure?.StackTrace}");
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;

                    return context.Response.WriteAsync("Error en autenticación externa: " + context.Failure?.Message);
                }
            };

        });

        // Autorización
        services.AddAuthorization(options =>
        {
            options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
            options.AddPolicy("User", policy => policy.RequireRole("User"));
        });

        // CORS
        services.AddCors(options =>
        {
            options.AddPolicy("AllowAllOrigins", builder =>
                builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
        });

        // Otros servicios
        services.AddControllers();
        services.AddAutoMapper(typeof(MapProfiles));

        // Logging
        // Logging
        builder.Logging.AddConsole();
        builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Debug);

    }

    public static void Configure(WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseHttpsRedirection();
        app.UseRouting();

        app.UseStatusCodePages(async context =>
        {
            var response = context.HttpContext.Response;
            if (response.StatusCode is 401 or 403 or 500)
            {
                Console.WriteLine($"Código de estado: {response.StatusCode}");
            }
        });

        app.UseCors("AllowAllOrigins");
        app.UseCookiePolicy();
        app.UseAuthentication();
        app.UseAuthorization();


        app.UseStaticFiles();
        app.MapControllers();
    }
}
