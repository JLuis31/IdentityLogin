using Aplication.Data;
using Aplication.Intrfaces;
using Aplication.Models;
using Aplication.Repositorios;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Aplication.MapProfiles;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        ConfigureServices(builder.Services, builder.Configuration);
        var app = builder.Build();
        Configure(app);
        app.Run();
    }

    public static void ConfigureServices(IServiceCollection services, IConfiguration configuration)
    {
        // Swagger para la documentación de la API
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo { Title = "API", Version = "v1" });
            c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = Microsoft.OpenApi.Models.ParameterLocation.Header,
                Description = "Ingresa el token JWT en este formato: {tu token}"
            });
            c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
            {
                {
                    new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                    {
                        Reference = new Microsoft.OpenApi.Models.OpenApiReference
                        {
                            Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    new string[] { }
                }
            });
        });

        // Configuración de Entity Framework Core y SQL Server
        services.AddDbContext<AppDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        // Configuración de Identity (esto registra internamente los esquemas de cookies)
        services.AddIdentity<Usuario, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>();

        // Repositorios
        services.AddScoped<ILoginRegister, LoginRegister>();

        // Configuración del mapeo del JWT
        services.Configure<JwtSettings>(configuration.GetSection("Jwt"));
        services.AddSingleton(sp => sp.GetRequiredService<IOptions<JwtSettings>>().Value);

        // Limpieza del mapeo de claims por defecto
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        // Configuración de la autenticación:
        // - El flujo principal de autenticación para la API es mediante JWT.
        // - El login externo (Google) usará el esquema de cookie ya configurado en Identity para login externo.
        services.AddAuthentication(options =>
        {
            // Usamos JWT por defecto para autenticate y challenge (para nuestros endpoints API)
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
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
                ValidIssuer = configuration["jwt:Issuer"],
                ValidAudience = configuration["jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                    configuration["jwt:Key"] ?? throw new InvalidOperationException("JWT Key is not configured")
                )),
                RoleClaimType = ClaimTypes.Role,
            };

            options.Events = new JwtBearerEvents
            {
                OnChallenge = context =>
                {
                    // Evita la respuesta predeterminada 401
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
        // **Eliminar este .AddCookie() extra, ya que Identity ya registra las cookies internas (como Identity.External)**
        //.AddCookie() 
        .AddGoogle(googleOptions =>
        {
            googleOptions.ClientId = configuration["Authorization:Google:ClientId"] ??
                throw new InvalidOperationException("Google ClientId is not configured");
            googleOptions.ClientSecret = configuration["Authorization:Google:ClientSecret"] ??
                throw new InvalidOperationException("Google ClientSecret is not configured");
            googleOptions.CallbackPath = "/api/Auth/google-callback"; // Asegúrate de que esta URL coincida en la consola de Google

            // Importante: le decimos que use el esquema de cookie que ya registró Identity para login externo
            googleOptions.SignInScheme = IdentityConstants.ExternalScheme;
            // Configuración de la cookie de correlación para entornos cross-site
            googleOptions.CorrelationCookie.SameSite = SameSiteMode.None;
            googleOptions.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        });

        // Configuración de Authorization y CORS
        services.AddAuthorization(options =>
        {
            options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
            options.AddPolicy("User", policy => policy.RequireRole("User"));
        });
        services.AddCors(options =>
        {
            options.AddPolicy("AllowAllOrigins",
                builder => builder.AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader());
        });

        // Controllers y AutoMapper
        services.AddControllers();
        services.AddAutoMapper(typeof(MapProfiles));
    }

    public static void Configure(WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }
        app.UseCookiePolicy(new CookiePolicyOptions
        {
            MinimumSameSitePolicy = SameSiteMode.None,
            Secure = CookieSecurePolicy.Always
        });
        app.UseForwardedHeaders();
        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseCors("AllowAllOrigins");
        app.UseForwardedHeaders(new ForwardedHeadersOptions
        {
            ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor |
                               Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto
        });
        app.UseAuthentication();
        app.UseAuthorization();

        app.UseStaticFiles();
        app.MapControllers();
    }
}