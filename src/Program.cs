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
        // Add services to the container.
        services.AddEndpointsApiExplorer();

        // Añadicion de Swagger para la documentación de la API
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

        // Añadicion de SqlServer y Entity Framework Core para la base de datos
        services.AddDbContext<AppDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        // Añadicion de Identity para la autenticación y autorización
        services.AddIdentity<Usuario, IdentityRole>()
        .AddEntityFrameworkStores<AppDbContext>();

        // Añadicion del repositorio de Login y Register
        services.AddScoped<ILoginRegister, LoginRegister>();

        // Añadicion del mapeo del JWT
        services.Configure<JwtSettings>(configuration.GetSection("Jwt"));
        services.AddSingleton(sp => sp.GetRequiredService<IOptions<JwtSettings>>().Value);

        // Añadicion de la configuración del JWT
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        // Configuración de JWT
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = configuration["jwt:Issuer"],
                ValidAudience = configuration["jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["jwt:Key"] ?? throw new InvalidOperationException("JWT Key is not configured"))),
                RoleClaimType = ClaimTypes.Role,
            };

            options.Events = new JwtBearerEvents
            {
                OnChallenge = context =>
                {
                    // Evita que se mande la respuesta predeterminada 401
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

        });

        // Añadicion de Authorization y CORS
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

        // Añadicion de Controllers y AutoMapper
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
        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseCors("AllowAllOrigins");
        app.UseAuthentication();
        app.UseAuthorization();



        app.UseStaticFiles();
        app.MapControllers();
    }
}








