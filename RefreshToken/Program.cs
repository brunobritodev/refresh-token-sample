using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MiniValidation;
using NetDevPack.Security.Jwt.AspNetCore;
using NetDevPack.Security.Jwt.Core;
using NetDevPack.Security.Jwt.Core.Interfaces;
using RefreshToken;
using JwtRegisteredClaimNames = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<RefreshTokenContext>(options => options.UseInMemoryDatabase("RT"));
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<RefreshTokenContext>().AddDefaultTokenProviders();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "https://refreshtoken.test",
        ValidAudience = "RefreshToken.API"
    };
});
builder.Services.AddAuthorization();
builder.Services.AddMemoryCache();
builder.Services.AddJwksManager().PersistKeysInMemory().UseJwtValidation();
IdentityModelEventSource.ShowPII = true;
// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Refresh Token Sample",
        Description = "Developed by Bruno Brito",
        License = new OpenApiLicense { Name = "MIT", Url = new Uri("https://opensource.org/licenses/MIT") }
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o token JWT desta maneira: Bearer {seu token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();


static async Task<string> GenerateAccessToken(UserManager<IdentityUser> userManager, IJwtService jwtService, string? email)
{
    var user = await userManager.FindByEmailAsync(email);
    var userRoles = await userManager.GetRolesAsync(user);
    var identityClaims = new ClaimsIdentity();
    identityClaims.AddClaims(await userManager.GetClaimsAsync(user));
    identityClaims.AddClaims(userRoles.Select(s => new Claim("role", s)));

    identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
    identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Email, user.Email));
    identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

    var handler = new JwtSecurityTokenHandler();

    var securityToken = handler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = "https://refreshtoken.test",
        Audience = "RefreshToken.API",
        SigningCredentials = await jwtService.GetCurrentSigningCredentials(),
        Subject = identityClaims,
        NotBefore = DateTime.UtcNow,
        Expires = DateTime.UtcNow.AddMinutes(60),
        IssuedAt = DateTime.UtcNow,
        TokenType = "at+jwt"
    });

    var encodedJwt = handler.WriteToken(securityToken);
    return encodedJwt;
}


static async Task<string> GenerateRefreshToken(UserManager<IdentityUser> userManager, IJwtService jwtService, string? email)
{
    var jti = Guid.NewGuid().ToString();
    var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Email, email),
        new Claim(JwtRegisteredClaimNames.Jti, jti)
    };

    // Necessário converver para IdentityClaims
    var identityClaims = new ClaimsIdentity();
    identityClaims.AddClaims(claims);

    var handler = new JwtSecurityTokenHandler();

    var securityToken = handler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = "https://refreshtoken.test",
        Audience = "RefreshToken.API",
        SigningCredentials = await jwtService.GetCurrentSigningCredentials(),
        Subject = identityClaims,
        NotBefore = DateTime.Now,
        Expires = DateTime.Now.AddDays(30),
        TokenType = "rt+jwt"
    });
    await UpdateLastGeneratedClaim(userManager, email, jti);
    var encodedJwt = handler.WriteToken(securityToken);
    return encodedJwt;
}

static async Task UpdateLastGeneratedClaim(UserManager<IdentityUser> userManager, string? email, string jti)
{
    var user = await userManager.FindByEmailAsync(email);
    var claims = await userManager.GetClaimsAsync(user);
    var newLastRtClaim = new Claim("LastRefreshToken", jti);

    var claimLastRt = claims.FirstOrDefault(f => f.Type == "LastRefreshToken");
    if (claimLastRt != null)
        await userManager.ReplaceClaimAsync(user, claimLastRt, newLastRtClaim);
    else
        await userManager.AddClaimAsync(user, newLastRtClaim);

}

app.MapPost("/accounts", [AllowAnonymous] async (
        UserManager<IdentityUser> userManager,
        UserRegister registerUser) =>
    {
        if (!MiniValidator.TryValidate(registerUser, out var errors))
            return Results.ValidationProblem(errors);

        var user = new IdentityUser
        {
            UserName = registerUser.Email,
            Email = registerUser.Email,
            EmailConfirmed = true
        };

        var result = await userManager.CreateAsync(user, registerUser.Password);

        if (!result.Succeeded)
            return Results.BadRequest(result.Errors);

        return Results.Ok();

    }).ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("New user")
    .WithTags("user");


app.MapPost("/sign-in", [AllowAnonymous] async (
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IJwtService jwtService,
        UserLogin login) =>
    {
        if (!MiniValidator.TryValidate(login, out var errors))
            return Results.ValidationProblem(errors);

        var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, false, true);

        if (result.IsLockedOut)
            return Results.BadRequest("Account blocked");

        if (!result.Succeeded)
            return Results.BadRequest("Invalid username or password");

        var at = await GenerateAccessToken(userManager, jwtService, login.Email);
        var rt = await GenerateRefreshToken(userManager, jwtService, login.Email);
        return Results.Ok(new UserLoginResponse(at, rt));

    }).ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("Sign-in")
    .WithTags("user");


app.MapPost("/refresh-token", [AllowAnonymous] async (
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IJwtService jwtService,
        [FromForm] Token token) =>
    {
        if (!MiniValidator.TryValidate(token, out var errors))
            return Results.ValidationProblem(errors);

        var handler = new JsonWebTokenHandler();

        var result = handler.ValidateToken(token.RefreshToken, new TokenValidationParameters()
        {
            ValidIssuer = "https://refreshtoken.test",
            ValidAudience = "RefreshToken.API",
            RequireSignedTokens = false,
            IssuerSigningKey = await jwtService.GetCurrentSecurityKey(),
        });

        if (!result.IsValid)
            return Results.BadRequest("Expired token");

        var user = await userManager.FindByEmailAsync(result.Claims[JwtRegisteredClaimNames.Email].ToString());
        var claims = await userManager.GetClaimsAsync(user);

        if (!claims.Any(c => c.Type == "LastRefreshToken" && c.Value == result.Claims[JwtRegisteredClaimNames.Jti].ToString()))
            return Results.BadRequest("Expired token");

        if (user.LockoutEnabled)
            if (user.LockoutEnd < DateTime.Now)
                return Results.BadRequest("User blocked");

        if (claims.Any(c => c.Type == "TenhoQueRelogar" && c.Value == "true"))
            return Results.BadRequest("User must login again");


        var at = await GenerateAccessToken(userManager, jwtService, result.Claims[JwtRegisteredClaimNames.Email].ToString());
        var rt = await GenerateRefreshToken(userManager, jwtService, result.Claims[JwtRegisteredClaimNames.Email].ToString());
        return Results.Ok(new UserLoginResponse(at, rt));


    }).ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("Refresh Token")
    .WithTags("user");

app.MapGet("/protected-endpoint", [Authorize] (IHttpContextAccessor context) =>
{
    return Results.Ok(context.HttpContext?.User.Claims.Select(s => new { s.Type, s.Value }));
});

app.Run();
