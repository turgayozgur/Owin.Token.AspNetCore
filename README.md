# Owin.Token.AspNetCore #
[![Latest version](https://img.shields.io/nuget/v/Owin.Token.AspNetCore.svg)](https://www.nuget.org/packages/Owin.Token.AspNetCore)

Simple .NET Core library to reading OWIN based OAuth tokens. Just implemented the code that deserialize OWIN based token to ticket. So, you can Authenticate your API user by old tokens on your ASPNET Core application. Use the current OAuth mechanism of ASPNET Core for the new token generations.

## Quick Usage ##

```csharp
var ticket = LegacyOAuthSecurityTokenHelper.GetTicket(token, new LegacyTokenAuthenticationOptions
    {
        DecryptionKey = "machineKey-DecryptionKey",
        ValidationKey = "machineKey-ValidationKey",
        EncryptionMethod = EncryptionMethod.AES, // Default AES
        ValidationMethod = ValidationMethod.HMACSHA256 // Default HMACSHA256
    }));

// Authenticate your user with ticket.Identity.Claims!
```

## Example Usage with JwtBearer ##

You can use the library with current ASPNET Core JwtBearer OAuth mechanism. Generate your tokens with JwtBearer and firstly validate that tokens with it. If validation falied, try again with LegacyOAuthSecurityTokenHelper.

Add authentication with JwtBearer functionality.

```csharp
public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
{
    services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                // You can change the parameters depends on your implementation.
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey =
                    new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes("The key(maybe guid) you specified when generating JwtBearer tokens"))
            };
            // Here is the important point! Add our fallback to SecurityTokenValidators list to validate OWIN tokens.
            options.SecurityTokenValidators.Add(new LegacyOAuthSecurityTokenHandler(new LegacyTokenAuthenticationOptions
            {
                DecryptionKey = configuration.GetValue<string>("LegacyTokenAuthentication:DecryptionKey"),
                ValidationKey = configuration.GetValue<string>("LegacyTokenAuthentication:ValidationKey")
            }));
        });
}
```

Implement the LegacyOAuthSecurityTokenHandler

```csharp
public class LegacyOAuthSecurityTokenHandler : SecurityTokenHandler
{
    private readonly LegacyTokenAuthenticationOptions _options;

    public LegacyOAuthSecurityTokenHandler(LegacyTokenAuthenticationOptions options)
    {
        _options = options;
    }

    public override bool CanValidateToken => true;

    public override bool CanReadToken(string tokenString) => true;
    
    /// <summary>
    /// ValidateToken
    /// </summary>
    /// <param name="token"></param>
    /// <param name="validationParameters"></param>
    /// <param name="validatedToken"></param>
    /// <returns></returns>
    public override ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters,
        out SecurityToken validatedToken)
    {
        var ticket = LegacyOAuthSecurityTokenHelper.GetTicket(token, _options);

        var claimsIdentity = new ClaimsIdentity(ClaimTypes.Email).AddClaims(ticket.Identity.Claims);
        
        validatedToken = default(SecurityToken);
        
        return new ClaimsPrincipal(claimsIdentity);
    }
    
    public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters)
    {
        throw new NotImplementedException();
    }
    
    public override void WriteToken(XmlWriter writer, SecurityToken token)
    {
        throw new NotImplementedException();
    }

    public override Type TokenType => typeof(SecurityToken);
}
```

## Bonus: Find Auto Generated MachineKey Detail ##

```csharp
byte[] autogenKeys = (byte[])typeof(HttpRuntime).GetField("s_autogenKeys", BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);

Type t = typeof(System.Web.Security.DefaultAuthenticationEventArgs).Assembly.GetType("System.Web.Security.Cryptography.MachineKeyMasterKeyProvider");
ConstructorInfo ctor = t.GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic)[0];

Type ckey = typeof(System.Web.Security.DefaultAuthenticationEventArgs).Assembly.GetType("System.Web.Security.Cryptography.CryptographicKey");
ConstructorInfo ckeyCtor = ckey.GetConstructors(BindingFlags.Instance | BindingFlags.Public)[0];
Object ckeyobj = ckeyCtor.Invoke(new object[] { autogenKeys });
object o = ctor.Invoke(new object[] { new MachineKeySection(), null, null, ckeyobj, null });
var encKey = t.GetMethod("GenerateCryptographicKey", BindingFlags.NonPublic | BindingFlags.Instance)
    .Invoke(o, new object[] { "decryptionKey", "AutoGenerate,IsolateApps", 0, 256, "Invalid_decryption_key" });
byte[] encBytes = ckey.GetMethod("GetKeyMaterial").Invoke(encKey, null) as byte[];
var vldKey = t.GetMethod("GenerateCryptographicKey", BindingFlags.NonPublic | BindingFlags.Instance)
    .Invoke(o, new object[] { "validationKey", "AutoGenerate,IsolateApps", 256, 256, "Invalid_validation_key" });
byte[] vldBytes = ckey.GetMethod("GetKeyMaterial").Invoke(vldKey, null) as byte[];
string decryptionKey = BitConverter.ToString(encBytes);
decryptionKey = decryptionKey.Replace("-", "");
string validationKey = BitConverter.ToString(vldBytes);
validationKey = validationKey.Replace("-", "");
```

## License ##
The Owin.Token.AspNetCore is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).