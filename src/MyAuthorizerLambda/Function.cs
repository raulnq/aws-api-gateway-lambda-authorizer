using Amazon.Lambda.Core;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Amazon.Lambda.APIGatewayEvents;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace MyAuthorizerLambda;

public class Function
{
    private string _tenantId;
    private string _clientId;
    private ConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

    public Function()
    {
        _tenantId = Environment.GetEnvironmentVariable("TENANT_ID")!;
        _clientId = Environment.GetEnvironmentVariable("CLIENT_ID")!;
        string metadataEndpoint = $"https://login.microsoftonline.com/{_tenantId}/v2.0/.well-known/openid-configuration";
        _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(metadataEndpoint, new OpenIdConnectConfigurationRetriever());
    }

    public async Task<APIGatewayCustomAuthorizerResponse> FunctionHandler(APIGatewayCustomAuthorizerRequest request, ILambdaContext context)
    {
        var authorized = false;
        var principalId = "user";
        try
        {
            var openIdConnectConfiguration = await _configurationManager.GetConfigurationAsync();
            var validationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                ValidAudience = $"api://{_clientId}",
                IssuerSigningKeys = openIdConnectConfiguration.SigningKeys,
                ValidIssuer = $"https://sts.windows.net/{_tenantId}/"
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(request.AuthorizationToken, validationParameters, out var securityToken);
            authorized = true;
            principalId = principal.Identity?.Name;
        }
        catch (Exception ex)
        {
            context.Logger.LogError($"Error occurred validating token: {ex.Message}");
            authorized = false;
        }

        var policy = new APIGatewayCustomAuthorizerPolicy
        {
            Version = "2012-10-17",
            Statement =
            [
                new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement
                {
                    Action = new HashSet<string>(new string[] { "execute-api:Invoke" }),
                    Effect = authorized ? "Allow" : "Deny",
                    Resource = new HashSet<string>(new string[] { request.MethodArn })

                }
            ]
        };

        var contextOutput = new APIGatewayCustomAuthorizerContextOutput
        {
            ["Path"] = request.MethodArn
        };

        return new APIGatewayCustomAuthorizerResponse
        {
            PrincipalID = principalId,
            Context = contextOutput,
            PolicyDocument = policy
        };
    }
}
