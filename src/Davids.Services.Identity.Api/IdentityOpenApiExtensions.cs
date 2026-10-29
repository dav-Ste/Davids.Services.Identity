using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace Davids.Services.Identity.Api;

public static class IdentityOpenApiExtensions
{
    public static IServiceCollection AddIdentityOpenApi(this IServiceCollection services)
    {
        services.AddOpenApi(options =>
        {
            options.AddDocumentTransformer((document, _, _) =>
            {
                document.Info.Title = "Davids Customer Identity OIDC API";
                document.Info.Version = "1.0.0";
                document.Info.Description =
                    "Self-hosted OAuth 2.1 / OpenID Connect customer authority (RS256 + PKCE S256) and profile endpoints.";

                document.Components ??= new OpenApiComponents();
                document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
                document.Components.SecuritySchemes["BearerAuth"] = new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT",
                    Description = "RS256 OIDC customer access token (aud: davids-services)."
                };

                if (document.Components.Schemas is not null &&
                    document.Components.Schemas.TryGetValue("SignUp", out var signUpRef) &&
                    signUpRef is OpenApiSchema signUpSchema &&
                    signUpSchema.Properties is not null)
                {
                    signUpSchema.Required = new HashSet<string>(StringComparer.Ordinal) { "email", "password" };

                    if (signUpSchema.Properties.TryGetValue("email", out var emailProp) && emailProp is OpenApiSchema emailSchema)
                    {
                        emailSchema.Type = JsonSchemaType.String;
                        emailSchema.MinLength = 6;
                        emailSchema.MaxLength = 254;
                        emailSchema.Pattern = @"^[A-Za-z0-9_%+\-]{1,20}(?:\.[A-Za-z0-9_%+\-]{1,20}){0,2}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,30}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$";
                    }

                    if (signUpSchema.Properties.TryGetValue("password", out var pwdProp) && pwdProp is OpenApiSchema pwdSchema)
                    {
                        pwdSchema.Type = JsonSchemaType.String;
                        pwdSchema.MinLength = 12;
                        pwdSchema.MaxLength = 128;
                        pwdSchema.Pattern = @"^[^\u0000]*\S[^\u0000]*$";
                    }

                    if (signUpSchema.Properties.TryGetValue("role", out var roleProp) && roleProp is OpenApiSchema roleSchema)
                    {
                        roleSchema.Type = JsonSchemaType.String | JsonSchemaType.Null;
                        roleSchema.Enum = [(JsonNode?)null!, JsonValue.Create("user")];
                    }

                    if (signUpSchema.Properties.TryGetValue("permissions", out var permsProp) && permsProp is OpenApiSchema permsSchema)
                    {
                        permsSchema.MaxItems = 0;
                    }
                }

                if (document.Paths is not null &&
                    document.Paths.TryGetValue("/connect/token", out var tokenPathItem) &&
                    tokenPathItem.Operations is not null &&
                    tokenPathItem.Operations.TryGetValue(HttpMethod.Post, out var tokenOp))
                {
                    tokenOp.Summary = "Exchange an OAuth 2.1 authorization code (+ PKCE verifier) or refresh token.";
                    tokenOp.RequestBody = new OpenApiRequestBody
                    {
                        Required = true,
                        Content = new Dictionary<string, OpenApiMediaType>
                        {
                            ["application/x-www-form-urlencoded"] = new()
                            {
                                Schema = new OpenApiSchema
                                {
                                    Type = JsonSchemaType.Object,
                                    Required = new HashSet<string>(StringComparer.Ordinal) { "grant_type", "client_id" },
                                    Properties = new Dictionary<string, IOpenApiSchema>
                                    {
                                        ["grant_type"] = new OpenApiSchema
                                        {
                                            Type = JsonSchemaType.String,
                                            Enum = [JsonValue.Create("authorization_code"), JsonValue.Create("refresh_token")]
                                        },
                                        ["client_id"] = new OpenApiSchema { Type = JsonSchemaType.String, MinLength = 1, MaxLength = 100 },
                                        ["code"] = new OpenApiSchema { Type = JsonSchemaType.String, MaxLength = 2048 },
                                        ["redirect_uri"] = new OpenApiSchema { Type = JsonSchemaType.String, Format = "uri", MaxLength = 512 },
                                        ["code_verifier"] = new OpenApiSchema { Type = JsonSchemaType.String, MinLength = 43, MaxLength = 128 },
                                        ["refresh_token"] = new OpenApiSchema { Type = JsonSchemaType.String, MaxLength = 2048 }
                                    }
                                }
                            }
                        }
                    };
                }

                foreach (var (_, pathItem) in document.Paths ?? [])
                {
                    foreach (var (_, operation) in pathItem.Operations ?? [])
                    {
                        if (operation.RequestBody is OpenApiRequestBody reqBody)
                        {
                            reqBody.Required = true;
                        }

                        foreach (var parameter in operation.Parameters ?? [])
                        {
                            if (string.Equals(parameter.Name, "limit", StringComparison.Ordinal) &&
                                parameter.Schema is OpenApiSchema limitSchema)
                            {
                                limitSchema.Type = JsonSchemaType.Integer;
                                limitSchema.Minimum = "1";
                                limitSchema.Maximum = "200";
                            }
                        }

                        if (operation.Security is { Count: > 0 })
                        {
                            operation.Security =
                            [
                                new OpenApiSecurityRequirement
                                {
                                    [new OpenApiSecuritySchemeReference("BearerAuth", document)] = []
                                }
                            ];
                        }
                    }
                }

                return Task.CompletedTask;
            });

            options.AddOperationTransformer((operation, context, _) =>
            {
                var metadata = context.Description.ActionDescriptor.EndpointMetadata;
                var requiresAuth = metadata.OfType<IAuthorizeData>().Any() && !metadata.OfType<IAllowAnonymous>().Any();

                operation.Responses ??= new OpenApiResponses();
                operation.Responses.TryAdd("429", new OpenApiResponse { Description = "Rate limit exceeded." });

                if (requiresAuth)
                {
                    operation.Security = [new OpenApiSecurityRequirement()];
                    operation.Responses.TryAdd("401", new OpenApiResponse { Description = "Missing, invalid, or revoked Bearer access token." });
                    operation.Responses.TryAdd("403", new OpenApiResponse { Description = "Authenticated caller is not authorized for this resource." });
                }

                return Task.CompletedTask;
            });
        });

        return services;
    }
}
