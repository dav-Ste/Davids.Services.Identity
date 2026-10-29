using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Davids.Services.Identity.Core.Exceptions;
using Davids.Services.Identity.Application.Exceptions;
namespace Davids.Services.Identity.Api;
public sealed class ApiExceptionHandler(ILogger<ApiExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext context,Exception exception,CancellationToken cancellationToken)
    {
        if (exception is OperationCanceledException && context.RequestAborted.IsCancellationRequested)
        {
            if (!context.Response.HasStarted) context.Response.StatusCode = StatusCodes.Status499ClientClosedRequest;
            return true;
        }

        var (status,code,reason)=exception switch
        {
            AccountLockedException e => (429,e.Code,e.Message),
            DomainException e => (400,e.Code,e.Message),
            AppException e => (400,e.Code,e.Message),
            SecurityTokenException => (400,"invalid_access_token","Invalid or expired access token."),
            ArgumentException => (400,"invalid_request","Invalid request."),
            InvalidDataException => (400,"invalid_request","Malformed request payload."),
            BadHttpRequestException => (400,"invalid_request","Invalid request body."),
            DbUpdateException {InnerException:SqlException {Number:2601 or 2627}} => (409,"conflict","The resource already exists."),
            _ => (500,"error","An unexpected error occurred.")
        };
        if(status==500) logger.LogError(exception,"Unhandled identity error.");
        context.Response.StatusCode=status;
        await context.Response.WriteAsJsonAsync(new {code,reason},cancellationToken);
        return true;
    }
}
