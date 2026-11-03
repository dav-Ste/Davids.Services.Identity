namespace Davids.Services.Identity.Core.Exceptions;

public sealed class InvalidCurrentPasswordException()
    : DomainException("The current password is incorrect.")
{
    public override string Code => "invalid_current_password";
}
