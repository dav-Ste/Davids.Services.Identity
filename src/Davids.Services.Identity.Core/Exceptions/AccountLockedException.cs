using System;

namespace Davids.Services.Identity.Core.Exceptions;

public class AccountLockedException(DateTime lockoutEndUtc)
    : DomainException("Account is temporarily locked due to repeated failed sign-in attempts.")
{
    public override string Code { get; } = "account_locked";
    public DateTime LockoutEndUtc { get; } = lockoutEndUtc;
}
