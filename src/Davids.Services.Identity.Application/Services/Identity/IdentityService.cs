using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Davids.Services.Identity.Application.Commands;
using Davids.Services.Identity.Application.DTO;
using Davids.Services.Identity.Application.Events;
using Davids.Services.Identity.Core.Entities;
using Davids.Services.Identity.Core.Exceptions;
using Davids.Services.Identity.Core.Repositories;
using Microsoft.Extensions.Logging;

namespace Davids.Services.Identity.Application.Services.Identity;

public sealed class IdentityLockoutSettings
{
    public int MaxFailedAccessAttempts { get; set; } = 5;
    public int DurationMinutes { get; set; } = 15;
}

public class IdentityService(
    IUserRepository userRepository,
    IPasswordService passwordService,
    IMessageBroker messageBroker,
    ILogger<IdentityService> logger,
    IdentityLockoutSettings? lockoutSettings = null,
    ILoginAuditRepository? loginAuditRepository = null) : IIdentityService
{
    private readonly IdentityLockoutSettings _lockout = lockoutSettings ?? new IdentityLockoutSettings();

    private static readonly Regex EmailRegex = new(
        @"^[A-Za-z0-9_%+\-]{1,20}(?:\.[A-Za-z0-9_%+\-]{1,20}){0,2}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,30}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    private static bool IsValidEmailAddress([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate) || candidate.Length < 6 || candidate.Length > 254 || candidate.Contains('\0'))
        {
            return false;
        }

        var atIndex = candidate.IndexOf('@');
        if (atIndex < 1 || atIndex > 64)
        {
            return false;
        }

        try
        {
            return EmailRegex.IsMatch(candidate);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    public async Task<UserDto?> GetAsync(Guid id)
    {
        var user = await userRepository.GetAsync(id);
        return user is null ? null : new UserDto(user);
    }

    public async Task<UserDto> AuthenticateAsync(string email, string password, LoginRequestMetadata? metadata = null)
    {
        var now = DateTime.UtcNow;
        var normalized = email?.Trim();
        if (!IsValidEmailAddress(normalized))
        {
            await WriteAuditAsync(now, null, email, false, "invalid_credentials", "Invalid customer email format.", metadata);
            logger.LogWarning(
                "Audit: invalid email format during OIDC customer authentication from {ClientIp}.",
                metadata?.ClientIpAddress ?? "unknown");
            throw new InvalidEmailException(email);
        }

        var user = await userRepository.GetAsync(normalized);
        if (user is null || string.IsNullOrEmpty(password))
        {
            await WriteAuditAsync(
                now,
                user is null ? null : user.Id.Value,
                normalized,
                false,
                "invalid_credentials",
                user is null ? "Unknown customer email." : "Missing customer password.",
                metadata);
            logger.LogWarning(
                "Audit: rejected customer OIDC sign-in for unknown email or empty password from {ClientIp}.",
                metadata?.ClientIpAddress ?? "unknown");
            throw new InvalidCredentialsException(normalized);
        }

        if (user.IsLockedOut(now))
        {
            await WriteAuditAsync(now, user.Id, normalized, false, "account_locked", "Customer account is currently locked out.", metadata);
            logger.LogWarning(
                "Audit: rejected OIDC sign-in for locked customer {UserId} until {LockoutEndUtc} from {ClientIp}.",
                user.Id,
                user.LockoutEndUtc,
                metadata?.ClientIpAddress ?? "unknown");
            throw new AccountLockedException(user.LockoutEndUtc!.Value);
        }

        if (!passwordService.IsValid(user.Password, password))
        {
            var maxAttempts = Math.Max(1, _lockout.MaxFailedAccessAttempts);
            var lockoutDuration = TimeSpan.FromMinutes(Math.Max(1, _lockout.DurationMinutes));
            var lockedNow = user.RecordFailedLogin(now, maxAttempts, lockoutDuration);
            await userRepository.UpdateAsync(user);

            if (lockedNow)
            {
                await WriteAuditAsync(
                    now,
                    user.Id,
                    normalized,
                    false,
                    "account_locked",
                    $"Customer account locked after {maxAttempts} failed attempts.",
                    metadata);
                logger.LogWarning(
                    "Audit: locked customer {UserId} until {LockoutEndUtc} after {MaxAttempts} failed sign-in attempts from {ClientIp}.",
                    user.Id,
                    user.LockoutEndUtc,
                    maxAttempts,
                    metadata?.ClientIpAddress ?? "unknown");
                throw new AccountLockedException(user.LockoutEndUtc!.Value);
            }

            await WriteAuditAsync(now, user.Id, normalized, false, "invalid_credentials", "Invalid customer password.", metadata);
            logger.LogWarning(
                "Audit: invalid customer OIDC credentials for {UserId} from {ClientIp}.",
                user.Id,
                metadata?.ClientIpAddress ?? "unknown");
            throw new InvalidCredentialsException(normalized);
        }

        if (!string.Equals(user.Role, Role.User, StringComparison.Ordinal))
        {
            await WriteAuditAsync(now, user.Id, normalized, false, "invalid_role", $"Account role '{user.Role}' is not permitted on customer authority.", metadata);
            throw new InvalidRoleException(user.Role);
        }

        if (user.FailedLoginCount > 0 || user.LockoutEndUtc is not null)
        {
            user.ResetFailedLogins();
            await userRepository.UpdateAsync(user);
        }

        await WriteAuditAsync(now, user.Id, normalized, true, "succeeded", null, metadata);
        logger.LogInformation(
            "Audit: authenticated customer {UserId} via OIDC from {ClientIp} (ClientId={ClientId}).",
            user.Id,
            metadata?.ClientIpAddress ?? "unknown",
            metadata?.ClientId ?? "unknown");
        await messageBroker.PublishAsync(new SignedIn(user.Id, user.Role));
        return new UserDto(user);
    }

    public Task RecordProtocolFailureAuditAsync(
        string? email,
        Guid? userId,
        string outcome,
        string? failureReason,
        LoginRequestMetadata? metadata = null)
        => WriteAuditAsync(DateTime.UtcNow, userId, email, false, outcome, failureReason, metadata);

    public async Task<IReadOnlyList<LoginAuditDto>> GetLoginAuditsAsync(Guid userId, int limit = 50)
    {
        if (loginAuditRepository is null)
        {
            return [];
        }

        var entries = await loginAuditRepository.BrowseForUserAsync(userId, limit);
        return entries.Select(LoginAuditDto.FromEntity).ToArray();
    }

    private async Task WriteAuditAsync(
        DateTime occurredAtUtc,
        Guid? userId,
        string? email,
        bool succeeded,
        string outcome,
        string? failureReason,
        LoginRequestMetadata? metadata)
    {
        if (loginAuditRepository is null)
        {
            return;
        }

        var entry = new LoginAuditEntry(
            Guid.NewGuid(),
            occurredAtUtc,
            userId,
            email,
            succeeded,
            outcome,
            failureReason,
            metadata?.ClientId,
            metadata?.ClientIpAddress,
            metadata?.UserAgent,
            metadata?.CorrelationId);
        await loginAuditRepository.AddAsync(entry);
    }

    public async Task SignUpAsync(SignUp command)
    {
        var normalizedEmail = command.Email;
        if (!IsValidEmailAddress(normalizedEmail))
        {
            logger.LogWarning("Invalid email format.");
            throw new InvalidEmailException(command.Email);
        }

        var passwordRuneCount = command.Password?.EnumerateRunes().Count() ?? 0;
        if (string.IsNullOrWhiteSpace(command.Password) ||
            passwordRuneCount < 12 ||
            passwordRuneCount > 128 ||
            command.Password.Contains('\0'))
        {
            throw new InvalidPasswordException();
        }

        if ((!string.IsNullOrWhiteSpace(command.Role) && command.Role != Role.User) || command.Permissions?.Any() == true)
        {
            throw new InvalidRoleException(command.Role);
        }

        var existing = await userRepository.GetAsync(normalizedEmail);
        if (existing is not null || await userRepository.GetAsync(command.UserId) is not null)
        {
            logger.LogWarning("Email or user identifier already registered.");
            throw new EmailInUseException(normalizedEmail);
        }

        var passwordHash = passwordService.Hash(command.Password);
        var user = new User(command.UserId, normalizedEmail, passwordHash, Role.User, DateTime.UtcNow, command.Permissions);
        await userRepository.AddAsync(user);

        logger.LogInformation("Created customer account for user {UserId}.", user.Id);
        await messageBroker.PublishAsync(new SignedUp(user.Id, user.Email, user.Role));
    }
}
