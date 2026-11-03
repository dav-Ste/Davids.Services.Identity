using System;
using System.Collections.Generic;
using System.Linq;
using Davids.Services.Identity.Core.Exceptions;

namespace Davids.Services.Identity.Core.Entities
{
    public class User : AggregateRoot
    {
        public string Email { get; private set; }
        public string Role { get; private set; }
        public string Password { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public IEnumerable<string> Permissions { get; private set; }
        public int FailedLoginCount { get; private set; }
        public DateTime? LockoutEndUtc { get; private set; }

        public User(Guid id, string email, string password, string role, DateTime createdAt,
            IEnumerable<string>? permissions = null, int failedLoginCount = 0, DateTime? lockoutEndUtc = null)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                throw new InvalidEmailException(email);
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new InvalidPasswordException();
            }

            if (!Entities.Role.IsValid(role))
            {
                throw new InvalidRoleException(role);
            }

            Id = id;
            Email = email.ToLowerInvariant();
            Password = password;
            Role = role.ToLowerInvariant();
            CreatedAt = createdAt;
            Permissions = permissions ?? Enumerable.Empty<string>();
            FailedLoginCount = Math.Max(0, failedLoginCount);
            LockoutEndUtc = lockoutEndUtc;
        }

        public bool IsLockedOut(DateTime utcNow)
            => LockoutEndUtc.HasValue && LockoutEndUtc.Value > utcNow;

        public bool RecordFailedLogin(DateTime utcNow, int maxFailedAccessAttempts, TimeSpan lockoutDuration)
        {
            if (LockoutEndUtc.HasValue && LockoutEndUtc.Value <= utcNow)
            {
                LockoutEndUtc = null;
                FailedLoginCount = 0;
            }

            FailedLoginCount++;
            var threshold = Math.Max(1, maxFailedAccessAttempts);
            if (FailedLoginCount >= threshold)
            {
                LockoutEndUtc = utcNow.Add(lockoutDuration <= TimeSpan.Zero ? TimeSpan.FromMinutes(15) : lockoutDuration);
                FailedLoginCount = 0;
                return true;
            }

            return false;
        }

        public void ResetFailedLogins()
        {
            FailedLoginCount = 0;
            LockoutEndUtc = null;
        }

        public void ChangePasswordHash(string newPasswordHash)
        {
            if (string.IsNullOrWhiteSpace(newPasswordHash))
            {
                throw new InvalidPasswordException();
            }

            Password = newPasswordHash;
            ResetFailedLogins();
        }

        public void ChangeEmail(string newEmail)
        {
            if (string.IsNullOrWhiteSpace(newEmail))
            {
                throw new InvalidEmailException(newEmail);
            }

            Email = newEmail.Trim().ToLowerInvariant();
        }
    }
}
