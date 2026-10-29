using System;
using System.Collections.Generic;

namespace Davids.Services.Identity.Application.Commands
{
    [Contract]
    public class SignUp
    {
        public Guid UserId { get; }
        public string Email { get; }
        public string Password { get; }
        public string? Role { get; }
        public IEnumerable<string>? Permissions { get; }

        public SignUp(Guid userId, string email, string password, string? role = null, IEnumerable<string>? permissions = null)
        {
            UserId = userId == Guid.Empty ? Guid.NewGuid() : userId;
            Email = email;
            Password = password;
            Role = role;
            Permissions = permissions;
        }
    }
}