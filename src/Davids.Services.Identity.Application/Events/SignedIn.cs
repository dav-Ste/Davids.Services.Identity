using System;

namespace Davids.Services.Identity.Application.Events
{
    [Contract]
    public class SignedIn
    {
        public Guid UserId { get; }
        public string Role { get; }

        public SignedIn(Guid userId, string role)
        {
            UserId = userId;
            Role = role;
        }
    }
}