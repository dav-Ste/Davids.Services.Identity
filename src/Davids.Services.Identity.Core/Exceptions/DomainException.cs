using System;

namespace Davids.Services.Identity.Core.Exceptions
{
    public abstract class DomainException : Exception
    {
        public virtual string Code { get; } = string.Empty;

        protected DomainException(string message) : base(message)
        {
        }
    }
}