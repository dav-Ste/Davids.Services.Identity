using System;

namespace Davids.Services.Identity.Application.Exceptions
{
    public abstract class AppException : Exception
    {
        public virtual string Code { get; } = string.Empty;

        protected AppException(string message) : base(message)
        {
        }
    }
}