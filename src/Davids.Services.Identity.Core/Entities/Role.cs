namespace Davids.Services.Identity.Core.Entities
{
    public static class Role
    {
        public const string User = "user";

        public static bool IsValid(string? role)
        {
            if (string.IsNullOrWhiteSpace(role))
            {
                return false;
            }

            return string.Equals(role.Trim(), User, System.StringComparison.OrdinalIgnoreCase);
        }
    }
}
