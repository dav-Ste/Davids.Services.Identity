namespace Davids.Services.Identity.Application.Commands;

public sealed record ChangeCustomerPassword(
    string CurrentPassword,
    string NewPassword);

public sealed record ChangeCustomerEmail(
    string CurrentPassword,
    string NewEmail);

public sealed record EmployeeUpdateCustomerEmail(
    string NewEmail);
