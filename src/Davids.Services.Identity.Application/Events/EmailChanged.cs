using System;

namespace Davids.Services.Identity.Application.Events;

[Contract]
public sealed record EmailChanged(Guid UserId, string OldEmail, string NewEmail);
