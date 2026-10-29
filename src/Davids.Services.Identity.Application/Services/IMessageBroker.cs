using System.Threading.Tasks;

namespace Davids.Services.Identity.Application.Services
{
    public interface IMessageBroker
    {
        Task PublishAsync(params object[] events);
    }
}