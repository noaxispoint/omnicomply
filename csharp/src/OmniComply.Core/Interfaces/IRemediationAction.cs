using OmniComply.Core.Models;

namespace OmniComply.Core.Interfaces
{
    public interface IRemediationAction
    {
        string Name { get; }
        string Description { get; }
        string Category { get; }
        bool RequiresReboot { get; }
        RemediationResult Execute();
        RemediationResult DryRun();
    }
}
