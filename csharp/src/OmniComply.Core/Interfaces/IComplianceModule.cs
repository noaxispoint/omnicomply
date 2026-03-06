using System;
using System.Collections.Generic;
using OmniComply.Core.Events;
using OmniComply.Core.Models;

namespace OmniComply.Core.Interfaces
{
    public interface IComplianceModule
    {
        string Name { get; }
        string Description { get; }
        string Category { get; }
        int Order { get; }
        IReadOnlyList<ComplianceCheckResult> Execute();
        event EventHandler<CheckProgressEventArgs> CheckCompleted;
    }
}
