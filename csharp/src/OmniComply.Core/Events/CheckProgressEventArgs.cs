using System;
using OmniComply.Core.Models;

namespace OmniComply.Core.Events
{
    public class CheckProgressEventArgs : EventArgs
    {
        public string ModuleName { get; set; }
        public ComplianceCheckResult Check { get; set; }
        public int CheckIndex { get; set; }

        public CheckProgressEventArgs(string moduleName, ComplianceCheckResult check, int checkIndex)
        {
            ModuleName = moduleName;
            Check = check;
            CheckIndex = checkIndex;
        }
    }
}
