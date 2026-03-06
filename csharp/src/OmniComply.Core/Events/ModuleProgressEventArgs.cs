using System;

namespace OmniComply.Core.Events
{
    public class ModuleProgressEventArgs : EventArgs
    {
        public string ModuleName { get; set; }
        public int ModuleIndex { get; set; }
        public int TotalModules { get; set; }
        public int ChecksInModule { get; set; }

        public ModuleProgressEventArgs(string moduleName, int moduleIndex, int totalModules)
        {
            ModuleName = moduleName;
            ModuleIndex = moduleIndex;
            TotalModules = totalModules;
        }
    }
}
