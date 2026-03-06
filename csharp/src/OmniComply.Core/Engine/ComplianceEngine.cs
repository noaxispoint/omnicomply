using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.ComponentModel.Composition.Hosting;
using System.IO;
using System.Linq;
using System.Reflection;
using OmniComply.Core.Events;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;
using OmniComply.Core.Models;

namespace OmniComply.Core.Engine
{
    public class ComplianceEngine : IDisposable
    {
        private CompositionContainer _container;
        private AggregateCatalog _catalog;

        [ImportMany(typeof(IComplianceModule))]
        public IEnumerable<Lazy<IComplianceModule, IModuleMetadata>> Modules { get; set; }

        [ImportMany(typeof(IRemediationAction))]
        public IEnumerable<Lazy<IRemediationAction>> RemediationActions { get; set; }

        [ImportMany(typeof(IReportGenerator))]
        public IEnumerable<Lazy<IReportGenerator>> ReportGenerators { get; set; }

        public event EventHandler<ModuleProgressEventArgs> ModuleStarted;
        public event EventHandler<ModuleProgressEventArgs> ModuleCompleted;
        public event EventHandler<CheckProgressEventArgs> CheckCompleted;

        public ComplianceEngine()
        {
            Compose();
        }

        public ComplianceEngine(string modulesDirectory)
        {
            Compose(modulesDirectory);
        }

        private void Compose(string modulesDirectory = null)
        {
            _catalog = new AggregateCatalog();

            // Always scan the executing assembly's directory
            var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            _catalog.Catalogs.Add(new DirectoryCatalog(baseDir, "OmniComply.*.dll"));

            // Scan additional modules directory if specified
            if (!string.IsNullOrEmpty(modulesDirectory) && Directory.Exists(modulesDirectory))
            {
                _catalog.Catalogs.Add(new DirectoryCatalog(modulesDirectory, "OmniComply.*.dll"));
            }

            // Also check for a "modules" subdirectory
            var modulesSubDir = Path.Combine(baseDir, "modules");
            if (Directory.Exists(modulesSubDir))
            {
                _catalog.Catalogs.Add(new DirectoryCatalog(modulesSubDir, "OmniComply.*.dll"));
            }

            _container = new CompositionContainer(_catalog);
            _container.ComposeParts(this);
        }

        public ComplianceScanResult RunAllChecks()
        {
            var scanResult = CreateScanResult();
            var orderedModules = Modules.OrderBy(m => m.Metadata.Order).ToList();
            int moduleIndex = 0;

            foreach (var module in orderedModules)
            {
                moduleIndex++;
                var moduleName = module.Metadata.Name;

                OnModuleStarted(new ModuleProgressEventArgs(moduleName, moduleIndex, orderedModules.Count));

                module.Value.CheckCompleted += (s, e) => OnCheckCompleted(e);

                var results = module.Value.Execute();

                foreach (var check in results)
                {
                    scanResult.Checks.Add(check);
                    if (!check.Passed) scanResult.Compliant = false;
                }

                var completedArgs = new ModuleProgressEventArgs(moduleName, moduleIndex, orderedModules.Count);
                completedArgs.ChecksInModule = results.Count;
                OnModuleCompleted(completedArgs);
            }

            return scanResult;
        }

        public ComplianceScanResult RunModule(string moduleName)
        {
            var scanResult = CreateScanResult();
            var module = Modules.FirstOrDefault(m =>
                string.Equals(m.Metadata.Name, moduleName, StringComparison.OrdinalIgnoreCase));

            if (module == null)
                throw new ArgumentException("Module not found: " + moduleName);

            module.Value.CheckCompleted += (s, e) => OnCheckCompleted(e);
            var results = module.Value.Execute();

            foreach (var check in results)
            {
                scanResult.Checks.Add(check);
                if (!check.Passed) scanResult.Compliant = false;
            }

            return scanResult;
        }

        public void GenerateReports(ComplianceScanResult results, string outputDirectory)
        {
            if (!Directory.Exists(outputDirectory))
                Directory.CreateDirectory(outputDirectory);

            var timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");

            foreach (var generator in ReportGenerators)
            {
                var fileName = string.Format("OmniComply-Report-{0}.{1}", timestamp, generator.Value.FileExtension);
                var filePath = Path.Combine(outputDirectory, fileName);
                generator.Value.Generate(results, filePath);
            }
        }

        public IEnumerable<IRemediationAction> GetRemediationsForCategory(string category)
        {
            return RemediationActions
                .Where(r => string.Equals(r.Value.Category, category, StringComparison.OrdinalIgnoreCase))
                .Select(r => r.Value);
        }

        public IEnumerable<string> GetAvailableModuleNames()
        {
            return Modules.OrderBy(m => m.Metadata.Order).Select(m => m.Metadata.Name);
        }

        private ComplianceScanResult CreateScanResult()
        {
            return new ComplianceScanResult
            {
                Timestamp = DateTime.Now,
                ComputerName = Environment.MachineName,
                WindowsVersion = WmiHelper.GetOsCaption(),
                WindowsBuild = WmiHelper.GetOsBuildNumber()
            };
        }

        protected virtual void OnModuleStarted(ModuleProgressEventArgs e)
        {
            ModuleStarted?.Invoke(this, e);
        }

        protected virtual void OnModuleCompleted(ModuleProgressEventArgs e)
        {
            ModuleCompleted?.Invoke(this, e);
        }

        protected virtual void OnCheckCompleted(CheckProgressEventArgs e)
        {
            CheckCompleted?.Invoke(this, e);
        }

        public void Dispose()
        {
            _container?.Dispose();
            _catalog?.Dispose();
        }
    }
}
