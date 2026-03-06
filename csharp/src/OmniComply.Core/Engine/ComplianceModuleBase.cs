using System;
using System.Collections.Generic;
using OmniComply.Core.Events;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Models;

namespace OmniComply.Core.Engine
{
    public abstract class ComplianceModuleBase : IComplianceModule
    {
        private readonly List<ComplianceCheckResult> _results = new List<ComplianceCheckResult>();
        private int _checkIndex;

        public abstract string Name { get; }
        public abstract string Description { get; }
        public abstract string Category { get; }
        public abstract int Order { get; }

        public event EventHandler<CheckProgressEventArgs> CheckCompleted;

        public IReadOnlyList<ComplianceCheckResult> Execute()
        {
            _results.Clear();
            _checkIndex = 0;

            try
            {
                RunChecks();
            }
            catch (Exception ex)
            {
                _results.Add(new ComplianceCheckResult
                {
                    Category = Category,
                    Check = Name + " - Module Error",
                    Requirement = "Module execution failed",
                    Passed = false,
                    CurrentValue = "Error: " + ex.Message,
                    ExpectedValue = "Module executes without errors",
                    Remediation = "Review module implementation"
                });
            }

            return _results.AsReadOnly();
        }

        protected abstract void RunChecks();

        protected void AddCheck(
            string check,
            string requirement,
            bool passed,
            string currentValue,
            string expectedValue,
            string remediation,
            string nist = null,
            string cis = null,
            string iso27001 = null,
            string pciDss = null,
            string sox = null,
            string gdpr = null,
            string ccpa = null,
            string intuneRecommendation = null)
        {
            var result = new ComplianceCheckResult
            {
                Category = Category,
                Check = check,
                Requirement = requirement,
                Frameworks = new FrameworkMappings
                {
                    SOC2_HIPAA = requirement,
                    NIST_800_53 = nist,
                    CIS_Controls_v8 = cis,
                    ISO_27001 = iso27001,
                    PCI_DSS_v4 = pciDss,
                    SOX_ITGC = sox,
                    GDPR = gdpr,
                    CCPA = ccpa
                },
                Passed = passed,
                CurrentValue = currentValue,
                ExpectedValue = expectedValue,
                Remediation = remediation,
                IntuneRecommendation = intuneRecommendation ?? "N/A"
            };

            _results.Add(result);
            _checkIndex++;

            OnCheckCompleted(new CheckProgressEventArgs(Name, result, _checkIndex));
        }

        protected virtual void OnCheckCompleted(CheckProgressEventArgs e)
        {
            CheckCompleted?.Invoke(this, e);
        }
    }
}
