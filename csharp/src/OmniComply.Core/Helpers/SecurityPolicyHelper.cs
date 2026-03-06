using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace OmniComply.Core.Helpers
{
    public static class SecurityPolicyHelper
    {
        private static readonly object _lock = new object();

        public static Dictionary<string, string> ExportSecurityPolicy()
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string tempFile = Path.Combine(Path.GetTempPath(), "omnicomply_secpol_" + Guid.NewGuid().ToString("N") + ".cfg");

            try
            {
                lock (_lock)
                {
                    var result = ProcessHelper.RunSecedit(string.Format("/export /cfg \"{0}\" /quiet", tempFile));

                    if (File.Exists(tempFile))
                    {
                        var lines = File.ReadAllLines(tempFile);
                        foreach (var line in lines)
                        {
                            var match = Regex.Match(line.Trim(), @"^(\w+)\s*=\s*(.+)$");
                            if (match.Success)
                            {
                                values[match.Groups[1].Value] = match.Groups[2].Value.Trim();
                            }
                        }
                    }
                }
            }
            finally
            {
                try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
            }

            return values;
        }

        public static int GetMinimumPasswordLength()
        {
            var policy = ExportSecurityPolicy();
            string value;
            if (policy.TryGetValue("MinimumPasswordLength", out value))
            {
                int result;
                if (int.TryParse(value, out result))
                    return result;
            }
            return 0;
        }

        public static bool GetPasswordComplexityEnabled()
        {
            var policy = ExportSecurityPolicy();
            string value;
            if (policy.TryGetValue("PasswordComplexity", out value))
            {
                return value == "1";
            }
            return false;
        }

        public static int GetPasswordHistorySize()
        {
            var policy = ExportSecurityPolicy();
            string value;
            if (policy.TryGetValue("PasswordHistorySize", out value))
            {
                int result;
                if (int.TryParse(value, out result))
                    return result;
            }
            return 0;
        }

        public static int GetLockoutBadCount()
        {
            var policy = ExportSecurityPolicy();
            string value;
            if (policy.TryGetValue("LockoutBadCount", out value))
            {
                int result;
                if (int.TryParse(value, out result))
                    return result;
            }
            return 0;
        }

        public static int GetMaximumPasswordAge()
        {
            var policy = ExportSecurityPolicy();
            string value;
            if (policy.TryGetValue("MaximumPasswordAge", out value))
            {
                int result;
                if (int.TryParse(value, out result))
                    return result;
            }
            return -1;
        }

        public static int GetLockoutDuration()
        {
            var policy = ExportSecurityPolicy();
            string value;
            if (policy.TryGetValue("LockoutDuration", out value))
            {
                int result;
                if (int.TryParse(value, out result))
                    return result;
            }
            return 0;
        }
    }
}
