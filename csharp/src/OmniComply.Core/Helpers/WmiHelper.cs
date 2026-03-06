using System;
using System.Collections.Generic;
using System.Management;

namespace OmniComply.Core.Helpers
{
    public static class WmiHelper
    {
        public static ManagementObject QueryFirst(string wmiClass, string wmiNamespace = @"root\cimv2")
        {
            try
            {
                var scope = new ManagementScope(wmiNamespace);
                var query = new ObjectQuery("SELECT * FROM " + wmiClass);
                using (var searcher = new ManagementObjectSearcher(scope, query))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj;
                    }
                }
            }
            catch
            {
            }
            return null;
        }

        public static List<ManagementObject> QueryAll(string wmiClass, string wmiNamespace = @"root\cimv2")
        {
            var results = new List<ManagementObject>();
            try
            {
                var scope = new ManagementScope(wmiNamespace);
                var query = new ObjectQuery("SELECT * FROM " + wmiClass);
                using (var searcher = new ManagementObjectSearcher(scope, query))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        results.Add(obj);
                    }
                }
            }
            catch
            {
            }
            return results;
        }

        public static ManagementObject QueryFirstWhere(string wmiClass, string condition, string wmiNamespace = @"root\cimv2")
        {
            try
            {
                var scope = new ManagementScope(wmiNamespace);
                var query = new ObjectQuery(string.Format("SELECT * FROM {0} WHERE {1}", wmiClass, condition));
                using (var searcher = new ManagementObjectSearcher(scope, query))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj;
                    }
                }
            }
            catch
            {
            }
            return null;
        }

        public static string GetPropertyString(ManagementObject obj, string propertyName)
        {
            try
            {
                var value = obj[propertyName];
                return value?.ToString();
            }
            catch
            {
                return null;
            }
        }

        public static T GetProperty<T>(ManagementObject obj, string propertyName, T defaultValue = default(T))
        {
            try
            {
                var value = obj[propertyName];
                if (value == null) return defaultValue;
                return (T)Convert.ChangeType(value, typeof(T));
            }
            catch
            {
                return defaultValue;
            }
        }

        public static string GetOsCaption()
        {
            var os = QueryFirst("Win32_OperatingSystem");
            return os != null ? GetPropertyString(os, "Caption") : "Unknown";
        }

        public static string GetOsBuildNumber()
        {
            var os = QueryFirst("Win32_OperatingSystem");
            return os != null ? GetPropertyString(os, "BuildNumber") : "Unknown";
        }

        public static int GetProcessorArchitecture()
        {
            var proc = QueryFirst("Win32_Processor");
            return proc != null ? GetProperty(proc, "Architecture", -1) : -1;
        }
    }
}
