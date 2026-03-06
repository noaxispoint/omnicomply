using System;
using Microsoft.Win32;

namespace OmniComply.Core.Helpers
{
    public static class RegistryHelper
    {
        public static object GetValue(string fullPath, string valueName)
        {
            try
            {
                using (var key = OpenKey(fullPath))
                {
                    return key?.GetValue(valueName);
                }
            }
            catch
            {
                return null;
            }
        }

        public static T GetValue<T>(string fullPath, string valueName, T defaultValue = default(T))
        {
            try
            {
                var value = GetValue(fullPath, valueName);
                if (value == null) return defaultValue;
                return (T)Convert.ChangeType(value, typeof(T));
            }
            catch
            {
                return defaultValue;
            }
        }

        public static int GetDword(string fullPath, string valueName, int defaultValue = -1)
        {
            return GetValue(fullPath, valueName, defaultValue);
        }

        public static string GetString(string fullPath, string valueName, string defaultValue = null)
        {
            return GetValue(fullPath, valueName, defaultValue);
        }

        public static bool SetDword(string fullPath, string valueName, int value)
        {
            try
            {
                using (var key = OpenOrCreateKey(fullPath))
                {
                    if (key == null) return false;
                    key.SetValue(valueName, value, RegistryValueKind.DWord);
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool SetString(string fullPath, string valueName, string value)
        {
            try
            {
                using (var key = OpenOrCreateKey(fullPath))
                {
                    if (key == null) return false;
                    key.SetValue(valueName, value, RegistryValueKind.String);
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool KeyExists(string fullPath)
        {
            try
            {
                using (var key = OpenKey(fullPath))
                {
                    return key != null;
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool ValueExists(string fullPath, string valueName)
        {
            return GetValue(fullPath, valueName) != null;
        }

        private static RegistryKey OpenKey(string fullPath)
        {
            string subPath;
            var hive = ParseHive(fullPath, out subPath);
            return hive?.OpenSubKey(subPath);
        }

        private static RegistryKey OpenOrCreateKey(string fullPath)
        {
            string subPath;
            var hive = ParseHive(fullPath, out subPath);
            return hive?.CreateSubKey(subPath);
        }

        private static RegistryKey ParseHive(string fullPath, out string subPath)
        {
            fullPath = fullPath.Replace("/", "\\");

            if (fullPath.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase) ||
                fullPath.StartsWith(@"HKEY_LOCAL_MACHINE\", StringComparison.OrdinalIgnoreCase))
            {
                subPath = fullPath.Substring(fullPath.IndexOf('\\') + 1);
                return Registry.LocalMachine;
            }
            if (fullPath.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase) ||
                fullPath.StartsWith(@"HKEY_CURRENT_USER\", StringComparison.OrdinalIgnoreCase))
            {
                subPath = fullPath.Substring(fullPath.IndexOf('\\') + 1);
                return Registry.CurrentUser;
            }
            if (fullPath.StartsWith(@"HKCR\", StringComparison.OrdinalIgnoreCase) ||
                fullPath.StartsWith(@"HKEY_CLASSES_ROOT\", StringComparison.OrdinalIgnoreCase))
            {
                subPath = fullPath.Substring(fullPath.IndexOf('\\') + 1);
                return Registry.ClassesRoot;
            }

            subPath = fullPath;
            return null;
        }
    }
}
