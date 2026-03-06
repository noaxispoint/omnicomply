using System.Security.Principal;

namespace OmniComply.Core.Helpers
{
    public static class AdminHelper
    {
        public static bool IsRunningAsAdmin()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
