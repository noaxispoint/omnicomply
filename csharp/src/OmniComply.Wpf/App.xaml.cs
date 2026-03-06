using System.Windows;
using OmniComply.Core.Helpers;

namespace OmniComply.Wpf
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            if (!AdminHelper.IsRunningAsAdmin())
            {
                MessageBox.Show(
                    "OmniComply requires Administrator privileges to perform compliance checks.\n\n" +
                    "Please right-click and select 'Run as Administrator'.",
                    "Administrator Required",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                Shutdown(1);
            }
        }
    }
}
