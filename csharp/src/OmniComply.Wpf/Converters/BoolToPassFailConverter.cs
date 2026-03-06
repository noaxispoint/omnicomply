using System;
using System.Globalization;
using System.Windows.Data;

namespace OmniComply.Wpf.Converters
{
    public class BoolToPassFailConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b) return b ? "PASS" : "FAIL";
            return "N/A";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
