using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace OmniComply.Wpf.Converters
{
    public class BoolToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool b)
                return b ? new SolidColorBrush(Color.FromRgb(0x10, 0x7C, 0x10)) : new SolidColorBrush(Color.FromRgb(0xD1, 0x34, 0x38));
            return new SolidColorBrush(Colors.Gray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
