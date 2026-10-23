using System.Windows;
using System.Windows.Controls;

namespace DiskSpace
{
    // The Protect page. In this stage it shows "What Protect reads", generated from the same constants the
    // scanner uses. Findings arrive in later stages. This file is under tools\check-trust.ps1.
    sealed partial class MainWindow
    {
        StackPanel protectInfo;

        void WireProtect()
        {
            protectInfo = E<StackPanel>("ProtectInfo");
            RenderProtectInfo();
        }

        void RenderProtectInfo()
        {
            protectInfo.Children.Clear();
            foreach (InfoSection s in ProtectInfo.Describe())
            {
                var body = new StackPanel();
                body.Children.Add(new TextBlock { Text = s.Title, Style = (Style)Res("BodyStrong"), FontSize = 15 });
                foreach (string line in s.Lines)
                    body.Children.Add(new TextBlock
                    {
                        Text = line,
                        Style = (Style)Res("BodySecondary"),
                        FontSize = 13,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 8, 0, 0)
                    });
                protectInfo.Children.Add(new Border
                {
                    Style = (Style)Res("Card"),
                    Margin = new Thickness(0, 0, 0, 12),
                    Padding = new Thickness(20, 16, 20, 18),
                    Child = body
                });
            }
        }
    }
}
