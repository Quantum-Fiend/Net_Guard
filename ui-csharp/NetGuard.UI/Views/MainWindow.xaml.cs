using System.Windows;
using NetGuard.UI.ViewModels;

namespace NetGuard.UI.Views
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            DataContext = new MainViewModel();
        }
    }
}
