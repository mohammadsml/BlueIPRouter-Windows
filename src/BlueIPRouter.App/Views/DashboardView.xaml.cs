using System.Windows.Controls;
using BlueIPRouter.App.ViewModels;

namespace BlueIPRouter.App.Views;

public partial class DashboardView : UserControl
{
    public DashboardView(MainViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
