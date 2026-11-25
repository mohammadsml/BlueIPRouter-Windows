using System.Windows.Controls;
using BlueIPRouter.App.ViewModels;

namespace BlueIPRouter.App.Views;

public partial class AdaptersView : UserControl
{
    public AdaptersView(MainViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
