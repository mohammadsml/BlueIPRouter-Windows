using System.ComponentModel;
using System.Windows.Controls;
using System.Windows.Data;
using BlueIPRouter.App.ViewModels;
using BlueIPRouter.Core.Models;

namespace BlueIPRouter.App.Views;

public partial class RoutingTableView : UserControl
{
    private readonly ICollectionView _view;

    public RoutingTableView(MainViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
        _view = CollectionViewSource.GetDefaultView(vm.RoutingTable);
        _view.Filter = FilterPredicate;
    }

    private bool FilterPredicate(object obj)
    {
        if (obj is not RouteEntry r) return false;
        var q = FilterBox.Text.Trim();
        if (string.IsNullOrEmpty(q)) return true;
        return r.DestinationLabel.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               r.Gateway.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               r.InterfaceName.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private void FilterBox_TextChanged(object sender, TextChangedEventArgs e) => _view.Refresh();
}
