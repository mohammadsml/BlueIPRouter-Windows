using System.Windows;
using System.Windows.Controls;
using BlueIPRouter.App.ViewModels;
using BlueIPRouter.Core.Models;

namespace BlueIPRouter.App.Views;

public partial class KillSwitchView : UserControl
{
    private readonly MainViewModel _vm;
    private bool _init;

    public KillSwitchView(MainViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        DataContext = vm;

        _init = true;
        ModeBox.SelectedIndex = vm.DraftKillSwitch.Mode == KillSwitchMode.FullSystem ? 1 : 0;
        InterfacesBox.Text = string.Join(", ", vm.DraftKillSwitch.Interfaces);
        _init = false;
    }

    private void Changed_Click(object sender, RoutedEventArgs e)
    {
        if (!_init) _vm.SaveDrafts();
    }

    private void ModeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_init) return;
        var tag = (ModeBox.SelectedItem as ComboBoxItem)?.Tag?.ToString();
        _vm.DraftKillSwitch.Mode = tag == "FullSystem" ? KillSwitchMode.FullSystem : KillSwitchMode.Destinations;
        _vm.SaveDrafts();
    }

    private void InterfacesBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_init) return;
        _vm.DraftKillSwitch.Interfaces = InterfacesBox.Text
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
        _vm.SaveDrafts();
    }
}
