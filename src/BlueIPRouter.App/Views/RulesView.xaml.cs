using System.Windows;
using System.Windows.Controls;
using BlueIPRouter.App.ViewModels;
using BlueIPRouter.Core.Models;

namespace BlueIPRouter.App.Views;

public partial class RulesView : UserControl
{
    private readonly MainViewModel _vm;

    public RulesView(MainViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        DataContext = vm;

        RuleTargetBox.ItemsSource = _vm.Interfaces.Select(i => i.Name).ToList();
        if (_vm.Interfaces.FirstOrDefault(i => i.IsUp && !i.IsLoopback) is { } active)
            RuleTargetBox.Text = active.Name;
    }

    private void AddRule_Click(object sender, RoutedEventArgs e) => RuleNameBox.Focus();

    private void QuickAdd_Click(object sender, RoutedEventArgs e)
    {
        var name = RuleNameBox.Text.Trim();
        var dests = RuleDestBox.Text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        var target = RuleTargetBox.Text.Trim();
        var modeTag = (RuleModeBox.SelectedItem as ComboBoxItem)?.Tag?.ToString();

        var via = modeTag switch
        {
            "InterfaceDirect" => new RouteVia { Kind = RouteViaKind.InterfaceDirect, InterfaceName = target },
            "SpecificGateway" => new RouteVia { Kind = RouteViaKind.SpecificGateway, GatewayIp = target },
            _ => new RouteVia { Kind = RouteViaKind.InterfaceRouter, InterfaceName = target }
        };

        var rule = new RouteRule
        {
            Name = string.IsNullOrEmpty(name) ? "New Rule" : name,
            Destinations = dests,
            Via = via,
            Enabled = true,
            Persistent = true
        };

        var errors = rule.Validate();
        if (errors.Count > 0)
        {
            _vm.BannerMessage = string.Join("; ", errors);
            return;
        }

        _vm.BannerMessage = null;
        _vm.DraftRules.Add(rule);
        _vm.SaveDrafts();
        RuleNameBox.Clear();
        RuleDestBox.Clear();
    }

    private void RuleToggle_Click(object sender, RoutedEventArgs e) => _vm.SaveDrafts();

    private void DeleteRule_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: RouteRule rule })
        {
            _vm.DraftRules.Remove(rule);
            _vm.SaveDrafts();
        }
    }
}
