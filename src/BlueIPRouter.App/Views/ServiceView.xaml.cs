using System.Windows;
using System.Windows.Controls;
using BlueIPRouter.App.Services;
using BlueIPRouter.App.ViewModels;
using BlueIPRouter.Core.Models;

namespace BlueIPRouter.App.Views;

public partial class ServiceView : UserControl
{
    private readonly MainViewModel _vm;

    public ServiceView(MainViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        DataContext = vm;
    }

    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        bool ok = ServiceClient.InstallAndStartService();
        _vm.BannerMessage = ok
            ? "BlueIPRouter Windows Service installed and started."
            : "Could not install service (ensure BlueIPRouter.Service.exe is bundled and UAC was approved).";
        await _vm.RefreshAsync();
    }

    private async void RemoveAll_Click(object sender, RoutedEventArgs e)
    {
        var resp = await ServiceClient.SendAsync(new IpcRequest { Command = IpcCommandType.RemoveAll });
        _vm.BannerMessage = resp.Ok ? "Removed all managed routes and cleared WFP filters." : resp.Error;
        await _vm.RefreshAsync();
    }

    private async void Uninstall_Click(object sender, RoutedEventArgs e)
    {
        await ServiceClient.SendAsync(new IpcRequest { Command = IpcCommandType.RemoveAll });
        bool ok = ServiceClient.UninstallService();
        _vm.BannerMessage = ok ? "Service uninstalled." : "Failed to uninstall service.";
        await _vm.RefreshAsync();
    }
}
