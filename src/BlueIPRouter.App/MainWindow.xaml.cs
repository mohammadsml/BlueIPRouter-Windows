using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using BlueIPRouter.App.ViewModels;
using BlueIPRouter.App.Views;
using Forms = System.Windows.Forms;

namespace BlueIPRouter.App;

public partial class MainWindow
{
    public MainViewModel ViewModel { get; } = new();
    private Forms.NotifyIcon? _trayIcon;
    private bool _allowClose;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = ViewModel;
        InitTrayIcon();
        NavigateTo("Dashboard");
        Loaded += async (_, _) => await ViewModel.RefreshAsync();
    }

    private void InitTrayIcon()
    {
        _trayIcon = new Forms.NotifyIcon
        {
            Text = "BlueIPRouter",
            Icon = System.Drawing.SystemIcons.Shield,
            Visible = true
        };
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open BlueIPRouter", null, (_, _) => RestoreWindow());
        menu.Items.Add("Refresh", null, async (_, _) => await ViewModel.RefreshAsync());
        menu.Items.Add("Apply Changes", null, async (_, _) => await ViewModel.ApplyAsync());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) =>
        {
            _allowClose = true;
            _trayIcon.Visible = false;
            System.Windows.Application.Current.Shutdown();
        });
        _trayIcon.ContextMenuStrip = menu;
        _trayIcon.DoubleClick += (_, _) => RestoreWindow();
    }

    private void RestoreWindow()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_allowClose)
        {
            e.Cancel = true;
            Hide();
            return;
        }
        _trayIcon?.Dispose();
        base.OnClosing(e);
    }

    private void NavButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string page })
        {
            NavigateTo(page);
        }
    }

    private void NavigateTo(string page)
    {
        ViewModel.SelectedPage = page;
        PageHost.Content = page switch
        {
            "Dashboard" => new DashboardView(ViewModel),
            "Rules" => new RulesView(ViewModel),
            "KillSwitch" => new KillSwitchView(ViewModel),
            "RoutingTable" => new RoutingTableView(ViewModel),
            "Adapters" => new AdaptersView(ViewModel),
            "Service" => new ServiceView(ViewModel),
            _ => new PlaceholderView(page)
        };
    }
}
