using System.Collections.ObjectModel;
using System.Windows.Media;
using BlueIPRouter.App.Services;
using BlueIPRouter.Core.Models;
using BlueIPRouter.Core.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BlueIPRouter.App.ViewModels;

public partial class MainViewModel : ObservableObject
{
    [ObservableProperty] private string _selectedPage = "Dashboard";
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _busyText = string.Empty;
    [ObservableProperty] private string? _bannerMessage;
    [ObservableProperty] private bool _isBannerError;

    // Network snapshot
    [ObservableProperty] private string _publicIp = "Checking...";
    [ObservableProperty] private string _publicLocation = "—";
    [ObservableProperty] private string _publicIsp = "—";
    [ObservableProperty] private string _internetVia = "Detecting...";
    [ObservableProperty] private string _primaryGateway = "—";
    [ObservableProperty] private string _updatedTime = "Never";

    // Service status
    [ObservableProperty] private bool _serviceInstalled;
    [ObservableProperty] private bool _serviceRunning;
    [ObservableProperty] private string _serviceStatusText = "Service not installed";
    [ObservableProperty] private Brush _serviceStatusBrush = Brushes.Gray;
    [ObservableProperty] private bool _killSwitchArmed;

    // Pending changes
    [ObservableProperty] private int _pendingCount;
    [ObservableProperty] private bool _hasPending;
    [ObservableProperty] private string _applyButtonText = "Applied";

    // Collections
    public ObservableCollection<RouteRule> DraftRules { get; } = [];
    public ObservableCollection<InterfaceSnapshot> Interfaces { get; } = [];
    public ObservableCollection<RouteEntry> RoutingTable { get; } = [];
    public ObservableCollection<LiveConnection> Connections { get; } = [];

    [ObservableProperty] private KillSwitchConfig _draftKillSwitch = new();
    [ObservableProperty] private HelperStatus _helperStatus = new();

    private List<RouteRule> _appliedRules = [];
    private KillSwitchConfig _appliedKillSwitch = new();

    public MainViewModel()
    {
        LoadDrafts();
    }

    private void LoadDrafts()
    {
        var rules = BirJson.Load<List<RouteRule>>(BirPaths.DraftRulesPath)
                    ?? BirJson.Load<List<RouteRule>>(BirPaths.PersistentRulesPath)
                    ?? [];
        DraftRules.Clear();
        foreach (var r in rules) DraftRules.Add(r);

        DraftKillSwitch = BirJson.Load<KillSwitchConfig>(BirPaths.DraftKillSwitchPath)
                          ?? BirJson.Load<KillSwitchConfig>(BirPaths.KillSwitchConfigPath)
                          ?? new KillSwitchConfig();
    }

    public void SaveDrafts()
    {
        BirJson.Save(BirPaths.DraftRulesPath, DraftRules.ToList());
        BirJson.Save(BirPaths.DraftKillSwitchPath, DraftKillSwitch);
        RecalculatePending();
    }

    public void RecalculatePending()
    {
        int diff = 0;
        var appliedById = _appliedRules.ToDictionary(r => r.Id);
        foreach (var r in DraftRules)
        {
            if (!appliedById.TryGetValue(r.Id, out var a) || !r.SameContent(a))
                diff++;
        }
        foreach (var a in _appliedRules)
        {
            if (DraftRules.All(r => r.Id != a.Id))
                diff++;
        }

        if (DraftKillSwitch.Enabled != _appliedKillSwitch.Enabled ||
            DraftKillSwitch.Mode != _appliedKillSwitch.Mode ||
            !DraftKillSwitch.Interfaces.SequenceEqual(_appliedKillSwitch.Interfaces))
        {
            diff++;
        }

        PendingCount = diff;
        HasPending = diff > 0;
        ApplyButtonText = diff > 0 ? $"Apply {diff} Change{(diff == 1 ? "" : "s")}" : "Applied";
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        IsBusy = true;
        BusyText = "Refreshing network state...";
        try
        {
            var (installed, running, label) = ServiceClient.GetServiceState();
            ServiceInstalled = installed;
            ServiceRunning = running;
            ServiceStatusText = label;
            ServiceStatusBrush = running ? Brushes.LimeGreen : (installed ? Brushes.Goldenrod : Brushes.Gray);

            var interfaces = await Task.Run(Win32Interfaces.GetSnapshot);
            Interfaces.Clear();
            foreach (var iface in interfaces.OrderByDescending(i => i.IsUp).ThenBy(i => i.Name))
                Interfaces.Add(iface);

            var routes = await Task.Run(() => Win32Routing.GetRoutingTable(interfaces));
            RoutingTable.Clear();
            foreach (var r in routes) RoutingTable.Add(r);

            var best = await Task.Run(() => Win32Routing.LookupBestRoute("1.1.1.1", interfaces));
            if (best is not null)
            {
                InternetVia = $"Internet via {best.InterfaceName}";
                PrimaryGateway = best.Gateway ?? "Direct";
            }

            if (running)
            {
                var resp = await ServiceClient.SendAsync(new IpcRequest { Command = IpcCommandType.GetStatus });
                if (resp.Ok && resp.Status is not null)
                {
                    HelperStatus = resp.Status;
                    KillSwitchArmed = resp.Status.KillSwitch.Active;
                }
            }

            _appliedRules = BirJson.Load<List<RouteRule>>(BirPaths.PersistentRulesPath) ?? [];
            _appliedKillSwitch = BirJson.Load<KillSwitchConfig>(BirPaths.KillSwitchConfigPath) ?? new KillSwitchConfig();
            RecalculatePending();

            var ipInfo = await ServiceClient.FetchPublicIpAsync();
            if (ipInfo is not null)
            {
                PublicIp = ipInfo.Ip;
                PublicLocation = string.Join(", ", new[] { ipInfo.City, ipInfo.Country }.Where(s => !string.IsNullOrEmpty(s)));
                if (string.IsNullOrEmpty(PublicLocation)) PublicLocation = "—";
                PublicIsp = ipInfo.Org ?? "—";
            }

            UpdatedTime = DateTime.Now.ToString("HH:mm:ss");
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    [RelayCommand]
    public async Task ApplyAsync()
    {
        SaveDrafts();
        if (!ServiceRunning)
        {
            BannerMessage = "Background service is not running. Go to Service tab to install and start it.";
            IsBannerError = true;
            return;
        }

        IsBusy = true;
        BusyText = "Applying routes and firewall rules...";
        BannerMessage = null;
        try
        {
            var resp = await ServiceClient.SendAsync(new IpcRequest
            {
                Command = IpcCommandType.Apply,
                Rules = DraftRules.ToList(),
                KillSwitch = DraftKillSwitch
            });

            if (!resp.Ok)
            {
                BannerMessage = resp.Error ?? "Failed to apply changes.";
                IsBannerError = true;
                return;
            }

            if (resp.Status is not null)
            {
                HelperStatus = resp.Status;
                KillSwitchArmed = resp.Status.KillSwitch.Active;
                if (resp.Status.Errors.Count > 0)
                {
                    BannerMessage = string.Join("; ", resp.Status.Errors.Take(3));
                    IsBannerError = true;
                }
                else
                {
                    BannerMessage = $"Applied {resp.Status.AppliedRoutes.Count} routes successfully.";
                    IsBannerError = false;
                }
            }

            await RefreshAsync();
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }
}
