using BlueIPRouter.Core.Models;
using BlueIPRouter.Core.Routing;
using BlueIPRouter.Core.Utils;
using BlueIPRouter.Core.Windows;

namespace BlueIPRouter.Service;

public sealed class ReconcileEngine
{
    private readonly object _lock = new();

    private static readonly string[] LinkLocalRanges =
    [
        "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"
    ];

    private static readonly string[] PrivateRanges =
    [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
    ];

    public HelperStatus Apply(
        List<RouteRule>? rulesOverride = null,
        KillSwitchConfig? ksOverride = null,
        List<BlockEntry>? blockOverride = null)
    {
        lock (_lock)
        {
            Directory.CreateDirectory(BirPaths.SystemDir);

            if (rulesOverride is not null)
                BirJson.Save(BirPaths.PersistentRulesPath, rulesOverride.Where(r => r.Persistent).ToList());
            if (ksOverride is not null)
                BirJson.Save(BirPaths.KillSwitchConfigPath, ksOverride);
            if (blockOverride is not null)
                BirJson.Save(BirPaths.BlockListPath, blockOverride);

            var rules = rulesOverride ?? BirJson.Load<List<RouteRule>>(BirPaths.PersistentRulesPath) ?? [];
            var ksConfig = ksOverride ?? BirJson.Load<KillSwitchConfig>(BirPaths.KillSwitchConfigPath) ?? new KillSwitchConfig();
            var blockList = blockOverride ?? BirJson.Load<List<BlockEntry>>(BirPaths.BlockListPath) ?? [];
            var dnsCache = BirJson.Load<Dictionary<string, List<string>>>(BirPaths.DnsCachePath) ?? [];
            var previousRoutes = BirJson.Load<List<ManagedRoute>>(BirPaths.AppliedStatePath) ?? [];

            var interfaces = Win32Interfaces.GetSnapshot();
            var plan = RoutePlanner.Plan(rules, interfaces, dnsCache);
            BirJson.Save(BirPaths.DnsCachePath, plan.DnsCache);

            var errors = new List<string>();

            // Remove old routes that are no longer in the plan
            var newKeys = plan.Routes.Select(r => $"{r.Destination}/{r.Prefix}").ToHashSet();
            foreach (var old in previousRoutes)
            {
                if (old.KeepOnRemove) continue;
                string key = $"{old.Destination}/{old.Prefix}";
                if (!newKeys.Contains(key))
                {
                    var (ok, err) = Win32Routing.DeleteRoute(old);
                    if (!ok && err != null) errors.Add(err);
                }
            }

            // Install or verify planned routes
            var appliedRoutes = new List<ManagedRoute>();
            foreach (var route in plan.Routes)
            {
                var lookup = Win32Routing.LookupBestRoute(route.Destination, interfaces);
                if (!Win32Routing.IsRouteInstalled(route, lookup))
                {
                    var (ok, err) = Win32Routing.AddRoute(route);
                    if (!ok && err != null)
                    {
                        errors.Add(err);
                        if (plan.Statuses.TryGetValue(route.RuleId, out var st))
                        {
                            st.Messages.Add(err);
                            st.State = RuleState.Partial;
                        }
                        continue;
                    }
                }
                appliedRoutes.Add(route);
                if (plan.Statuses.TryGetValue(route.RuleId, out var stOk))
                    stOk.LiveCount++;
            }

            BirJson.Save(BirPaths.AppliedStatePath, appliedRoutes);

            // Learn VPN core server IPs
            var learned = BirJson.Load<List<string>>(BirPaths.LearnedServersPath) ?? [];
            if (ksConfig.LearnVpnServers)
            {
                var detected = Win32Connections.DetectVpnServerIps(interfaces);
                var merged = learned.Concat(detected).Distinct().OrderBy(x => x).ToList();
                if (merged.Count != learned.Count)
                {
                    learned = merged;
                    BirJson.Save(BirPaths.LearnedServersPath, learned);
                }
            }

            // Compile Kill Switch & Block List into WFP
            var blockedCidrs = ResolveEntries(
                ksConfig.BlockLists.Where(l => l.Enabled).SelectMany(l => l.Entries),
                dnsCache);

            var allowedCidrs = ResolveEntries(ksConfig.Allow, dnsCache);
            if (ksConfig.AllowLocalNetworks)
                allowedCidrs.AddRange(LinkLocalRanges.Concat(PrivateRanges));
            if (ksConfig.AllowRuleDestinations)
                allowedCidrs.AddRange(appliedRoutes.Select(r => $"{r.Destination}/{r.Prefix}"));
            if (ksConfig.LearnVpnServers)
                allowedCidrs.AddRange(learned.Select(ip => $"{ip}/32"));
            if (ksConfig.AllowDns)
                allowedCidrs.AddRange(interfaces.SelectMany(i => i.DnsServers).Where(IpUtils.IsValidIPv4).Select(ip => $"{ip}/32"));

            var deniedCidrs = ResolveEntries(blockList.Where(b => b.Enabled).Select(b => b.Value), dnsCache);

            var (wfpOk, wfpErrors) = WfpFirewall.Apply(ksConfig, interfaces, blockedCidrs, allowedCidrs, deniedCidrs);
            errors.AddRange(wfpErrors);

            var status = new HelperStatus
            {
                UpdatedAt = DateTime.UtcNow,
                AppliedRoutes = appliedRoutes,
                RuleStatuses = plan.Statuses,
                KillSwitch = new KillSwitchStatus
                {
                    Active = ksConfig.Enabled && wfpOk,
                    Mode = ksConfig.Mode,
                    Interfaces = ksConfig.Interfaces,
                    Blocked = blockedCidrs.Distinct().ToList(),
                    Allowed = allowedCidrs.Distinct().ToList(),
                    DnsServers = interfaces.SelectMany(i => i.DnsServers).Distinct().ToList(),
                    LearnedServers = learned,
                    WfpActive = wfpOk,
                    Errors = wfpErrors
                },
                BlockList = new BlockListStatus
                {
                    Active = deniedCidrs.Count > 0 && wfpOk,
                    Denied = deniedCidrs.Distinct().ToList(),
                    Errors = wfpErrors
                },
                Errors = errors
            };

            BirJson.Save(BirPaths.StatusPath, status);
            return status;
        }
    }

    public HelperStatus RemoveAll()
    {
        lock (_lock)
        {
            var previous = BirJson.Load<List<ManagedRoute>>(BirPaths.AppliedStatePath) ?? [];
            foreach (var r in previous.Where(x => !x.KeepOnRemove))
                Win32Routing.DeleteRoute(r);

            WfpFirewall.ClearAll();
            BirJson.Save(BirPaths.AppliedStatePath, new List<ManagedRoute>());

            var status = new HelperStatus { UpdatedAt = DateTime.UtcNow };
            BirJson.Save(BirPaths.StatusPath, status);
            return status;
        }
    }

    public HelperStatus KillSwitchOff()
    {
        lock (_lock)
        {
            var ks = BirJson.Load<KillSwitchConfig>(BirPaths.KillSwitchConfigPath) ?? new KillSwitchConfig();
            ks.Enabled = false;
            BirJson.Save(BirPaths.KillSwitchConfigPath, ks);
            return Apply(ksOverride: ks);
        }
    }

    public HelperStatus GetStatus()
    {
        lock (_lock)
        {
            return BirJson.Load<HelperStatus>(BirPaths.StatusPath) ?? new HelperStatus();
        }
    }

    private static List<string> ResolveEntries(IEnumerable<string> entries, Dictionary<string, List<string>> cache)
    {
        var cidrs = new List<string>();
        foreach (var raw in entries)
        {
            if (IpUtils.NormalizeCidr(raw) is { } c)
            {
                cidrs.Add(c);
            }
            else if (IpUtils.IsValidDomain(raw))
            {
                var d = raw.Trim().TrimEnd('.').ToLowerInvariant();
                var ips = RoutePlanner.ResolveIPv4(d);
                if (ips.Count > 0) cache["ks:" + d] = ips;
                else if (cache.TryGetValue("ks:" + d, out var cached)) ips = cached;
                cidrs.AddRange(ips.Select(ip => $"{ip}/32"));
            }
        }
        return cidrs;
    }
}
