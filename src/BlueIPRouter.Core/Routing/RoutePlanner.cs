using System.Net;
using System.Net.Sockets;
using BlueIPRouter.Core.Models;

namespace BlueIPRouter.Core.Routing;

public static class RoutePlanner
{
    public sealed class PlanResult
    {
        public List<ManagedRoute> Routes { get; } = [];
        public Dictionary<Guid, RuleStatus> Statuses { get; } = [];
        public Dictionary<string, List<string>> DnsCache { get; } = [];
    }

    public static PlanResult Plan(
        IEnumerable<RouteRule> rules,
        List<InterfaceSnapshot> interfaces,
        Dictionary<string, List<string>> existingCache)
    {
        var result = new PlanResult();
        foreach (var kv in existingCache) result.DnsCache[kv.Key] = [.. kv.Value];

        var seen = new Dictionary<string, Guid>();

        foreach (var rule in rules)
        {
            var status = new RuleStatus { RuleId = rule.Id };
            if (!rule.Enabled)
            {
                status.State = RuleState.Disabled;
                result.Statuses[rule.Id] = status;
                continue;
            }

            if (rule.Via.ValidationError() is { } viaErr)
            {
                status.State = RuleState.Failed;
                status.Messages.Add(viaErr);
                result.Statuses[rule.Id] = status;
                continue;
            }

            string? gateway = null;
            InterfaceSnapshot? targetIface = null;

            switch (rule.Via.Kind)
            {
                case RouteViaKind.SpecificGateway:
                    gateway = rule.Via.GatewayIp;
                    targetIface = interfaces.FirstOrDefault(i => i.IsUp && i.Gateways.Contains(gateway!))
                                  ?? interfaces.FirstOrDefault(i => i.IsUp && !i.IsLoopback);
                    break;

                case RouteViaKind.InterfaceDirect:
                    targetIface = interfaces.FirstOrDefault(i =>
                        string.Equals(i.Name, rule.Via.InterfaceName, StringComparison.OrdinalIgnoreCase) && i.IsUp);
                    if (targetIface is null)
                    {
                        status.State = RuleState.Waiting;
                        status.Messages.Add($"Interface {rule.Via.InterfaceName} is not present or is down");
                        result.Statuses[rule.Id] = status;
                        continue;
                    }
                    break;

                case RouteViaKind.InterfaceRouter:
                    targetIface = interfaces.FirstOrDefault(i =>
                        string.Equals(i.Name, rule.Via.InterfaceName, StringComparison.OrdinalIgnoreCase) && i.IsUp);
                    if (targetIface is null || targetIface.Ipv4.Count == 0)
                    {
                        status.State = RuleState.Waiting;
                        status.Messages.Add($"Interface {rule.Via.InterfaceName} is down or has no IPv4 address");
                        result.Statuses[rule.Id] = status;
                        continue;
                    }
                    gateway = targetIface.PrimaryGateway;
                    if (string.IsNullOrEmpty(gateway) && !targetIface.IsTunnel)
                    {
                        status.State = RuleState.Waiting;
                        status.Messages.Add($"No gateway known for {targetIface.Name} yet (DHCP not finished?)");
                        result.Statuses[rule.Id] = status;
                        continue;
                    }
                    break;
            }

            if (targetIface is null)
            {
                status.State = RuleState.Waiting;
                status.Messages.Add("Target interface not available");
                result.Statuses[rule.Id] = status;
                continue;
            }

            foreach (var rawDest in rule.Destinations)
            {
                var parsed = DestinationParser.Parse(rawDest);
                if (parsed is null) continue;

                var targets = new List<(string Address, int Prefix, string? Domain)>();
                switch (parsed.Kind)
                {
                    case DestinationKind.Host:
                        targets.Add((parsed.Address, 32, null));
                        break;
                    case DestinationKind.Network:
                        targets.Add((parsed.Address, parsed.Prefix, null));
                        break;
                    case DestinationKind.Domain:
                        var resolved = ResolveIPv4(parsed.Address);
                        if (resolved.Count > 0)
                        {
                            result.DnsCache[parsed.Address] = resolved;
                            status.Resolved[parsed.Address] = resolved;
                        }
                        else if (existingCache.TryGetValue(parsed.Address, out var cached) && cached.Count > 0)
                        {
                            status.Resolved[parsed.Address] = cached;
                            status.Messages.Add($"DNS lookup for {parsed.Address} failed; using cached IPs");
                        }
                        else
                        {
                            status.Messages.Add($"Could not resolve {parsed.Address}");
                        }

                        if (status.Resolved.TryGetValue(parsed.Address, out var ips))
                        {
                            foreach (var ip in ips) targets.Add((ip, 32, parsed.Address));
                        }
                        break;
                }

                foreach (var (address, prefix, domain) in targets)
                {
                    if (address == gateway)
                    {
                        status.Messages.Add($"Skipped {address}: it is the gateway itself");
                        continue;
                    }

                    string key = $"{address}/{prefix}";
                    if (seen.TryGetValue(key, out var owner))
                    {
                        if (owner != rule.Id)
                            status.Messages.Add($"{key} is already routed by another rule; skipped");
                        continue;
                    }
                    seen[key] = rule.Id;

                    result.Routes.Add(new ManagedRoute(
                        rule.Id,
                        rule.Name,
                        address,
                        prefix,
                        gateway,
                        targetIface.Name,
                        targetIface.Index,
                        targetIface.Luid,
                        domain,
                        rule.KeepRoutesOnRemove));
                }
            }

            status.ExpectedCount = result.Routes.Count(r => r.RuleId == rule.Id);
            status.State = status.ExpectedCount > 0 ? RuleState.Applied : RuleState.Failed;
            result.Statuses[rule.Id] = status;
        }

        return result;
    }

    public static List<string> ResolveIPv4(string domain)
    {
        try
        {
            return Dns.GetHostAddresses(domain)
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.ToString())
                .Distinct()
                .OrderBy(ip => ip)
                .ToList();
        }
        catch
        {
            return [];
        }
    }
}
