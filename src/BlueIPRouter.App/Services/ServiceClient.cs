using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net.Http;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using BlueIPRouter.Core.Models;

namespace BlueIPRouter.App.Services;

public sealed record PublicIpInfo(string Ip, string? Country, string? City, string? Org);

public static class ServiceClient
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(6) };

    public static (bool Installed, bool Running, string Label) GetServiceState()
    {
        try
        {
            using var sc = new ServiceController(BirPaths.ServiceName);
            var status = sc.Status;
            bool running = status == ServiceControllerStatus.Running;
            return (true, running, running ? "Persistence on" : "Persistence off");
        }
        catch
        {
            return (false, false, "Service not installed");
        }
    }

    public static async Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken ct = default)
    {
        try
        {
            await using var client = new NamedPipeClientStream(".", BirPaths.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(2500, ct);

            await using var writer = new StreamWriter(client, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(client, Encoding.UTF8, leaveOpen: true);

            await writer.WriteLineAsync(JsonSerializer.Serialize(request, BirJson.Options));
            var line = await reader.ReadLineAsync(ct);
            if (string.IsNullOrWhiteSpace(line))
                return new IpcResponse { Ok = false, Error = "Empty response from service." };

            return JsonSerializer.Deserialize<IpcResponse>(line, BirJson.Options)
                   ?? new IpcResponse { Ok = false, Error = "Invalid JSON response." };
        }
        catch (TimeoutException)
        {
            return new IpcResponse { Ok = false, Error = "Service is not running or did not respond." };
        }
        catch (Exception ex)
        {
            return new IpcResponse { Ok = false, Error = ex.Message };
        }
    }

    public static bool RunElevatedCommand(string command, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(15000);
            return proc?.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static string? FindBundledServiceExe()
    {
        var baseDir = AppContext.BaseDirectory;
        var candidate1 = Path.Combine(baseDir, "service", "BlueIPRouter.Service.exe");
        if (File.Exists(candidate1)) return candidate1;
        var candidate2 = Path.Combine(baseDir, "BlueIPRouter.Service.exe");
        if (File.Exists(candidate2)) return candidate2;
        return null;
    }

    public static bool InstallAndStartService()
    {
        var exe = FindBundledServiceExe();
        if (exe is null) return false;
        var cmd = $"/c sc create {BirPaths.ServiceName} binPath= \"\\\"{exe}\\\"\" start= auto DisplayName= \"{BirPaths.ServiceDisplayName}\" & sc start {BirPaths.ServiceName}";
        return RunElevatedCommand("cmd.exe", cmd);
    }

    public static bool UninstallService()
    {
        var cmd = $"/c sc stop {BirPaths.ServiceName} & sc delete {BirPaths.ServiceName}";
        return RunElevatedCommand("cmd.exe", cmd);
    }

    public static async Task<PublicIpInfo?> FetchPublicIpAsync()
    {
        try
        {
            var ip = (await Http.GetStringAsync("https://api.ipify.org")).Trim();
            if (string.IsNullOrWhiteSpace(ip)) return null;
            try
            {
                var json = await Http.GetStringAsync($"https://ipinfo.io/{ip}/json");
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                return new PublicIpInfo(
                    ip,
                    root.TryGetProperty("country", out var c) ? c.GetString() : null,
                    root.TryGetProperty("city", out var ct) ? ct.GetString() : null,
                    root.TryGetProperty("org", out var o) ? o.GetString() : null);
            }
            catch
            {
                return new PublicIpInfo(ip, null, null, null);
            }
        }
        catch
        {
            return null;
        }
    }
}
