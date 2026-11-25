using System.IO.Pipes;
using System.Net.NetworkInformation;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using BlueIPRouter.Core.Models;

namespace BlueIPRouter.Service;

public sealed class PipeServerWorker(ReconcileEngine engine, ILogger<PipeServerWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("BlueIPRouter Service starting...");
        try
        {
            engine.Apply();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Initial reconcile failed");
        }

        NetworkChange.NetworkAddressChanged += OnNetworkChanged;

        _ = Task.Run(() => PeriodicReconcileLoop(stoppingToken), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var pipeSecurity = new PipeSecurity();
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    PipeAccessRights.ReadWrite,
                    AccessControlType.Allow));
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));

                await using var server = NamedPipeServerStreamAcl.Create(
                    BirPaths.PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 65536,
                    outBufferSize: 65536,
                    pipeSecurity);

                await server.WaitForConnectionAsync(stoppingToken);
                await HandleClientAsync(server, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Named pipe server error");
                await Task.Delay(500, stoppingToken);
            }
        }

        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
    }

    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        try
        {
            engine.Apply();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Reconcile on network change failed");
        }
    }

    private async Task PeriodicReconcileLoop(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        while (await timer.WaitForNextTickAsync(token))
        {
            try
            {
                engine.Apply();
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Periodic reconcile failed");
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream server, CancellationToken token)
    {
        using var reader = new StreamReader(server, Encoding.UTF8, leaveOpen: true);
        await using var writer = new StreamWriter(server, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };

        var line = await reader.ReadLineAsync(token);
        if (string.IsNullOrWhiteSpace(line)) return;

        IpcResponse response;
        try
        {
            var req = JsonSerializer.Deserialize<IpcRequest>(line, BirJson.Options)
                      ?? throw new InvalidOperationException("Invalid IPC request");

            var status = req.Command switch
            {
                IpcCommandType.GetStatus => engine.GetStatus(),
                IpcCommandType.Apply => engine.Apply(req.Rules, req.KillSwitch, req.BlockList),
                IpcCommandType.RemoveAll => engine.RemoveAll(),
                IpcCommandType.KillSwitchOff => engine.KillSwitchOff(),
                IpcCommandType.DetectVpn => engine.Apply(),
                _ => throw new NotSupportedException($"Unknown command {req.Command}")
            };

            response = new IpcResponse { Ok = true, Status = status };
        }
        catch (Exception ex)
        {
            response = new IpcResponse { Ok = false, Error = ex.Message };
        }

        await writer.WriteLineAsync(JsonSerializer.Serialize(response, BirJson.Options));
    }
}
