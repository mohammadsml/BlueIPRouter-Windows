# BlueIPRouter for Windows (Phase 1 MVP)

A native Windows 10/11 (.NET 8 + WPF Fluent UI + Windows Service + WFP) port of [BlueIPRouter](https://github.com/ahorazahedi/BlueIPRouter).

## Architecture

- **`BlueIPRouter.Core`**: Shared models, IPv4/IPv6/CIDR validation, `RoutePlanner`, `iphlpapi.dll` P/Invoke (`Win32Interfaces`, `Win32Routing`, `Win32Connections`), and Windows Filtering Platform (`WfpFirewall` via `fwpuclnt.dll`).
- **`BlueIPRouter.Service`**: `LocalSystem` Windows Service that applies persistent routes, monitors network changes, detects VPN core peers, enforces WFP Kill Switch / Block List filters, and exposes a Named Pipe IPC server (`BlueIPRouterServicePipe`).
- **`BlueIPRouter.App`**: WPF desktop app using `WPF-UI` (Windows 11 Mica/Dark Fluent theme) with System Tray support and UAC-elevated service installation.

## Build on Windows

Requires [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) on Windows 10/11 (or Visual Studio 2022).

```powershell
dotnet restore BlueIPRouter.sln
dotnet build BlueIPRouter.sln -c Release

# Publish standalone package (App + bundled Service)
dotnet publish src/BlueIPRouter.App/BlueIPRouter.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
dotnet publish src/BlueIPRouter.Service/BlueIPRouter.Service.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/service
```

Then run `publish\BlueIPRouter.exe`, go to **Service**, and click **Install & Start Service (UAC)**.
