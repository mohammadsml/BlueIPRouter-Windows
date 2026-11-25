using BlueIPRouter.Core.Models;
using BlueIPRouter.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = BirPaths.ServiceName;
});
builder.Services.AddSingleton<ReconcileEngine>();
builder.Services.AddHostedService<PipeServerWorker>();

var host = builder.Build();
host.Run();
