using RedPacketSniffer.Core.Export;
using RedPacketSniffer.Hubs;
using RedPacketSniffer.Services;

namespace RedPacketSniffer.Modes;

/// <summary>
/// Web dashboard mode — ASP.NET Core + SignalR
/// </summary>
public static class WebMode
{
    public static async Task RunAsync(string[] args, int port)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Services
        builder.Services.AddSignalR()
            .AddJsonProtocol(options =>
            {
                options.PayloadSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
            });

        builder.Services.AddSingleton<CaptureService>();
        builder.Services.AddHostedService<PacketBroadcastService>();

        // CORS cho development
        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy.AllowAnyOrigin()
                      .AllowAnyHeader()
                      .AllowAnyMethod();
            });
        });

        var app = builder.Build();

        app.UseDefaultFiles();
        app.UseStaticFiles();
        app.UseCors();

        app.MapHub<PacketHub>("/hub/packets");

        // Health check endpoint
        app.MapGet("/api/health", () => Results.Ok(new { status = "ok", timestamp = DateTime.UtcNow }));

        // PCAP export endpoint
        app.MapGet("/api/export/pcap", (CaptureService captureService) =>
        {
            var pcapBytes = captureService.ExportPcap();
            var fileName = $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap";
            return Results.File(pcapBytes, "application/vnd.tcpdump.pcap", fileName);
        });

        // HTML report endpoint
        app.MapGet("/api/export/report", (CaptureService captureService) =>
        {
            var report = captureService.GenerateReport();
            var html = ReportGenerator.ExportHtml(report);
            var fileName = $"report_{DateTime.Now:yyyyMMdd_HHmmss}.html";
            return Results.File(
                System.Text.Encoding.UTF8.GetBytes(html),
                "text/html",
                fileName);
        });

        // JSON report endpoint
        app.MapGet("/api/export/report.json", (CaptureService captureService) =>
        {
            var report = captureService.GenerateReport();
            return Results.Ok(report);
        });

        Console.WriteLine($@"
+================================================+
|       Red Packet Sniffer v1.0                  |
|       CMC Red Team - Internal Tool             |
|                                                |
|   Web UI: http://localhost:{port,-5}             |
|   SignalR: ws://localhost:{port}/hub/packets    |
|                                                |
|   API Endpoints:                               |
|     GET /api/export/pcap   -- PCAP download    |
|     GET /api/export/report -- HTML report      |
|     GET /api/export/report.json -- JSON data   |
|                                                |
|   [!] Yeu cau: Administrator + WinpkFilter     |
+================================================+
");

        await app.RunAsync($"http://0.0.0.0:{port}");
    }
}
