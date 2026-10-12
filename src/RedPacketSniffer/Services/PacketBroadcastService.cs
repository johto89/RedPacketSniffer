using Microsoft.AspNetCore.SignalR;
using RedPacketSniffer.Core.Analysis;
using RedPacketSniffer.Hubs;

namespace RedPacketSniffer.Services;

/// <summary>
/// Background service: forward packet/credential/weakness events tu CaptureService sang SignalR clients
/// Batching: gom packet lai gui moi 100ms thay vi gui tung cai — giam overhead SignalR
/// </summary>
public sealed class PacketBroadcastService : BackgroundService
{
    private readonly CaptureService _captureService;
    private readonly IHubContext<PacketHub> _hubContext;
    private readonly ILogger<PacketBroadcastService> _logger;
    private readonly List<PacketDto> _pendingPackets = new();
    private readonly List<CredentialDto> _pendingCredentials = new();
    private readonly List<WeaknessDto> _pendingWeaknesses = new();
    private readonly List<DnsRecordDto> _pendingDnsRecords = new();
    private readonly List<TcpConnectionDto> _pendingTcpUpdates = new();
    private readonly List<HttpLogEntryDto> _pendingHttpEntries = new();
    private readonly List<NetworkHostDto> _pendingHostUpdates = new();
    private readonly List<L2L3FindingDto> _pendingL2L3Findings = new();
    private readonly List<VoipFindingDto> _pendingVoipFindings = new();
    private readonly object _batchLock = new();

    // Broadcast intervals
    private const int BATCH_INTERVAL_MS = 100;
    private const int STATS_INTERVAL_MS = 1000;
    private const int MAX_BATCH_SIZE = 50; // Khong gui qua 50 packet/batch (tranh flood browser)

    public PacketBroadcastService(
        CaptureService captureService,
        IHubContext<PacketHub> hubContext,
        ILogger<PacketBroadcastService> logger)
    {
        _captureService = captureService;
        _hubContext = hubContext;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _captureService.OnPacketCaptured += packet =>
        {
            var dto = PacketDto.FromPacket(packet);
            lock (_batchLock)
            {
                _pendingPackets.Add(dto);
            }
        };

        _captureService.OnCredentialFound += cred =>
        {
            var dto = CredentialDto.FromCredential(cred);
            lock (_batchLock)
            {
                _pendingCredentials.Add(dto);
            }
        };

        _captureService.OnWeaknessDetected += weakness =>
        {
            var dto = WeaknessDto.FromWeakness(weakness);
            lock (_batchLock)
            {
                _pendingWeaknesses.Add(dto);
            }
        };

        _captureService.OnDnsRecord += record =>
        {
            var dto = DnsRecordDto.FromRecord(record);
            lock (_batchLock)
            {
                _pendingDnsRecords.Add(dto);
            }
        };

        _captureService.OnTcpConnectionUpdated += conn =>
        {
            var dto = TcpConnectionDto.FromConnection(conn);
            lock (_batchLock)
            {
                // Replace existing entry cho cung connection (chi giu state moi nhat)
                _pendingTcpUpdates.RemoveAll(c => c.Id == dto.Id);
                _pendingTcpUpdates.Add(dto);
            }
        };

        _captureService.OnHttpEntry += entry =>
        {
            var dto = HttpLogEntryDto.FromEntry(entry);
            lock (_batchLock)
            {
                _pendingHttpEntries.Add(dto);
            }
        };

        _captureService.OnHostUpdated += host =>
        {
            var dto = NetworkHostDto.FromHost(host);
            lock (_batchLock)
            {
                // Replace existing entry cho cung host (chi giu state moi nhat)
                _pendingHostUpdates.RemoveAll(h => h.Id == dto.Id);
                _pendingHostUpdates.Add(dto);
            }
        };

        _captureService.OnL2L3Finding += finding =>
        {
            var dto = L2L3FindingDto.FromFinding(finding);
            lock (_batchLock)
            {
                _pendingL2L3Findings.Add(dto);
            }
        };

        _captureService.OnVoipFinding += finding =>
        {
            var dto = VoipFindingDto.FromFinding(finding);
            lock (_batchLock)
            {
                _pendingVoipFindings.Add(dto);
            }
        };

        _captureService.OnError += async error =>
        {
            try
            {
                await _hubContext.Clients.All.SendAsync("ErrorOccurred", error, stoppingToken);
            }
            catch { /* ignore broadcast failures */ }
        };

        _captureService.OnStateChanged += async state =>
        {
            try
            {
                await _hubContext.Clients.All.SendAsync("StateChanged", state.ToString(), stoppingToken);
            }
            catch { /* ignore */ }
        };

        int tickCount = 0;

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(BATCH_INTERVAL_MS, stoppingToken);
            tickCount++;

            // Collect pending items
            List<PacketDto>? packetBatch = null;
            List<CredentialDto>? credBatch = null;
            List<WeaknessDto>? weakBatch = null;
            List<DnsRecordDto>? dnsBatch = null;
            List<TcpConnectionDto>? tcpBatch = null;
            List<HttpLogEntryDto>? httpBatch = null;
            List<NetworkHostDto>? hostBatch = null;
            List<L2L3FindingDto>? l2l3Batch = null;
            List<VoipFindingDto>? voipBatch = null;

            lock (_batchLock)
            {
                if (_pendingPackets.Count > 0)
                {
                    int take = Math.Min(_pendingPackets.Count, MAX_BATCH_SIZE);
                    packetBatch = _pendingPackets.GetRange(_pendingPackets.Count - take, take);
                    _pendingPackets.Clear();
                }
                if (_pendingCredentials.Count > 0)
                {
                    credBatch = new List<CredentialDto>(_pendingCredentials);
                    _pendingCredentials.Clear();
                }
                if (_pendingWeaknesses.Count > 0)
                {
                    weakBatch = new List<WeaknessDto>(_pendingWeaknesses);
                    _pendingWeaknesses.Clear();
                }
                if (_pendingDnsRecords.Count > 0)
                {
                    dnsBatch = new List<DnsRecordDto>(_pendingDnsRecords);
                    _pendingDnsRecords.Clear();
                }
                if (_pendingTcpUpdates.Count > 0)
                {
                    tcpBatch = new List<TcpConnectionDto>(_pendingTcpUpdates);
                    _pendingTcpUpdates.Clear();
                }
                if (_pendingHttpEntries.Count > 0)
                {
                    httpBatch = new List<HttpLogEntryDto>(_pendingHttpEntries);
                    _pendingHttpEntries.Clear();
                }
                if (_pendingHostUpdates.Count > 0)
                {
                    hostBatch = new List<NetworkHostDto>(_pendingHostUpdates);
                    _pendingHostUpdates.Clear();
                }
                if (_pendingL2L3Findings.Count > 0)
                {
                    l2l3Batch = new List<L2L3FindingDto>(_pendingL2L3Findings);
                    _pendingL2L3Findings.Clear();
                }
                if (_pendingVoipFindings.Count > 0)
                {
                    voipBatch = new List<VoipFindingDto>(_pendingVoipFindings);
                    _pendingVoipFindings.Clear();
                }
            }

            // Send packet batch
            if (packetBatch != null)
            {
                try
                {
                    await _hubContext.Clients.All.SendAsync("PacketBatch", packetBatch, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to broadcast packet batch: {Error}", ex.Message);
                }
            }

            // Send credentials
            if (credBatch != null)
            {
                try
                {
                    await _hubContext.Clients.All.SendAsync("CredentialFound", credBatch, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to broadcast credentials: {Error}", ex.Message);
                }
            }

            // Send weaknesses
            if (weakBatch != null)
            {
                try
                {
                    await _hubContext.Clients.All.SendAsync("WeaknessDetected", weakBatch, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to broadcast weaknesses: {Error}", ex.Message);
                }
            }

            // Send DNS records
            if (dnsBatch != null)
            {
                try
                {
                    await _hubContext.Clients.All.SendAsync("DnsRecordFound", dnsBatch, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to broadcast DNS records: {Error}", ex.Message);
                }
            }

            // Send TCP connection updates
            if (tcpBatch != null)
            {
                try
                {
                    await _hubContext.Clients.All.SendAsync("TcpConnectionUpdated", tcpBatch, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to broadcast TCP connections: {Error}", ex.Message);
                }
            }

            // Send HTTP entries
            if (httpBatch != null)
            {
                try
                {
                    await _hubContext.Clients.All.SendAsync("HttpEntryFound", httpBatch, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to broadcast HTTP entries: {Error}", ex.Message);
                }
            }

            // Send network host updates
            if (hostBatch != null)
            {
                try
                {
                    await _hubContext.Clients.All.SendAsync("HostUpdated", hostBatch, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to broadcast host updates: {Error}", ex.Message);
                }
            }

            // Send L2/L3 findings
            if (l2l3Batch != null)
            {
                try
                {
                    await _hubContext.Clients.All.SendAsync("L2L3FindingFound", l2l3Batch, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to broadcast L2/L3 findings: {Error}", ex.Message);
                }
            }

            // Send VoIP findings
            if (voipBatch != null)
            {
                try
                {
                    await _hubContext.Clients.All.SendAsync("VoipFindingFound", voipBatch, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to broadcast VoIP findings: {Error}", ex.Message);
                }
            }

            // Send stats moi giay
            if (tickCount * BATCH_INTERVAL_MS >= STATS_INTERVAL_MS)
            {
                tickCount = 0;
                try
                {
                    var stats = _captureService.GetStats();
                    await _hubContext.Clients.All.SendAsync("StatsUpdate", stats, stoppingToken);
                }
                catch { /* ignore */ }
            }
        }
    }
}
