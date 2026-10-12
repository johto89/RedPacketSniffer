using System.Threading.Channels;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// Wires packet capture to credential extraction, off the capture thread.
///
/// <see cref="PacketCaptureEngine"/> raises OnPacketCaptured synchronously inside its read
/// loop, so any work done in the handler is on the critical path: if it is slower than the
/// arrival rate, the driver's queue backs up and packets are dropped at the kernel — the worst
/// outcome for a passive sniffer, since a dropped packet is a lost credential. This coordinator
/// therefore does almost nothing on the capture thread: it drops irrelevant packets and hands
/// each relevant packet to a bounded queue, then a single worker thread does the actual extraction.
///
/// Routing (on the worker thread):
///   - HTTP is fed through <see cref="TcpStreamReassembler"/> into
///     <see cref="HttpStreamCredentialParser"/>, so multi-segment requests (form-POST bodies,
///     NTLM exchanges) are reassembled before matching.
///   - Line-based protocols (FTP, POP3, IMAP, SMTP, Telnet) stay on the per-packet
///     <see cref="CredentialExtractor"/>, whose HTTP branch is disabled (HandleHttp = false)
///     so a request is never reported twice.
///   - Kerberos (TCP/UDP port 88) is analyzed by <see cref="KerberosAnalyzer"/> for
///     Kerberoasting, AS-REP Roasting, encryption downgrade, Pass-the-Ticket, and
///     Overpass-the-Hash detection with hashcat-compatible hash extraction.
///
/// Because a single worker thread drives all engines, the reassembler, extractor, and Kerberos
/// analyzer still see a single-producer stream — the threading assumptions they were built on
/// hold. Downstream events (OnCredentialFound, OnKerberosEvent) are therefore raised on the
/// worker thread; marshal to the UI thread as needed, exactly as before.
///
/// Back-pressure: the queue is bounded. When it is full the capture thread does NOT block
/// (that would just move the drop to the kernel); the packet is dropped here and counted in
/// <see cref="DroppedPackets"/>, so the loss is visible. Size the queue for the expected burst.
/// </summary>
public sealed class CredentialCaptureCoordinator : IDisposable
{
    private readonly PacketCaptureEngine _engine;
    private readonly CredentialExtractor _lineExtractor;
    private readonly TcpStreamReassembler _reassembler;
    private readonly HttpStreamCredentialParser _httpParser;
    private readonly KerberosAnalyzer _kerberosAnalyzer;
    private readonly CoordinatorOptions _options;

    private readonly Channel<CapturedPacket> _channel;
    private readonly Task _worker;

    private long _droppedPackets;
    private long _processedPackets;
    private long _processErrors;
    private bool _disposed;

    /// <summary>Raised for every distinct credential found by either source (on the worker thread).</summary>
    public event Action<ExtractedCredential>? OnCredentialFound;

    /// <summary>
    /// Raised when a server response confirms a credential's login outcome (Success/Failed).
    /// Carries the same ExtractedCredential instance with its LoginStatus updated. Line-based
    /// protocols only — HTTP does not report login results through this path. Worker thread.
    /// </summary>
    public event Action<ExtractedCredential>? OnLoginResult;

    /// <summary>
    /// Raised when the Kerberos analyzer detects a security event (on the worker thread).
    /// Events include hash captures, attack detection, and protocol weaknesses.
    /// </summary>
    public event Action<KerberosEvent>? OnKerberosEvent;

    /// <summary>Raised when processing a packet throws (on the worker thread).</summary>
    public event Action<string>? OnError;

    public CredentialExtractor LineExtractor => _lineExtractor;
    public HttpStreamCredentialParser HttpParser => _httpParser;
    public TcpStreamReassembler Reassembler => _reassembler;
    public KerberosAnalyzer KerberosAnalyzer => _kerberosAnalyzer;

    /// <summary>Packets dropped because the queue was full (extraction could not keep up).</summary>
    public long DroppedPackets => Interlocked.Read(ref _droppedPackets);

    /// <summary>Packets fully processed by the worker.</summary>
    public long ProcessedPackets => Interlocked.Read(ref _processedPackets);

    /// <summary>Packets whose processing threw and was skipped.</summary>
    public long ProcessErrors => Interlocked.Read(ref _processErrors);

    /// <summary>Approximate number of packets currently waiting in the queue.</summary>
    public int QueueDepth => _channel.Reader.Count;

    public CredentialCaptureCoordinator(
        PacketCaptureEngine engine,
        TcpReassemblyOptions? reassemblyOptions = null,
        CoordinatorOptions? coordinatorOptions = null)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _options = coordinatorOptions ?? new CoordinatorOptions();

        _lineExtractor = new CredentialExtractor { HandleHttp = false };
        _reassembler = new TcpStreamReassembler(reassemblyOptions);
        _httpParser = new HttpStreamCredentialParser();
        _kerberosAnalyzer = new KerberosAnalyzer();

        _lineExtractor.OnCredentialFound += Forward;
        _lineExtractor.OnLoginResult += ForwardResult;
        _httpParser.OnCredentialFound += Forward;
        _reassembler.OnStreamData += _httpParser.Parse;
        _kerberosAnalyzer.OnKerberosEvent += ForwardKerberos;

        // FullMode.Wait means TryWrite returns false when full (instead of blocking the writer),
        // so the capture thread never stalls and we can count drops.
        _channel = Channel.CreateBounded<CapturedPacket>(new BoundedChannelOptions(_options.QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = true,
            AllowSynchronousContinuations = false
        });

        _worker = Task.Run(WorkerLoopAsync);
        _engine.OnPacketCaptured += OnPacket;
    }

    // ============================================================
    // Capture thread — keep this as cheap as possible
    // ============================================================

    private void OnPacket(CapturedPacket packet)
    {
        // Accept TCP (protocol 6) for credential extraction + Kerberos,
        // and UDP (protocol 17) only for Kerberos (port 88).
        // Drop everything else before it costs a queue slot.
        if (packet.IpProtocol == 6)
        {
            // TCP: always queue
        }
        else if (packet.IpProtocol == 17 &&
                 (packet.SourcePort == 88 || packet.DestPort == 88))
        {
            // UDP Kerberos: queue for KerberosAnalyzer
        }
        else
        {
            return; // Not relevant — drop
        }

        if (!_channel.Writer.TryWrite(packet))
            Interlocked.Increment(ref _droppedPackets);
    }

    // ============================================================
    // Worker thread — the actual extraction
    // ============================================================

    private async Task WorkerLoopAsync()
    {
        try
        {
            await foreach (CapturedPacket packet in _channel.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                try
                {
                    ProcessPacket(packet);
                    Interlocked.Increment(ref _processedPackets);
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref _processErrors);
                    OnError?.Invoke(ex.Message);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
    }

    private void ProcessPacket(CapturedPacket packet)
    {
        // Kerberos: analyze TCP and UDP port 88 traffic.
        // Runs first because it is self-contained and does not affect other analyzers.
        if (packet.SourcePort == 88 || packet.DestPort == 88)
            _kerberosAnalyzer.Analyze(packet);

        // Non-TCP packets stop here — only Kerberos needed them.
        if (packet.IpProtocol != 6) return;

        // Line-based protocols: per-packet extraction (HTTP branch disabled on this instance).
        _lineExtractor.Analyze(packet);

        // HTTP: reassemble. The reassembler exists only to serve the HTTP parser, so by default
        // we feed it only HTTP-likely ports and skip buffering unrelated flows (443/SSH/SMB/...).
        // Set ReassembleAllTcp to also catch HTTP on non-standard ports, at higher memory cost.
        if (_options.ReassembleAllTcp || IsHttpPort(packet))
            _reassembler.Feed(packet);
    }

    private bool IsHttpPort(CapturedPacket packet)
    {
        ushort serverPort = Math.Min(packet.SourcePort, packet.DestPort);
        return _options.HttpPorts.Contains(serverPort);
    }

    private void Forward(ExtractedCredential cred) => OnCredentialFound?.Invoke(cred);

    private void ForwardResult(ExtractedCredential cred) => OnLoginResult?.Invoke(cred);

    private void ForwardKerberos(KerberosEvent evt) => OnKerberosEvent?.Invoke(evt);

    // ============================================================
    // Results / lifecycle
    // ============================================================

    /// <summary>Merged credentials from both sources.</summary>
    public List<ExtractedCredential> GetAllCredentials()
    {
        var all = new List<ExtractedCredential>();
        all.AddRange(_lineExtractor.GetAllCredentials());
        all.AddRange(_httpParser.GetAllCredentials());
        return all;
    }

    /// <summary>All detected Kerberos security events.</summary>
    public List<KerberosEvent> GetKerberosEvents()
    {
        return _kerberosAnalyzer.GetEvents();
    }

    /// <summary>Reset all buffered credentials, Kerberos events, and reassembly state.</summary>
    public void Clear()
    {
        _lineExtractor.Clear();
        _httpParser.Clear();
        _reassembler.Clear();
        _kerberosAnalyzer.Clear();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _engine.OnPacketCaptured -= OnPacket;

        // Stop accepting packets and let the worker drain what is already queued.
        _channel.Writer.TryComplete();
        try { _worker.Wait(TimeSpan.FromSeconds(5)); }
        catch { /* worker faulted or timed out — nothing more to do */ }

        _reassembler.OnStreamData -= _httpParser.Parse;
        _lineExtractor.OnCredentialFound -= Forward;
        _lineExtractor.OnLoginResult -= ForwardResult;
        _httpParser.OnCredentialFound -= Forward;
        _kerberosAnalyzer.OnKerberosEvent -= ForwardKerberos;
    }
}

/// <summary>
/// Tuning for <see cref="CredentialCaptureCoordinator"/>.
/// </summary>
public sealed class CoordinatorOptions
{
    /// <summary>Max packets buffered between the capture thread and the worker. Overflow is dropped and counted.</summary>
    public int QueueCapacity { get; set; } = 8192;

    /// <summary>Server-side ports treated as HTTP for reassembly routing.</summary>
    public HashSet<ushort> HttpPorts { get; set; } = new() { 80, 8080, 8000, 8888 };

    /// <summary>Feed every TCP packet to the reassembler (catches HTTP on non-standard ports) instead of only <see cref="HttpPorts"/>. Higher memory cost.</summary>
    public bool ReassembleAllTcp { get; set; } = false;
}
