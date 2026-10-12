using System.Runtime.InteropServices;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;
using RedPacketSniffer.Core.NdisApi;

namespace RedPacketSniffer.Core.Capture;

/// <summary>
/// Engine capture packet sử dụng WinpkFilter NDIS API (pure C# — không cần ndisapi.dll)
///
/// Workflow:
/// 1. Open driver → GetAdapters → SelectAdapter
/// 2. SetFilter (optional)
/// 3. StartCapture → event loop đọc packet → fire OnPacketCaptured
/// 4. StopCapture → Cleanup
///
/// Chạy ở LISTEN mode (không chặn traffic) — phù hợp cho passive sniffing
/// Có thể chuyển sang TUNNEL mode nếu cần modify/inject packet
/// </summary>
public sealed class PacketCaptureEngine : IDisposable
{
    private NdisApiManaged? _ndisApi;
    private TCP_AdapterList _adapterList;
    private int _selectedAdapter = -1;
    private CancellationTokenSource? _captureCts;
    private Task? _captureTask;
    private CaptureFilter _filter = new();
    private uint _originalHwFilter = 0;
    private bool _promiscuousSet = false;
    private bool _disposed = false;

    // Stats
    private long _totalPackets = 0;
    private long _filteredPackets = 0;
    private long _totalBytes = 0;
    private DateTime _captureStartTime;

    /// <summary>
    /// Fired khi capture được 1 packet (đã qua filter)
    /// </summary>
    public event Action<CapturedPacket>? OnPacketCaptured;

    /// <summary>
    /// Fired khi có error trong capture loop
    /// </summary>
    public event Action<string>? OnError;

    /// <summary>
    /// Fired khi capture state thay đổi
    /// </summary>
    public event Action<CaptureState>? OnStateChanged;

    public CaptureState State { get; private set; } = CaptureState.Idle;
    public bool IsDriverLoaded => _ndisApi?.IsLoaded == true;
    public long TotalPackets => _totalPackets;
    public long FilteredPackets => _filteredPackets;
    public long TotalBytes => _totalBytes;
    public TimeSpan CaptureElapsed => State == CaptureState.Capturing
        ? DateTime.UtcNow - _captureStartTime
        : TimeSpan.Zero;

    // ============================================================
    // Initialization
    // ============================================================

    /// <summary>
    /// Mở kết nối tới WinpkFilter driver
    /// </summary>
    public DriverInfo Open()
    {
        if (_ndisApi != null)
            throw new InvalidOperationException("Driver already opened");

        _ndisApi = new NdisApiManaged();

        if (!_ndisApi.IsLoaded)
        {
            int err = _ndisApi.LastWin32Error;
            _ndisApi.Dispose();
            _ndisApi = null;
            throw new InvalidOperationException(
                $"Không thể load WinpkFilter driver (Win32 Error: {err}). Kiểm tra:\n" +
                "1. WinpkFilter driver đã cài (https://www.ntkernel.com/windows-packet-filter/)\n" +
                "2. Đang chạy với quyền Administrator");
        }

        uint version = _ndisApi.GetDriverVersion();
        SetState(CaptureState.Ready);

        return new DriverInfo
        {
            Version = $"{(version >> 24) & 0xFF}.{(version >> 16) & 0xFF}.{(version >> 8) & 0xFF}.{version & 0xFF}"
        };
    }

    /// <summary>
    /// Liệt kê tất cả network adapter đang bound với TCP/IP
    /// </summary>
    public List<AdapterInfo> GetAdapters()
    {
        EnsureDriverOpen();

        _adapterList = new TCP_AdapterList();
        bool result = _ndisApi!.GetTcpipBoundAdaptersInfo(ref _adapterList);
        if (!result)
        {
            throw new InvalidOperationException(
                $"GetTcpipBoundAdaptersInfo thất bại. Win32 Error: {_ndisApi.LastWin32Error}. " +
                "Kiểm tra: WinpkFilter driver đang chạy, quyền Administrator.");
        }

        var adapters = new List<AdapterInfo>();
        for (int i = 0; i < _adapterList.m_nAdapterCount; i++)
        {
            string internalName = _adapterList.GetInternalName(i);
            string? friendlyName = NdisApiManaged.ConvertAdapterName(internalName);
            string mac = _adapterList.GetMacAddressString(i);
            ushort mtu = _adapterList.m_usMTU[i];

            // Bỏ qua WAN Miniport adapters (thường không cần capture)
            bool isWan = internalName.Contains("NDISWANIP", StringComparison.OrdinalIgnoreCase)
                      || internalName.Contains("NDISWANBH", StringComparison.OrdinalIgnoreCase);

            adapters.Add(new AdapterInfo
            {
                Index = i,
                InternalName = internalName,
                FriendlyName = friendlyName ?? internalName,
                MacAddress = mac,
                MTU = mtu,
                Handle = _adapterList.m_nAdapterHandle[i],
                Medium = _adapterList.m_nAdapterMediumList[i],
                IsWanAdapter = isWan
            });
        }

        return adapters;
    }

    /// <summary>
    /// Chọn adapter để capture
    /// </summary>
    public void SelectAdapter(int adapterIndex)
    {
        EnsureDriverOpen();
        if (adapterIndex < 0 || adapterIndex >= _adapterList.m_nAdapterCount)
            throw new ArgumentOutOfRangeException(nameof(adapterIndex));
        _selectedAdapter = adapterIndex;
    }

    /// <summary>
    /// Đặt filter cho capture session
    /// </summary>
    public void SetFilter(CaptureFilter filter)
    {
        _filter = filter ?? new CaptureFilter();
    }

    // ============================================================
    // Capture control
    // ============================================================

    /// <summary>
    /// Bắt đầu capture packet từ adapter đã chọn
    /// Listen mode: packet vẫn đi bình thường, chỉ lấy bản sao
    /// </summary>
    public void StartCapture()
    {
        EnsureDriverOpen();
        if (_selectedAdapter < 0)
            throw new InvalidOperationException("Chưa chọn adapter. Gọi SelectAdapter() trước.");
        if (State == CaptureState.Capturing)
            throw new InvalidOperationException("Đang capture rồi.");

        // Reset stats
        Interlocked.Exchange(ref _totalPackets, 0);
        Interlocked.Exchange(ref _filteredPackets, 0);
        Interlocked.Exchange(ref _totalBytes, 0);
        PacketParser.ResetCounter();
        _captureStartTime = DateTime.UtcNow;

        IntPtr adapterHandle = _adapterList.m_nAdapterHandle[_selectedAdapter];

        // Set promiscuous mode nếu được yêu cầu
        if (_filter.Promiscuous)
        {
            _ndisApi!.GetHwPacketFilter(adapterHandle, ref _originalHwFilter);
            if (_ndisApi!.SetHwPacketFilter(adapterHandle, NdisConst.NDIS_PACKET_TYPE_PROMISCUOUS))
            {
                _promiscuousSet = true;
            }
        }

        // Set adapter mode: LISTEN (không chặn traffic)
        var mode = new ADAPTER_MODE
        {
            hAdapterHandle = adapterHandle,
            dwFlags = NdisConst.MSTCP_FLAG_SENT_LISTEN | NdisConst.MSTCP_FLAG_RECV_LISTEN
        };

        if (_filter.Promiscuous)
        {
            mode.dwFlags |= NdisConst.MSTCP_FLAG_FILTER_DIRECT | NdisConst.MSTCP_FLAG_LOOPBACK_BLOCK;
        }

        _ndisApi!.SetAdapterMode(ref mode);

        // Start capture thread
        _captureCts = new CancellationTokenSource();
        _captureTask = Task.Run(() => CaptureLoop(adapterHandle, _captureCts.Token));

        SetState(CaptureState.Capturing);
    }

    /// <summary>
    /// Dừng capture
    /// </summary>
    public async Task StopCaptureAsync()
    {
        if (State != CaptureState.Capturing || _captureCts == null)
            return;

        _captureCts.Cancel();

        if (_captureTask != null)
        {
            try { await _captureTask; }
            catch (OperationCanceledException) { }
        }

        IntPtr adapterHandle = _adapterList.m_nAdapterHandle[_selectedAdapter];

        // Restore adapter mode
        var mode = new ADAPTER_MODE
        {
            hAdapterHandle = adapterHandle,
            dwFlags = 0
        };
        _ndisApi!.SetAdapterMode(ref mode);

        // Flush queue
        _ndisApi!.FlushAdapterPacketQueue(adapterHandle);

        // Restore hardware filter
        if (_promiscuousSet)
        {
            _ndisApi!.SetHwPacketFilter(adapterHandle, _originalHwFilter);
            _promiscuousSet = false;
        }

        _captureCts.Dispose();
        _captureCts = null;
        _captureTask = null;

        SetState(CaptureState.Ready);
    }

    // ============================================================
    // Capture loop
    // ============================================================

    private void CaptureLoop(IntPtr adapterHandle, CancellationToken ct)
    {
        // Allocate unmanaged buffer cho packet read
        var buffer = new INTERMEDIATE_BUFFER();
        int bufferSize = Marshal.SizeOf<INTERMEDIATE_BUFFER>();
        IntPtr bufferPtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            // Tạo Win32 event cho packet notification — hiệu quả hơn polling
            using var packetEvent = new ManualResetEvent(false);
            _ndisApi!.SetPacketEvent(adapterHandle, packetEvent.SafeWaitHandle);

            var request = new ETH_REQUEST
            {
                hAdapterHandle = adapterHandle,
                EthPacket = new NDISRD_ETH_Packet { Buffer = bufferPtr }
            };

            while (!ct.IsCancellationRequested)
            {
                // Chờ packet event — timeout 500ms để check cancellation
                packetEvent.WaitOne(500);

                // Đọc hết packet trong queue
                while (!ct.IsCancellationRequested && _ndisApi!.ReadPacket(ref request))
                {
                    Interlocked.Increment(ref _totalPackets);

                    // Marshal unmanaged → managed
                    buffer = Marshal.PtrToStructure<INTERMEDIATE_BUFFER>(bufferPtr);
                    Interlocked.Add(ref _totalBytes, buffer.m_Length);

                    // Parse
                    CapturedPacket packet;
                    try
                    {
                        packet = PacketParser.Parse(buffer);
                    }
                    catch
                    {
                        continue; // Skip malformed packet
                    }

                    // Apply filter
                    if (!_filter.Matches(packet))
                        continue;

                    Interlocked.Increment(ref _filteredPackets);

                    // Fire event
                    try
                    {
                        OnPacketCaptured?.Invoke(packet);
                    }
                    catch (Exception ex)
                    {
                        OnError?.Invoke($"Error in packet handler: {ex.Message}");
                    }

                    // Check max packets
                    if (_filter.MaxPackets > 0 && _filteredPackets >= _filter.MaxPackets)
                    {
                        return;
                    }

                    // Check max bytes
                    if (_filter.MaxBytes > 0 && _totalBytes >= _filter.MaxBytes)
                    {
                        return;
                    }
                }

                packetEvent.Reset();
            }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            OnError?.Invoke($"Capture error: {ex.Message}");
        }
        finally
        {
            Marshal.FreeHGlobal(bufferPtr);
        }
    }

    // ============================================================
    // Raw Packet Injection (cho ARP spoofing, etc.)
    // ============================================================

    /// <summary>
    /// Gửi raw Ethernet frame ra mạng qua adapter đang chọn.
    /// Frame phải là complete Ethernet frame (14 bytes header + payload).
    /// Yêu cầu: driver đã mở, adapter đã chọn.
    ///
    /// NOTE: INTERMEDIATE_BUFFER.m_IBuffer là fixed-size buffer (không phải managed array),
    /// nên phải dùng unsafe + Marshal.Copy để ghi dữ liệu vào.
    /// </summary>
    public unsafe bool SendRawPacket(byte[] frameData)
    {
        EnsureDriverOpen();
        if (_selectedAdapter < 0)
            throw new InvalidOperationException("Chưa chọn adapter.");
        if (frameData.Length < 14 || frameData.Length > NdisConst.MAX_ETHER_FRAME)
            throw new ArgumentException($"Frame size phải từ 14 đến {NdisConst.MAX_ETHER_FRAME} bytes.");

        IntPtr adapterHandle = _adapterList.m_nAdapterHandle[_selectedAdapter];

        // Allocate unmanaged INTERMEDIATE_BUFFER — m_IBuffer is a fixed-size buffer,
        // cannot use object initializer or Array.Copy
        int bufferSize = sizeof(INTERMEDIATE_BUFFER);
        IntPtr bufferPtr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            // Zero entire buffer first
            new Span<byte>((void*)bufferPtr, bufferSize).Clear();

            // Set header fields via pointer
            var buffer = (INTERMEDIATE_BUFFER*)bufferPtr;
            buffer->m_dwDeviceFlags = NdisConst.PACKET_FLAG_ON_SEND;
            buffer->m_Length = (uint)frameData.Length;

            // Copy frame data into fixed-size m_IBuffer using Marshal.Copy
            Marshal.Copy(frameData, 0, (IntPtr)buffer->m_IBuffer, frameData.Length);

            var request = new ETH_REQUEST
            {
                hAdapterHandle = adapterHandle,
                EthPacket = new NDISRD_ETH_Packet { Buffer = bufferPtr }
            };
            return _ndisApi!.SendPacketToAdapter(ref request);
        }
        finally
        {
            Marshal.FreeHGlobal(bufferPtr);
        }
    }

    /// <summary>
    /// Lấy MAC address của adapter đang chọn
    /// </summary>
    public byte[] GetSelectedAdapterMac()
    {
        if (_selectedAdapter < 0)
            throw new InvalidOperationException("Chưa chọn adapter.");
        return _adapterList.GetMacAddress(_selectedAdapter);
    }

    /// <summary>
    /// Lấy MAC address string của adapter đang chọn
    /// </summary>
    public string GetSelectedAdapterMacString()
    {
        if (_selectedAdapter < 0)
            throw new InvalidOperationException("Chưa chọn adapter.");
        return _adapterList.GetMacAddressString(_selectedAdapter);
    }

    /// <summary>
    /// Lấy adapter handle hiện tại (cho external modules cần inject trực tiếp)
    /// </summary>
    public IntPtr GetSelectedAdapterHandle()
    {
        if (_selectedAdapter < 0)
            throw new InvalidOperationException("Chưa chọn adapter.");
        return _adapterList.m_nAdapterHandle[_selectedAdapter];
    }

    // ============================================================
    // Helpers
    // ============================================================

    private void EnsureDriverOpen()
    {
        if (_ndisApi == null || !_ndisApi.IsLoaded)
            throw new InvalidOperationException("Driver chưa mở. Gọi Open() trước.");
    }

    private void SetState(CaptureState state)
    {
        State = state;
        OnStateChanged?.Invoke(state);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (State == CaptureState.Capturing)
        {
            _captureCts?.Cancel();
            _captureTask?.Wait(TimeSpan.FromSeconds(3));
        }

        _ndisApi?.Dispose();
        _ndisApi = null;

        _captureCts?.Dispose();
    }
}

public enum CaptureState
{
    Idle,
    Ready,      // Driver loaded, adapter listed
    Capturing,  // Đang capture
    Error
}

public class DriverInfo
{
    public string Version { get; init; } = "";
}

public class AdapterInfo
{
    public int Index { get; init; }
    public string InternalName { get; init; } = "";
    public string FriendlyName { get; init; } = "";
    public string MacAddress { get; init; } = "";
    public ushort MTU { get; init; }
    [JsonIgnore]
    public IntPtr Handle { get; init; }
    [JsonIgnore]
    public uint Medium { get; init; }
    public bool IsWanAdapter { get; init; }

    /// <summary>Medium type text</summary>
    public string MediumStr => Medium switch
    {
        0 => "Ethernet (802.3)",
        1 => "Token Ring (802.5)",
        8 => "WAN",
        _ => $"Medium({Medium})"
    };
}
