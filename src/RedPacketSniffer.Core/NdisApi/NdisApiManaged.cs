using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace RedPacketSniffer.Core.NdisApi;

/// <summary>
/// Pure C# replacement for ndisapi.dll — calls DeviceIoControl directly to WinpkFilter driver.
/// No C++ build required, no ndisapi.dll dependency.
///
/// REQUIRES: WinpkFilter driver installed + Administrator privileges
/// </summary>
public sealed class NdisApiManaged : IDisposable
{
    // ============================================================
    // Win32 P/Invoke — kernel32.dll (available on all Windows)
    // ============================================================

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        ref NativeOverlapped lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetOverlappedResult(
        SafeFileHandle hFile,
        ref NativeOverlapped lpOverlapped,
        out uint lpNumberOfBytesTransferred,
        bool bWait);

    [DllImport("kernel32.dll")]
    private static extern void RtlZeroMemory(IntPtr dest, int size);

    // Constants
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    private const int ERROR_IO_PENDING = 997;

    // ============================================================
    // IOCTL codes — computed from Common.h CTL_CODE macro
    // CTL_CODE(DeviceType, Function, Method, Access) =
    //   (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
    // FILE_DEVICE_NDISRD = 0x8300, NDISRD_IOCTL_INDEX = 0x830
    // All use METHOD_BUFFERED(0) and FILE_ANY_ACCESS(0)
    // ============================================================

    private const uint FILE_DEVICE_NDISRD = 0x00008300;
    private const uint NDISRD_IOCTL_INDEX = 0x830;

    private static uint CTL_CODE(uint function) =>
        (FILE_DEVICE_NDISRD << 16) | (function << 2);

    // Index 0-9: core operations
    private static readonly uint IOCTL_NDISRD_GET_VERSION = CTL_CODE(NDISRD_IOCTL_INDEX);           // 0
    private static readonly uint IOCTL_NDISRD_GET_TCPIP_INTERFACES = CTL_CODE(NDISRD_IOCTL_INDEX + 1);  // 1
    private static readonly uint IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER = CTL_CODE(NDISRD_IOCTL_INDEX + 2); // 2
    private static readonly uint IOCTL_NDISRD_SEND_PACKET_TO_MSTCP = CTL_CODE(NDISRD_IOCTL_INDEX + 3);  // 3
    private static readonly uint IOCTL_NDISRD_READ_PACKET = CTL_CODE(NDISRD_IOCTL_INDEX + 4);        // 4
    private static readonly uint IOCTL_NDISRD_SET_ADAPTER_MODE = CTL_CODE(NDISRD_IOCTL_INDEX + 5);   // 5
    private static readonly uint IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE = CTL_CODE(NDISRD_IOCTL_INDEX + 6); // 6
    private static readonly uint IOCTL_NDISRD_SET_EVENT = CTL_CODE(NDISRD_IOCTL_INDEX + 7);          // 7
    private static readonly uint IOCTL_NDISRD_NDIS_SET_REQUEST = CTL_CODE(NDISRD_IOCTL_INDEX + 8);   // 8
    private static readonly uint IOCTL_NDISRD_NDIS_GET_REQUEST = CTL_CODE(NDISRD_IOCTL_INDEX + 9);   // 9

    // Index 10-11: WAN and adapter list change events
    private static readonly uint IOCTL_NDISRD_SET_WAN_EVENT = CTL_CODE(NDISRD_IOCTL_INDEX + 10);     // 10
    private static readonly uint IOCTL_NDISRD_SET_ADAPTER_LIST_CHANGE_EVENT = CTL_CODE(NDISRD_IOCTL_INDEX + 11); // 11

    // Index 12-16: adapter queue, mode, and filters
    private static readonly uint IOCTL_NDISRD_ADAPTER_QUEUE_SIZE = CTL_CODE(NDISRD_IOCTL_INDEX + 12); // 12
    private static readonly uint IOCTL_NDISRD_GET_ADAPTER_MODE = CTL_CODE(NDISRD_IOCTL_INDEX + 13);  // 13
    private static readonly uint IOCTL_NDISRD_SET_PACKET_FILTERS = CTL_CODE(NDISRD_IOCTL_INDEX + 14); // 14
    private static readonly uint IOCTL_NDISRD_RESET_PACKET_FILTERS = CTL_CODE(NDISRD_IOCTL_INDEX + 15); // 15
    private static readonly uint IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE = CTL_CODE(NDISRD_IOCTL_INDEX + 16); // 16

    // Index 17-19: filter table retrieval, RAS links
    private static readonly uint IOCTL_NDISRD_GET_PACKET_FILTERS = CTL_CODE(NDISRD_IOCTL_INDEX + 17);          // 17
    private static readonly uint IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS = CTL_CODE(NDISRD_IOCTL_INDEX + 18); // 18
    private static readonly uint IOCTL_NDISRD_GET_RAS_LINKS = CTL_CODE(NDISRD_IOCTL_INDEX + 19);               // 19

    // Index 20-22: batch operations
    private static readonly uint IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER = CTL_CODE(NDISRD_IOCTL_INDEX + 20); // 20
    private static readonly uint IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP = CTL_CODE(NDISRD_IOCTL_INDEX + 21);  // 21
    private static readonly uint IOCTL_NDISRD_READ_PACKETS = CTL_CODE(NDISRD_IOCTL_INDEX + 22);            // 22

    // Index 23-24: Fast I/O
    private static readonly uint IOCTL_NDISRD_INITIALIZE_FAST_IO = CTL_CODE(NDISRD_IOCTL_INDEX + 23);     // 23
    private static readonly uint IOCTL_NDISRD_ADD_SECONDARY_FAST_IO = CTL_CODE(NDISRD_IOCTL_INDEX + 24);  // 24

    // ============================================================
    // Instance state
    // ============================================================

    private readonly SafeFileHandle _driverHandle;
    private uint _bytesReturned;
    private int _lastWin32Error;
    private bool _disposed;

    /// <summary>
    /// True if driver handle opened successfully
    /// </summary>
    public bool IsLoaded => _driverHandle != null && !_driverHandle.IsInvalid && !_driverHandle.IsClosed;

    /// <summary>
    /// Win32 error code of the last IOCTL call — for debugging
    /// </summary>
    public int LastWin32Error => _lastWin32Error;

    // ============================================================
    // Constructor / Dispose
    // ============================================================

    /// <summary>
    /// Open handle to WinpkFilter driver
    /// </summary>
    public NdisApiManaged(string driverName = NdisConst.NDISRD_DRIVER_NAME)
    {
        string fullPath = $"\\\\.\\{driverName}";

        _driverHandle = CreateFile(
            fullPath,
            0, // no specific access needed — DeviceIoControl has its own access control
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            IntPtr.Zero);

        // Save Win32 error immediately after CreateFile — before any other API calls
        if (!IsLoaded)
            _lastWin32Error = Marshal.GetLastWin32Error();
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            _driverHandle?.Dispose();
        }
    }

    // ============================================================
    // Internal DeviceIoControl wrapper — thread-safe
    // Per-call ManualResetEvent avoids shared state race conditions.
    // ============================================================

    private unsafe bool IoControl(uint ioctl, void* inBuf, uint inSize, void* outBuf, uint outSize)
    {
        if (!IsLoaded)
        {
            Volatile.Write(ref _lastWin32Error, -1);
            return false;
        }

        // Per-call event: eliminates race condition when multiple threads call IoControl
        using var ioEvent = new ManualResetEvent(false);

        var overlapped = new NativeOverlapped
        {
            EventHandle = ioEvent.SafeWaitHandle.DangerousGetHandle()
        };

        uint bytesReturned;
        bool result = DeviceIoControl(
            _driverHandle,
            ioctl,
            (IntPtr)inBuf, inSize,
            (IntPtr)outBuf, outSize,
            out bytesReturned,
            ref overlapped);

        if (!result)
        {
            int err = Marshal.GetLastWin32Error();
            if (err == ERROR_IO_PENDING)
            {
                ioEvent.WaitOne();
                result = GetOverlappedResult(_driverHandle, ref overlapped, out bytesReturned, false);
                if (!result)
                    err = Marshal.GetLastWin32Error();
                else
                    err = 0;
            }
            Volatile.Write(ref _lastWin32Error, err);
        }
        else
        {
            Volatile.Write(ref _lastWin32Error, 0);
        }

        Volatile.Write(ref _bytesReturned, bytesReturned);
        return result;
    }

    // ============================================================
    // Driver lifecycle
    // ============================================================

    /// <summary>
    /// Get WinpkFilter driver version (IOCTL-based)
    /// </summary>
    public unsafe uint GetDriverVersion()
    {
        uint version = 0xFFFFFFFF;
        IoControl(IOCTL_NDISRD_GET_VERSION, &version, sizeof(uint), &version, sizeof(uint));
        return version;
    }

    /// <summary>
    /// Get bytes returned from the last IOCTL call
    /// </summary>
    public uint GetBytesReturned() => Volatile.Read(ref _bytesReturned);

    /// <summary>
    /// Check if the WinpkFilter driver file is installed on the system.
    /// Does not require an open driver handle.
    /// </summary>
    /// <param name="fileName">Driver file name without extension (default: "ndisrd")</param>
    /// <returns>true if the .sys file exists in System32\drivers</returns>
    public static bool IsDriverInstalled(string fileName = "ndisrd")
    {
        string filePath = Path.Combine(Environment.SystemDirectory, "drivers", $"{fileName}.sys");
        return File.Exists(filePath);
    }

    /// <summary>
    /// Get the file version of the driver .sys file.
    /// Does not require an open driver handle.
    /// </summary>
    /// <param name="fileName">Driver file name without extension (default: "ndisrd")</param>
    /// <returns>Version of the driver file, or 0.0.0.0 if not found</returns>
    public static Version GetDriverFileVersion(string fileName = "ndisrd")
    {
        string filePath = Path.Combine(Environment.SystemDirectory, "drivers", $"{fileName}.sys");
        if (File.Exists(filePath))
        {
            var versionInfo = FileVersionInfo.GetVersionInfo(filePath);
            if (versionInfo.FileVersion is { } fv)
                return new Version(fv);
        }
        return new Version(0, 0, 0, 0);
    }

    // ============================================================
    // Adapter enumeration
    // ============================================================

    /// <summary>
    /// Get list of active TCP/IP-bound adapters
    /// </summary>
    public unsafe bool GetTcpipBoundAdaptersInfo(ref TCP_AdapterList adapters)
    {
        int size = Marshal.SizeOf<TCP_AdapterList>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            RtlZeroMemory(ptr, size);

            bool result = IoControl(
                IOCTL_NDISRD_GET_TCPIP_INTERFACES,
                (void*)ptr, (uint)size,
                (void*)ptr, (uint)size);
            if (result)
                adapters = Marshal.PtrToStructure<TCP_AdapterList>(ptr);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    // ============================================================
    // Adapter mode & packet event
    // ============================================================

    /// <summary>
    /// Set adapter mode (listen/tunnel/promiscuous)
    /// </summary>
    public unsafe bool SetAdapterMode(ref ADAPTER_MODE mode)
    {
        fixed (ADAPTER_MODE* pMode = &mode)
        {
            return IoControl(
                IOCTL_NDISRD_SET_ADAPTER_MODE,
                pMode, (uint)Marshal.SizeOf<ADAPTER_MODE>(),
                null, 0);
        }
    }

    /// <summary>
    /// Get current adapter mode
    /// </summary>
    public unsafe bool GetAdapterMode(ref ADAPTER_MODE mode)
    {
        fixed (ADAPTER_MODE* pMode = &mode)
        {
            return IoControl(
                IOCTL_NDISRD_GET_ADAPTER_MODE,
                pMode, (uint)Marshal.SizeOf<ADAPTER_MODE>(),
                pMode, (uint)Marshal.SizeOf<ADAPTER_MODE>());
        }
    }

    /// <summary>
    /// Set event for driver to signal when new packets are available.
    /// On Windows NT (10/11), Win32 event handle = Ring0 event handle directly.
    /// </summary>
    public unsafe bool SetPacketEvent(IntPtr hAdapter, SafeWaitHandle hWin32Event)
    {
        var adapterEvent = new AdapterEvent
        {
            hAdapterHandle = hAdapter,
            hEvent = hWin32Event.DangerousGetHandle()
        };

        return IoControl(
            IOCTL_NDISRD_SET_EVENT,
            &adapterEvent, (uint)sizeof(AdapterEvent),
            null, 0);
    }

    /// <summary>
    /// Set WAN event — driver signals when WAN link state changes.
    /// Managed replacement for ndisapi.dll SetWANEvent().
    /// </summary>
    public unsafe bool SetWanEvent(SafeWaitHandle hWin32Event)
    {
        IntPtr eventHandle = hWin32Event.DangerousGetHandle();
        return IoControl(
            IOCTL_NDISRD_SET_WAN_EVENT,
            &eventHandle, (uint)sizeof(IntPtr),
            null, 0);
    }

    /// <summary>
    /// Set adapter list change event — driver signals when adapter list changes
    /// (e.g., network adapter connected/disconnected).
    /// Managed replacement for ndisapi.dll SetAdapterListChangeEvent().
    /// </summary>
    public unsafe bool SetAdapterListChangeEvent(SafeWaitHandle hWin32Event)
    {
        IntPtr eventHandle = hWin32Event.DangerousGetHandle();
        return IoControl(
            IOCTL_NDISRD_SET_ADAPTER_LIST_CHANGE_EVENT,
            &eventHandle, (uint)sizeof(IntPtr),
            null, 0);
    }

    /// <summary>
    /// Flush adapter packet queue
    /// </summary>
    public unsafe bool FlushAdapterPacketQueue(IntPtr hAdapter)
    {
        IntPtr handle = hAdapter;
        return IoControl(
            IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE,
            &handle, (uint)sizeof(IntPtr),
            null, 0);
    }

    /// <summary>
    /// Get number of packets in adapter queue
    /// </summary>
    public unsafe bool GetAdapterPacketQueueSize(IntPtr hAdapter, ref uint pdwSize)
    {
        IntPtr handle = hAdapter;
        uint queueSize = 0;
        bool result = IoControl(
            IOCTL_NDISRD_ADAPTER_QUEUE_SIZE,
            &handle, (uint)sizeof(IntPtr),
            &queueSize, sizeof(uint));
        if (result)
            pdwSize = queueSize;
        return result;
    }

    // ============================================================
    // NDIS OID request — generic query/set operations
    // ============================================================

    /// <summary>
    /// Send an NDIS OID request to the adapter (query or set).
    /// This is the generic interface for reading/writing adapter properties via OID codes.
    /// Managed replacement for ndisapi.dll NdisrdRequest().
    /// </summary>
    /// <param name="hAdapter">Adapter handle</param>
    /// <param name="oid">OID code (e.g., OID_GEN_CURRENT_PACKET_FILTER)</param>
    /// <param name="data">Data buffer for query result or set value</param>
    /// <param name="set">true for SET request, false for GET request</param>
    /// <returns>true if successful</returns>
    public unsafe bool NdisrdRequest(IntPtr hAdapter, uint oid, Span<byte> data, bool set)
    {
        // Guard against integer overflow in size calculation
        if (data.Length > 65535)
            throw new ArgumentOutOfRangeException(nameof(data), "OID data buffer exceeds maximum allowed size (65535 bytes).");

        // Layout: IntPtr hAdapterHandle + uint Oid + uint Length + byte[] Data
        int totalSize = sizeof(IntPtr) + sizeof(uint) + sizeof(uint) + data.Length;
        IntPtr ptr = Marshal.AllocHGlobal(totalSize);
        try
        {
            byte* p = (byte*)ptr;
            *(IntPtr*)p = hAdapter;
            *(uint*)(p + sizeof(IntPtr)) = oid;
            *(uint*)(p + sizeof(IntPtr) + 4) = (uint)data.Length;

            // Copy input data for SET requests
            if (set)
                data.CopyTo(new Span<byte>(p + sizeof(IntPtr) + 8, data.Length));
            else
                RtlZeroMemory((IntPtr)(p + sizeof(IntPtr) + 8), data.Length);

            uint ioctlCode = set ? IOCTL_NDISRD_NDIS_SET_REQUEST : IOCTL_NDISRD_NDIS_GET_REQUEST;
            bool result = IoControl(
                ioctlCode,
                (void*)ptr, (uint)totalSize,
                (void*)ptr, (uint)totalSize);

            // Copy result back for GET requests
            if (result && !set)
                new Span<byte>(p + sizeof(IntPtr) + 8, data.Length).CopyTo(data);

            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Send an NDIS OID request using PACKET_OID_DATA struct pointer.
    /// Low-level overload for callers who manage their own memory layout.
    /// </summary>
    public unsafe bool NdisrdRequest(PACKET_OID_DATA* pOidData, bool set)
    {
        uint totalSize = (uint)(sizeof(IntPtr) + sizeof(uint) + sizeof(uint) + pOidData->Length);
        uint ioctlCode = set ? IOCTL_NDISRD_NDIS_SET_REQUEST : IOCTL_NDISRD_NDIS_GET_REQUEST;
        return IoControl(ioctlCode, pOidData, totalSize, pOidData, totalSize);
    }

    // ============================================================
    // Packet capture / injection
    // ============================================================

    /// <summary>
    /// Read 1 packet from adapter queue. Non-blocking.
    /// </summary>
    public unsafe bool ReadPacket(ref ETH_REQUEST packet)
    {
        if (!IsLoaded) return false;

        int size = Marshal.SizeOf<ETH_REQUEST>();
        fixed (ETH_REQUEST* pPacket = &packet)
        {
            return IoControl(
                IOCTL_NDISRD_READ_PACKET,
                pPacket, (uint)size,
                pPacket, (uint)size);
        }
    }

    /// <summary>
    /// Read batch of packets — significantly higher throughput than ReadPacket one-by-one
    /// </summary>
    public unsafe bool ReadPackets(ref ETH_M_REQUEST packets)
    {
        int size = Marshal.SizeOf<ETH_M_REQUEST>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(packets, ptr, false);
            bool result = IoControl(
                IOCTL_NDISRD_READ_PACKETS,
                (void*)ptr, (uint)size,
                (void*)ptr, (uint)size);
            if (result)
                packets = Marshal.PtrToStructure<ETH_M_REQUEST>(ptr);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Send packet up to TCP/IP stack (simulate packet received from network)
    /// </summary>
    public unsafe bool SendPacketToMstcp(ref ETH_REQUEST packet)
    {
        if (!IsLoaded) return false;
        int size = Marshal.SizeOf<ETH_REQUEST>();
        fixed (ETH_REQUEST* pPacket = &packet)
        {
            return IoControl(
                IOCTL_NDISRD_SEND_PACKET_TO_MSTCP,
                pPacket, (uint)size,
                pPacket, (uint)size);
        }
    }

    /// <summary>
    /// Send packet to adapter (inject raw packet to network)
    /// </summary>
    public unsafe bool SendPacketToAdapter(ref ETH_REQUEST packet)
    {
        if (!IsLoaded) return false;
        int size = Marshal.SizeOf<ETH_REQUEST>();
        fixed (ETH_REQUEST* pPacket = &packet)
        {
            return IoControl(
                IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER,
                pPacket, (uint)size,
                pPacket, (uint)size);
        }
    }

    /// <summary>
    /// Send batch of packets up to TCP/IP stack
    /// </summary>
    public unsafe bool SendPacketsToMstcp(ref ETH_M_REQUEST packets)
    {
        int size = Marshal.SizeOf<ETH_M_REQUEST>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(packets, ptr, false);
            return IoControl(
                IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP,
                (void*)ptr, (uint)size,
                null, 0);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Send batch of packets to adapter
    /// </summary>
    public unsafe bool SendPacketsToAdapter(ref ETH_M_REQUEST packets)
    {
        int size = Marshal.SizeOf<ETH_M_REQUEST>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(packets, ptr, false);
            return IoControl(
                IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER,
                (void*)ptr, (uint)size,
                null, 0);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    // ============================================================
    // Hardware packet filter (promiscuous mode)
    // ============================================================

    private const uint OID_GEN_CURRENT_PACKET_FILTER = 0x0001010E;

    /// <summary>
    /// Set hardware packet filter (promiscuous mode) — uses NDIS OID request
    /// </summary>
    public unsafe bool SetHwPacketFilter(IntPtr hAdapter, uint filter)
    {
        Span<byte> data = stackalloc byte[sizeof(uint)];
        BitConverter.TryWriteBytes(data, filter);
        return NdisrdRequest(hAdapter, OID_GEN_CURRENT_PACKET_FILTER, data, true);
    }

    /// <summary>
    /// Get current hardware packet filter
    /// </summary>
    public unsafe bool GetHwPacketFilter(IntPtr hAdapter, ref uint pFilter)
    {
        Span<byte> data = stackalloc byte[sizeof(uint)];
        bool result = NdisrdRequest(hAdapter, OID_GEN_CURRENT_PACKET_FILTER, data, false);
        if (result)
            pFilter = BitConverter.ToUInt32(data);
        return result;
    }

    // ============================================================
    // Static packet filters
    // ============================================================

    /// <summary>
    /// Set static packet filter table
    /// </summary>
    public unsafe bool SetPacketFilterTable(ref STATIC_FILTER_TABLE filterList)
    {
        int size = Marshal.SizeOf<STATIC_FILTER_TABLE>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(filterList, ptr, false);
            return IoControl(
                IOCTL_NDISRD_SET_PACKET_FILTERS,
                (void*)ptr, (uint)size,
                null, 0);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Reset (clear) all packet filters
    /// </summary>
    public unsafe bool ResetPacketFilterTable()
    {
        return IoControl(IOCTL_NDISRD_RESET_PACKET_FILTERS, null, 0, null, 0);
    }

    /// <summary>
    /// Get the number of filters in the current filter table
    /// </summary>
    public unsafe bool GetPacketFilterTableSize(ref uint pdwTableSize)
    {
        fixed (uint* pSize = &pdwTableSize)
        {
            return IoControl(
                IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE,
                pSize, sizeof(uint),
                pSize, sizeof(uint));
        }
    }

    /// <summary>
    /// Get the current packet filter table with statistics.
    /// Managed replacement for ndisapi.dll GetPacketFilterTable().
    /// Caller must allocate STATIC_FILTER_TABLE with enough room for m_TableSize entries.
    /// </summary>
    public unsafe bool GetPacketFilterTable(ref STATIC_FILTER_TABLE filterTable)
    {
        int size = Marshal.SizeOf<STATIC_FILTER_TABLE>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(filterTable, ptr, false);
            bool result = IoControl(
                IOCTL_NDISRD_GET_PACKET_FILTERS,
                (void*)ptr, (uint)size,
                (void*)ptr, (uint)size);
            if (result)
                filterTable = Marshal.PtrToStructure<STATIC_FILTER_TABLE>(ptr);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Get the current packet filter table and reset statistics counters.
    /// Managed replacement for ndisapi.dll GetPacketFilterTableResetStats().
    /// </summary>
    public unsafe bool GetPacketFilterTableResetStats(ref STATIC_FILTER_TABLE filterTable)
    {
        int size = Marshal.SizeOf<STATIC_FILTER_TABLE>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(filterTable, ptr, false);
            bool result = IoControl(
                IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS,
                (void*)ptr, (uint)size,
                (void*)ptr, (uint)size);
            if (result)
                filterTable = Marshal.PtrToStructure<STATIC_FILTER_TABLE>(ptr);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    // ============================================================
    // RAS (Remote Access Service) Links — WAN interface support
    // ============================================================

    /// <summary>
    /// Get RAS links for a WAN adapter.
    /// Managed replacement for ndisapi.dll GetRasLinks().
    /// </summary>
    public unsafe bool GetRasLinks(IntPtr hAdapter, ref RAS_LINKS rasLinks)
    {
        int size = Marshal.SizeOf<RAS_LINKS>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            RtlZeroMemory(ptr, size);

            // Input: adapter handle. Output: RAS_LINKS struct
            // The IOCTL expects the adapter handle followed by the output buffer
            // For simplicity, pass adapter handle as part of input, result in output
            IntPtr handle = hAdapter;
            bool result = IoControl(
                IOCTL_NDISRD_GET_RAS_LINKS,
                &handle, (uint)sizeof(IntPtr),
                (void*)ptr, (uint)size);
            if (result)
                rasLinks = Marshal.PtrToStructure<RAS_LINKS>(ptr);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    // ============================================================
    // Fast I/O — shared memory for high-performance packet transfer
    // ============================================================

    /// <summary>
    /// Initialize Fast I/O shared memory section with the driver.
    /// After successful initialization, packets can be exchanged via shared memory
    /// instead of DeviceIoControl for better performance.
    /// Managed replacement for ndisapi.dll InitializeFastIo().
    /// </summary>
    /// <param name="pFastIoSection">Pointer to allocated and zeroed FAST_IO_SECTION memory</param>
    /// <param name="dwSize">Total size of the allocated memory in bytes</param>
    /// <returns>true if driver accepted the shared memory section</returns>
    public unsafe bool InitializeFastIo(IntPtr pFastIoSection, uint dwSize)
    {
        return IoControl(
            IOCTL_NDISRD_INITIALIZE_FAST_IO,
            (void*)pFastIoSection, dwSize,
            (void*)pFastIoSection, dwSize);
    }

    /// <summary>
    /// Add a secondary Fast I/O section for additional throughput.
    /// Managed replacement for ndisapi.dll AddSecondaryFastIo().
    /// </summary>
    /// <param name="pFastIoSection">Pointer to allocated and zeroed FAST_IO_SECTION memory</param>
    /// <param name="dwSize">Total size of the allocated memory in bytes</param>
    /// <returns>true if driver accepted the secondary section</returns>
    public unsafe bool AddSecondaryFastIo(IntPtr pFastIoSection, uint dwSize)
    {
        return IoControl(
            IOCTL_NDISRD_ADD_SECONDARY_FAST_IO,
            (void*)pFastIoSection, dwSize,
            (void*)pFastIoSection, dwSize);
    }

    // ============================================================
    // Adapter startup mode — Registry-based, no driver handle needed
    // ============================================================

    private const string NDISRD_STARTUP_REG_KEY = @"SYSTEM\CurrentControlSet\Services\ndisrd\Parameters";
    private const string NDISRD_STARTUP_MODE_VALUE = "StartupMode";

    /// <summary>
    /// Get adapters startup mode from Registry.
    /// This is the mode applied to all adapters when the driver loads.
    /// Managed replacement for ndisapi.dll GetAdaptersStartupMode().
    /// </summary>
    /// <returns>Startup mode flags, or 0 if not set</returns>
    public static uint GetAdaptersStartupMode()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(NDISRD_STARTUP_REG_KEY, false);
            object? val = key?.GetValue(NDISRD_STARTUP_MODE_VALUE);
            if (val is int intVal)
                return (uint)intVal;
        }
        catch { }
        return 0;
    }

    /// <summary>
    /// Set adapters startup mode in Registry.
    /// Managed replacement for ndisapi.dll SetAdaptersStartupMode().
    /// </summary>
    /// <param name="startupMode">Mode flags (use NdisConst.MSTCP_FLAG_* values)</param>
    /// <returns>true if Registry write succeeded</returns>
    public static bool SetAdaptersStartupMode(uint startupMode)
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(NDISRD_STARTUP_REG_KEY, true);
            key.SetValue(NDISRD_STARTUP_MODE_VALUE, (int)startupMode, RegistryValueKind.DWord);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ============================================================
    // Adapter name conversion — Registry-based, no C++ dependency
    // ============================================================

    private const string REGSTR_NETWORK_CONTROL_KEY =
        @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\";

    /// <summary>
    /// Convert internal adapter name (GUID) to friendly display name shown in Windows.
    /// Read from Registry — equivalent to ConvertWindows2000AdapterName in ndisapi.cpp
    /// </summary>
    public static string? ConvertAdapterName(string internalName)
    {
        // Handle WAN interfaces
        if (internalName.Contains("NDISWANIP", StringComparison.OrdinalIgnoreCase))
            return "WAN Network Interface (IP)";
        if (internalName.Contains("NDISWANBH", StringComparison.OrdinalIgnoreCase))
            return "WAN Network Interface (BH)";
        if (internalName.Contains("NDISWANIPV6", StringComparison.OrdinalIgnoreCase))
            return "WAN Network Interface (IPv6)";

        // Extract GUID from internal name: "\Device\{GUID}" -> "{GUID}"
        string guid = internalName;
        const string devicePrefix = "\\Device\\";
        if (guid.StartsWith(devicePrefix, StringComparison.OrdinalIgnoreCase))
            guid = guid[devicePrefix.Length..];

        // Read friendly name from Registry
        string regPath = $"{REGSTR_NETWORK_CONTROL_KEY}{guid}\\Connection";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(regPath, false);
            return key?.GetValue("Name") as string;
        }
        catch
        {
            return null;
        }
    }

    // ============================================================
    // MTU — read/write from Registry
    // ============================================================

    private const string NDISRD_REG_KEY = @"SYSTEM\CurrentControlSet\Services\ndisrd";

    /// <summary>
    /// Get current MTU decrement from Registry
    /// </summary>
    public static uint GetMTUDecrement()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(NDISRD_REG_KEY, false);
            object? val = key?.GetValue("MTUDecrement");
            if (val is int intVal)
                return (uint)intVal;
        }
        catch { }
        return 0;
    }

    /// <summary>
    /// Set MTU decrement in Registry
    /// </summary>
    public static bool SetMTUDecrement(uint dwMTUDecrement)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(NDISRD_REG_KEY, true);
            if (key == null) return false;
            key.SetValue("MTUDecrement", (int)dwMTUDecrement, RegistryValueKind.DWord);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ============================================================
    // Internal structs
    // ============================================================

    [StructLayout(LayoutKind.Sequential)]
    private struct AdapterEvent
    {
        public IntPtr hAdapterHandle;
        public IntPtr hEvent;
    }
}
