using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace RedPacketSniffer.Core.NdisApi;

/// <summary>
/// P/Invoke bindings for ndisapi.dll — native Win32 DLL wrapper of WinpkFilter.
///
/// ndisapi.dll must be in the same directory as the exe or in PATH.
/// Download from: https://github.com/wiresock/ndisapi/tree/master/ndisapi.dll
/// Select the correct platform: x64, x86, or ARM64.
///
/// REQUIREMENTS: WinpkFilter driver installed + running as Administrator.
///
/// NOTE: Most functions in this file have managed equivalents in NdisApiManaged.cs
/// that call DeviceIoControl directly, avoiding the ndisapi.dll dependency.
/// Use this class only for functions that require the DLL (adapter name conversion,
/// filter table operations via pointer, unsorted packet APIs, etc.).
/// </summary>
public static unsafe class NdisApiNative
{
    private const string DLL_NAME = "ndisapi.dll";

    // ============================================================
    // Driver lifecycle
    // ============================================================

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr OpenFilterDriver(byte[] pszFileName);

    /// <summary>
    /// Opens a handle to the WinpkFilter driver. Returns IntPtr.Zero on failure.
    /// </summary>
    public static IntPtr OpenFilterDriver(string driverName = NdisConst.NDISRD_DRIVER_NAME)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(driverName + '\0');
        return OpenFilterDriver(nameBytes);
    }

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern void CloseFilterDriver(IntPtr hOpen);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool IsDriverLoaded(IntPtr hOpen);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern uint GetDriverVersion(IntPtr hOpen);

    // ============================================================
    // Adapter enumeration
    // ============================================================

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool GetTcpipBoundAdaptersInfo(IntPtr hOpen, ref TCP_AdapterList adapters);

    // ============================================================
    // Adapter mode & packet event
    // ============================================================

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SetAdapterMode(IntPtr hOpen, ref ADAPTER_MODE mode);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool GetAdapterMode(IntPtr hOpen, ref ADAPTER_MODE mode);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SetPacketEvent(IntPtr hOpen, IntPtr hAdapter, SafeWaitHandle hWin32Event);

    /// <summary>
    /// SetPacketEvent overload accepting raw IntPtr event handle.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SetPacketEvent(IntPtr hOpen, IntPtr hAdapter, IntPtr hEvent);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool FlushAdapterPacketQueue(IntPtr hOpen, IntPtr hAdapter);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool GetAdapterPacketQueueSize(IntPtr hOpen, IntPtr hAdapter, ref uint pdwSize);

    // ============================================================
    // WAN & adapter list change events
    // ============================================================

    /// <summary>
    /// Sets an event to be signaled when a WAN link state changes.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SetWANEvent(IntPtr hOpen, SafeWaitHandle hWin32Event);

    /// <summary>
    /// Sets an event to be signaled when the adapter list changes
    /// (adapter added/removed, enabled/disabled).
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SetAdapterListChangeEvent(IntPtr hOpen, SafeWaitHandle hWin32Event);

    // ============================================================
    // RAS links (WAN interfaces)
    // ============================================================

    /// <summary>
    /// Gets the RAS link information for a WAN adapter.
    /// pLinks must point to a RAS_LINKS-sized buffer.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool GetRasLinks(IntPtr hOpen, IntPtr hAdapter, IntPtr pLinks);

    // ============================================================
    // Packet capture / injection — single packet
    // ============================================================

    /// <summary>
    /// Reads one packet from the adapter queue. Non-blocking — returns false if empty.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool ReadPacket(IntPtr hOpen, ref ETH_REQUEST packet);

    /// <summary>
    /// Sends a packet up to the TCP/IP stack (simulates receiving a packet from the network).
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SendPacketToMstcp(IntPtr hOpen, ref ETH_REQUEST packet);

    /// <summary>
    /// Sends a packet out through the adapter (injects a raw packet onto the wire).
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SendPacketToAdapter(IntPtr hOpen, ref ETH_REQUEST packet);

    // ============================================================
    // Packet capture / injection — batch
    // ============================================================

    /// <summary>
    /// Reads a batch of packets. Higher throughput than ReadPacket.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool ReadPackets(IntPtr hOpen, ref ETH_M_REQUEST packets);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SendPacketsToMstcp(IntPtr hOpen, ref ETH_M_REQUEST packets);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SendPacketsToAdapter(IntPtr hOpen, ref ETH_M_REQUEST packets);

    // ============================================================
    // Packet capture / injection — unsorted (Fast I/O compatible)
    // Each INTERMEDIATE_BUFFER has its own adapter handle (m_hAdapter).
    // ============================================================

    /// <summary>
    /// Reads packets from multiple adapters in a single call.
    /// Each INTERMEDIATE_BUFFER must have its AdapterHandle set.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool ReadPacketsUnsorted(
        IntPtr hOpen, IntPtr[] packets, uint dwPacketsNum, ref uint pdwPacketsSuccess);

    /// <summary>
    /// Sends packets to their respective adapters (each buffer specifies its own adapter).
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SendPacketsToAdaptersUnsorted(
        IntPtr hOpen, IntPtr[] packets, uint dwPacketsNum, ref uint pdwPacketsSuccess);

    /// <summary>
    /// Sends packets to MSTCP, each routed to the adapter specified in the buffer.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SendPacketsToMstcpUnsorted(
        IntPtr hOpen, IntPtr[] packets, uint dwPacketsNum, ref uint pdwPacketsSuccess);

    // ============================================================
    // NDIS OID requests
    // ============================================================

    /// <summary>
    /// Sends an NDIS OID request (query or set) through the driver.
    /// set=false for query, set=true for set operation.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool NdisrdRequest(IntPtr hOpen, ref PACKET_OID_DATA oidData, bool set);

    /// <summary>
    /// NdisrdRequest overload with raw pointer for variable-length OID data.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool NdisrdRequest(IntPtr hOpen, PACKET_OID_DATA* oidData, bool set);

    // ============================================================
    // Hardware packet filter (promiscuous mode via OID)
    // ============================================================

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SetHwPacketFilter(IntPtr hOpen, IntPtr hAdapter, NDIS_PACKET_TYPE filter);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool GetHwPacketFilter(IntPtr hOpen, IntPtr hAdapter, ref NDIS_PACKET_TYPE pFilter);

    /// <summary>Legacy overload accepting raw uint filter value.</summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, EntryPoint = "SetHwPacketFilter")]
    public static extern bool SetHwPacketFilterRaw(IntPtr hOpen, IntPtr hAdapter, uint filter);

    /// <summary>Legacy overload returning raw uint filter value.</summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetHwPacketFilter")]
    public static extern bool GetHwPacketFilterRaw(IntPtr hOpen, IntPtr hAdapter, ref uint pFilter);

    // ============================================================
    // Static packet filters
    // ============================================================

    /// <summary>
    /// Sets the static packet filter table in the driver.
    /// Uses pointer to support variable-length filter arrays.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SetPacketFilterTable(IntPtr hOpen, STATIC_FILTER_TABLE* pFilterList);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool ResetPacketFilterTable(IntPtr hOpen);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool GetPacketFilterTableSize(IntPtr hOpen, ref uint pdwTableSize);

    /// <summary>
    /// Retrieves the current static filter table from the driver.
    /// Buffer must be pre-allocated to hold the entire table.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool GetPacketFilterTable(IntPtr hOpen, STATIC_FILTER_TABLE* pFilterList);

    /// <summary>
    /// Retrieves the current filter table and resets per-filter statistics counters.
    /// Useful for periodic stats collection without losing filter rules.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool GetPacketFilterTableResetStats(IntPtr hOpen, STATIC_FILTER_TABLE* pFilterList);

    // ============================================================
    // Fast I/O — shared memory for high-performance packet exchange
    // ============================================================

    /// <summary>
    /// Initializes a Fast I/O shared memory section for an adapter.
    /// pFastIo points to a memory region large enough for the header + N INTERMEDIATE_BUFFERs.
    /// dwSize is the total byte size of the allocated section.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool InitializeFastIo(IntPtr hOpen, FAST_IO_SECTION* pFastIo, uint dwSize);

    /// <summary>
    /// Adds a secondary Fast I/O section for additional throughput.
    /// Same parameters as InitializeFastIo.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool AddSecondaryFastIo(IntPtr hOpen, FAST_IO_SECTION* pFastIo, uint dwSize);

    // ============================================================
    // Adapter startup mode
    // ============================================================

    /// <summary>
    /// Gets the default adapter mode applied at driver startup (before any user-mode app connects).
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern MSTCP_FLAGS GetAdaptersStartupMode();

    /// <summary>
    /// Sets the default adapter mode applied at driver startup.
    /// Persists across reboots until changed.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SetAdaptersStartupMode(MSTCP_FLAGS dwStartupMode);

    // ============================================================
    // Adapter name conversion
    // ============================================================

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    private static extern bool ConvertWindows2000AdapterName(
        byte* szAdapterName, byte* szUserFriendlyName, uint dwUserFriendlyNameLength);

    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    private static extern bool ConvertWindowsNTAdapterName(
        byte* szAdapterName, byte* szUserFriendlyName, uint dwUserFriendlyNameLength);

    /// <summary>
    /// Converts an internal adapter name (GUID path) to a user-friendly display name.
    /// Uses the Windows 2000+ API; falls back to WindowsNT API on failure.
    /// Returns null if conversion fails.
    /// </summary>
    public static string? ConvertAdapterName(string internalName)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(internalName + '\0');
        byte[] friendlyName = new byte[NdisConst.ADAPTER_NAME_SIZE];

        fixed (byte* pName = nameBytes)
        fixed (byte* pFriendly = friendlyName)
        {
            bool success = ConvertWindows2000AdapterName(pName, pFriendly, (uint)friendlyName.Length);

            if (!success)
                success = ConvertWindowsNTAdapterName(pName, pFriendly, (uint)friendlyName.Length);

            if (success)
            {
                int nullIdx = Array.IndexOf<byte>(friendlyName, 0);
                if (nullIdx < 0) nullIdx = friendlyName.Length;
                return Encoding.Default.GetString(friendlyName, 0, nullIdx);
            }
        }
        return null;
    }

    // ============================================================
    // Misc
    // ============================================================

    /// <summary>
    /// Gets the MTU decrement value applied by the driver.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern uint GetMTUDecrement();

    /// <summary>
    /// Sets the MTU decrement value. Used to accommodate protocol headers
    /// added by tunneling or encapsulation without fragmenting.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern bool SetMTUDecrement(uint dwMTUDecrement);

    /// <summary>
    /// Gets the number of bytes returned by the last DeviceIoControl call.
    /// </summary>
    [DllImport(DLL_NAME, CallingConvention = CallingConvention.StdCall)]
    public static extern uint GetBytesReturned(IntPtr hOpen);
}
