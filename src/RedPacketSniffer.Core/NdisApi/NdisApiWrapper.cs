using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace RedPacketSniffer.Core.NdisApi;

/// <summary>
/// High-level wrapper over NdisApiManaged providing:
/// - Factory methods for creating pinned NDIS buffers (zero-copy kernel I/O)
/// - Object lifecycle: Clone / Zero / Dispose for buffer management
/// - Auto-routing SendPackets (splits by direction: adapter vs MSTCP)
/// - SendPacketsUnsorted with ArrayPool for batch operations
/// - Fast I/O shared memory lifecycle management
/// - Network adapter enumeration
///
/// Thread safety: all mutable state is protected by lock.
///
/// SECURITY NOTES:
/// - All factory methods validate input parameters
/// - Fast I/O prevents reinitialization to avoid double-free
/// - Dispose releases all resources including pinned arrays and unmanaged memory
/// - ArrayPool buffers are returned in finally blocks to prevent leaks
/// </summary>
#if NETCOREAPP
[SkipLocalsInit]
#endif
public unsafe class NdisApiWrapper : IDisposable
{
    // ============================================================
    // Win32 P/Invoke — needed for memory operations
    // ============================================================

    [DllImport("kernel32.dll")]
    private static extern void RtlMoveMemory(IntPtr dest, IntPtr src, uint length);

    [DllImport("kernel32.dll")]
    private static extern void RtlZeroMemory(IntPtr dest, int size);

    // ============================================================
    // Constants
    // ============================================================

    /// <summary>Default batch size for pre-allocated send request buffers.</summary>
    private const int DefaultBatchPacketCount = 256;

    // ============================================================
    // Instance state
    // ============================================================

    private readonly NdisApiManaged _api;
    private readonly bool _ownsApi;
    private readonly PinnedManagedArrayAllocator<byte> _allocator;
    private readonly ArrayPool<IntPtr> _arrayPool;
    private readonly object _lock = new();
    private readonly int _maxPacketSize;

    // Pre-allocated batch request buffers for SendPackets auto-routing
    private ETH_M_REQUEST _sendToAdapter;
    private ETH_M_REQUEST _sendToMstcp;

    // Fast I/O state
    private IntPtr _fastIOSectionPtr;
    private int _fastIONumberOfPackets;
    private IntPtr[]? _secondaryFastIOSectionPtrs = null;

    private bool _disposed;

    /// <summary>
    /// Size of INTERMEDIATE_BUFFER including the variable-length packet data area.
    /// Use this when allocating buffers for packet capture.
    /// </summary>
    public int IntermediateBufferSize { get; }

    /// <summary>
    /// Maximum packet size in bytes (default: MAX_ETHER_FRAME = 1514).
    /// </summary>
    public int MaxPacketSize => _maxPacketSize;

    /// <summary>
    /// Access to the underlying low-level managed API for direct IOCTL calls.
    /// </summary>
    public NdisApiManaged Api => _api;

    /// <summary>
    /// Access to the pinned array allocator for custom buffer management.
    /// </summary>
    public PinnedManagedArrayAllocator<byte> Allocator => _allocator;

    // ============================================================
    // Constructor / Dispose
    // ============================================================

    /// <summary>
    /// Creates a new high-level NDIS API wrapper.
    /// </summary>
    /// <param name="api">Low-level managed API instance. If null, creates a new one.</param>
    /// <param name="ownsApi">If true, Dispose will also dispose the NdisApiManaged instance.</param>
    /// <param name="maxPacketSize">Maximum Ethernet frame size (default: 1514).</param>
    public NdisApiWrapper(NdisApiManaged? api = null, bool ownsApi = true, int maxPacketSize = NdisConst.MAX_ETHER_FRAME)
    {
        if (maxPacketSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxPacketSize), "Maximum packet size must be positive.");

        _api = api ?? new NdisApiManaged();
        _ownsApi = ownsApi;
        _maxPacketSize = maxPacketSize;
        IntermediateBufferSize = INTERMEDIATE_BUFFER.SizeOfHeader + maxPacketSize;

        _allocator = new PinnedManagedArrayAllocator<byte>();
        _arrayPool = ArrayPool<IntPtr>.Create();

        // Pre-allocate batch send buffers
        _sendToAdapter = new ETH_M_REQUEST();
        _sendToMstcp = new ETH_M_REQUEST();
    }

    /// <summary>
    /// Releases all resources: pinned arrays, unmanaged Fast I/O memory, and optionally the API handle.
    /// </summary>
    public virtual void Dispose()
    {
        if (_disposed) return;

        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;

            // Free Fast I/O unmanaged memory
            if (_fastIOSectionPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_fastIOSectionPtr);
                _fastIOSectionPtr = IntPtr.Zero;
            }

            if (_secondaryFastIOSectionPtrs != null)
            {
                foreach (IntPtr ptr in _secondaryFastIOSectionPtrs)
                {
                    if (ptr != IntPtr.Zero)
                        Marshal.FreeHGlobal(ptr);
                }
                _secondaryFastIOSectionPtrs = null;
            }

            // Free all pinned arrays
            _allocator.Dispose();

            // Optionally dispose the underlying API
            if (_ownsApi)
                _api.Dispose();
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(NdisApiWrapper));
    }

    // ============================================================
    // Factory methods — create pinned buffers for kernel I/O
    // ============================================================

    /// <summary>
    /// Creates a pinned INTERMEDIATE_BUFFER for packet capture/injection.
    /// The returned pointer remains valid until DisposeObject or Dispose is called.
    /// </summary>
    /// <returns>Pointer to a zeroed, pinned INTERMEDIATE_BUFFER.</returns>
    public INTERMEDIATE_BUFFER* CreateIntermediateBuffer()
    {
        ThrowIfDisposed();
        return (INTERMEDIATE_BUFFER*)_allocator.AllocateArray(IntermediateBufferSize);
    }

    /// <summary>
    /// Creates a pinned ETH_REQUEST with its own pinned INTERMEDIATE_BUFFER.
    /// The adapter handle must be set before use.
    /// </summary>
    /// <returns>Pointer to a pinned ETH_REQUEST with allocated buffer.</returns>
    public ETH_REQUEST* CreateEthRequest()
    {
        ThrowIfDisposed();

        var ethRequest = (ETH_REQUEST*)_allocator.AllocateArray(sizeof(ETH_REQUEST));
        ethRequest->EthPacket.Buffer = _allocator.AllocateArray(IntermediateBufferSize);
        return ethRequest;
    }

    /// <summary>
    /// Creates a pinned ETH_M_REQUEST with the specified number of packet slots,
    /// each with its own pinned INTERMEDIATE_BUFFER.
    /// The adapter handle must be set before use.
    /// </summary>
    /// <param name="packetCount">Number of packet slots (1-256).</param>
    /// <returns>Pointer to a pinned ETH_M_REQUEST with allocated buffers.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If packetCount is 0 or exceeds 256.</exception>
    public ETH_M_REQUEST_UNSAFE* CreateEthMRequest(uint packetCount)
    {
        ThrowIfDisposed();

        if (packetCount == 0 || packetCount > 256)
            throw new ArgumentOutOfRangeException(nameof(packetCount), "Packet count must be between 1 and 256.");

        int headerSize = sizeof(IntPtr) + sizeof(uint) + sizeof(uint); // hAdapterHandle + dwPacketsNumber + dwPacketsSuccess
        int totalSize = headerSize + (int)(packetCount * sizeof(NDISRD_ETH_Packet));
        IntPtr pinnedPtr = _allocator.AllocateArray(totalSize);

        var ethMRequest = (ETH_M_REQUEST_UNSAFE*)pinnedPtr;
        ethMRequest->dwPacketsNumber = packetCount;
        ethMRequest->dwPacketsSuccess = 0;

        NDISRD_ETH_Packet* packets = ethMRequest->GetPacketsPtr();
        for (int i = 0; i < packetCount; i++)
        {
            packets[i].Buffer = _allocator.AllocateArray(IntermediateBufferSize);
        }

        return ethMRequest;
    }

    /// <summary>
    /// Creates a pinned FAST_IO_SECTION for high-performance packet exchange.
    /// </summary>
    /// <param name="intermediateBufferCount">Number of packet slots.</param>
    /// <returns>Pointer to a pinned FAST_IO_SECTION.</returns>
    public FAST_IO_SECTION* CreateFastIOSection(uint intermediateBufferCount)
    {
        ThrowIfDisposed();

        if (intermediateBufferCount == 0)
            throw new ArgumentOutOfRangeException(nameof(intermediateBufferCount), "Buffer count must be positive.");

        int totalSize = FAST_IO_SECTION_HEADER.Size + (int)(intermediateBufferCount * IntermediateBufferSize);
        return (FAST_IO_SECTION*)_allocator.AllocateArray(totalSize);
    }

    /// <summary>
    /// Creates a pinned STATIC_FILTER_TABLE with the specified number of filter slots.
    /// Each filter entry is initialized to default values.
    /// </summary>
    /// <param name="filterCount">Number of filter entries (max 65535 to prevent overflow).</param>
    /// <returns>Pointer to a pinned STATIC_FILTER_TABLE.</returns>
    public STATIC_FILTER_TABLE* CreateStaticFilterTable(uint filterCount)
    {
        ThrowIfDisposed();

        if (filterCount == 0 || filterCount > 65535)
            throw new ArgumentOutOfRangeException(nameof(filterCount), "Filter count must be between 1 and 65535.");

        int totalSize = STATIC_FILTER_TABLE.SizeOfHeader + (int)(filterCount * STATIC_FILTER.Size);
        IntPtr pinnedPtr = _allocator.AllocateArray(totalSize);

        var table = (STATIC_FILTER_TABLE*)pinnedPtr;
        table->m_TableSize = filterCount;

        Span<STATIC_FILTER> filters = table->StaticFilters;
        for (int i = 0; i < filterCount; i++)
            filters[i] = new STATIC_FILTER();

        return table;
    }

    // ============================================================
    // Object lifecycle — Clone / Zero / Dispose
    // ============================================================

    /// <summary>
    /// Deep-copies an INTERMEDIATE_BUFFER including packet data.
    /// </summary>
    public void CloneObject(INTERMEDIATE_BUFFER* source, INTERMEDIATE_BUFFER* destination)
    {
        if (source == null) throw new ArgumentNullException(nameof(source));
        if (destination == null) throw new ArgumentNullException(nameof(destination));

        RtlMoveMemory((IntPtr)destination, (IntPtr)source, (uint)IntermediateBufferSize);
    }

    /// <summary>
    /// Deep-copies an ETH_REQUEST including its buffer data.
    /// </summary>
    public ETH_REQUEST* CloneObject(ETH_REQUEST* source)
    {
        if (source == null) throw new ArgumentNullException(nameof(source));

        ETH_REQUEST* dest = CreateEthRequest();
        CloneObject(source, dest);
        return dest;
    }

    /// <summary>
    /// Deep-copies ETH_REQUEST: copies adapter handle and buffer data.
    /// </summary>
    public void CloneObject(ETH_REQUEST* source, ETH_REQUEST* destination)
    {
        if (source == null) throw new ArgumentNullException(nameof(source));
        if (destination == null) throw new ArgumentNullException(nameof(destination));

        destination->hAdapterHandle = source->hAdapterHandle;
        RtlMoveMemory(destination->EthPacket.Buffer, source->EthPacket.Buffer, (uint)IntermediateBufferSize);
    }

    /// <summary>
    /// Zeroes the INTERMEDIATE_BUFFER data area.
    /// </summary>
    public void ZeroObject(INTERMEDIATE_BUFFER* buffer)
    {
        if (buffer == null) throw new ArgumentNullException(nameof(buffer));
        RtlZeroMemory((IntPtr)buffer, IntermediateBufferSize);
    }

    /// <summary>
    /// Zeroes an ETH_REQUEST: clears adapter handle and buffer data.
    /// </summary>
    public void ZeroObject(ETH_REQUEST* request)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        request->hAdapterHandle = IntPtr.Zero;
        RtlZeroMemory(request->EthPacket.Buffer, IntermediateBufferSize);
    }

    /// <summary>
    /// Frees a pinned pointer allocated by this wrapper's factory methods.
    /// </summary>
    public void DisposeObject(IntPtr ptr)
    {
        _allocator.FreeArray(ptr);
    }

    /// <summary>
    /// Frees a pinned INTERMEDIATE_BUFFER.
    /// </summary>
    public void DisposeObject(INTERMEDIATE_BUFFER* buffer)
    {
        _allocator.FreeArray((IntPtr)buffer);
    }

    /// <summary>
    /// Frees a pinned ETH_REQUEST and its buffer.
    /// </summary>
    public void DisposeObject(ETH_REQUEST* request)
    {
        if (request == null) return;
        if (request->EthPacket.Buffer != IntPtr.Zero)
            _allocator.FreeArray(request->EthPacket.Buffer);
        _allocator.FreeArray((IntPtr)request);
    }

    /// <summary>
    /// Frees a pinned ETH_M_REQUEST_UNSAFE and all its packet buffers.
    /// </summary>
    public void DisposeObject(ETH_M_REQUEST_UNSAFE* request)
    {
        if (request == null) return;

        NDISRD_ETH_Packet* packets = request->GetPacketsPtr();
        for (int i = 0; i < request->dwPacketsNumber; i++)
        {
            if (packets[i].Buffer != IntPtr.Zero)
                _allocator.FreeArray(packets[i].Buffer);
        }

        _allocator.FreeArray((IntPtr)request);
    }

    /// <summary>
    /// Frees a pinned STATIC_FILTER_TABLE.
    /// </summary>
    public void DisposeObject(STATIC_FILTER_TABLE* table)
    {
        _allocator.FreeArray((IntPtr)table);
    }

    /// <summary>
    /// Gets the managed byte array backing a pinned pointer.
    /// Useful for reading raw packet data after kernel I/O completes.
    /// </summary>
    public byte[] GetPinnedArray(IntPtr ptr)
    {
        return _allocator.GetArray(ptr);
    }

    // ============================================================
    // Auto-routing SendPackets — splits by packet direction
    // ============================================================

    /// <summary>
    /// Sends a single packet to adapter or MSTCP based on its direction flags.
    /// PACKET_FLAG_ON_SEND → SendPacketToAdapter (re-inject to wire)
    /// Otherwise → SendPacketToMstcp (pass up to TCP/IP stack)
    /// </summary>
    public bool SendPacket(ref ETH_REQUEST ethRequest)
    {
        ThrowIfDisposed();

        var buffer = (INTERMEDIATE_BUFFER*)ethRequest.EthPacket.Buffer;
        return buffer->m_dwDeviceFlags == (uint)PACKET_FLAG.PACKET_FLAG_ON_SEND
            ? _api.SendPacketToAdapter(ref ethRequest)
            : _api.SendPacketToMstcp(ref ethRequest);
    }

    /// <summary>
    /// Sends a batch of packets, automatically routing each to adapter or MSTCP
    /// based on its INTERMEDIATE_BUFFER.m_dwDeviceFlags.
    ///
    /// Thread-safe: uses lock to protect pre-allocated send buffers.
    /// </summary>
    /// <param name="packets">Source ETH_M_REQUEST containing packets to send.</param>
    /// <returns>true if all sends succeeded.</returns>
    public bool SendPackets(ref ETH_M_REQUEST packets)
    {
        ThrowIfDisposed();

        lock (_lock)
        {
            // Reset pre-allocated buffers
            _sendToAdapter.hAdapterHandle = packets.hAdapterHandle;
            _sendToAdapter.dwPacketsNumber = 0;
            _sendToAdapter.dwPacketsSuccess = 0;

            _sendToMstcp.hAdapterHandle = packets.hAdapterHandle;
            _sendToMstcp.dwPacketsNumber = 0;
            _sendToMstcp.dwPacketsSuccess = 0;

            // Initialize packet arrays if needed
            _sendToAdapter.EthPacket ??= new NDISRD_ETH_Packet[DefaultBatchPacketCount];
            _sendToMstcp.EthPacket ??= new NDISRD_ETH_Packet[DefaultBatchPacketCount];

            // Sort packets by direction
            int count = (int)packets.dwPacketsSuccess; // dwPacketsSuccess = actual packets read
            if (count > DefaultBatchPacketCount)
                count = DefaultBatchPacketCount; // Clamp to array bounds
            NDISRD_ETH_Packet[]? ethPackets = packets.EthPacket;
            if (ethPackets == null)
                return true; // Nothing to send
            if (count > ethPackets.Length)
                count = ethPackets.Length;
            for (int i = 0; i < count; i++)
            {
                IntPtr buffer = ethPackets[i].Buffer;
                var intermediateBuffer = (INTERMEDIATE_BUFFER*)buffer;

                if (intermediateBuffer->m_dwDeviceFlags == (uint)PACKET_FLAG.PACKET_FLAG_ON_SEND)
                {
                    uint idx = _sendToAdapter.dwPacketsNumber++;
                    _sendToAdapter.EthPacket[idx].Buffer = buffer;
                }
                else
                {
                    uint idx = _sendToMstcp.dwPacketsNumber++;
                    _sendToMstcp.EthPacket[idx].Buffer = buffer;
                }
            }

            bool success = true;

            if (_sendToMstcp.dwPacketsNumber > 0)
            {
                _sendToMstcp.dwPacketsSuccess = _sendToMstcp.dwPacketsNumber;
                success = _api.SendPacketsToMstcp(ref _sendToMstcp);
            }

            if (_sendToAdapter.dwPacketsNumber > 0)
            {
                _sendToAdapter.dwPacketsSuccess = _sendToAdapter.dwPacketsNumber;
                success = _api.SendPacketsToAdapter(ref _sendToAdapter) && success;
            }

            return success;
        }
    }

    /// <summary>
    /// Sends unsorted packets (each with its own adapter handle), automatically routing
    /// by direction flags. Uses ArrayPool for efficient temporary buffer allocation.
    ///
    /// NOTE: This method requires ndisapi.dll for the unsorted send functions.
    /// Use NdisApiNative.SendPacketsToAdaptersUnsorted / SendPacketsToMstcpUnsorted.
    /// </summary>
    /// <param name="driverHandle">Open filter driver handle (from NdisApiNative.OpenFilterDriver).</param>
    /// <param name="buffers">Array of IntPtr to INTERMEDIATE_BUFFER structs.</param>
    /// <param name="packetCount">Number of valid entries in buffers.</param>
    /// <param name="packetsSuccess">Total number of successfully sent packets.</param>
    /// <returns>true if all sends succeeded.</returns>
    public bool SendPacketsUnsorted(IntPtr driverHandle, IntPtr[] buffers, uint packetCount, out uint packetsSuccess)
    {
        ThrowIfDisposed();

        if (buffers == null) throw new ArgumentNullException(nameof(buffers));
        if (packetCount > buffers.Length)
            throw new ArgumentOutOfRangeException(nameof(packetCount), "Packet count exceeds buffer array length.");

        IntPtr[] mstcpBuffers = _arrayPool.Rent((int)packetCount);
        IntPtr[] adapterBuffers = _arrayPool.Rent((int)packetCount);

        try
        {
            uint mstcpCount = 0;
            uint adapterCount = 0;

            for (int i = 0; i < packetCount; i++)
            {
                var buffer = (INTERMEDIATE_BUFFER*)buffers[i];

                if (buffer->m_dwDeviceFlags == (uint)PACKET_FLAG.PACKET_FLAG_ON_SEND)
                    adapterBuffers[adapterCount++] = buffers[i];
                else
                    mstcpBuffers[mstcpCount++] = buffers[i];
            }

            bool success = true;
            uint totalSuccess = 0;

            if (adapterCount > 0)
            {
                uint adapterSuccess = 0;
                success = NdisApiNative.SendPacketsToAdaptersUnsorted(
                    driverHandle, adapterBuffers, adapterCount, ref adapterSuccess);
                totalSuccess += adapterSuccess;
            }

            if (mstcpCount > 0)
            {
                uint mstcpSuccess = 0;
                success = NdisApiNative.SendPacketsToMstcpUnsorted(
                    driverHandle, mstcpBuffers, mstcpCount, ref mstcpSuccess) & success;
                totalSuccess += mstcpSuccess;
            }

            packetsSuccess = totalSuccess;
            return success;
        }
        finally
        {
            _arrayPool.Return(mstcpBuffers);
            _arrayPool.Return(adapterBuffers);
        }
    }

    // ============================================================
    // Fast I/O lifecycle — shared memory for high-performance I/O
    // ============================================================

    /// <summary>
    /// Initializes Fast I/O shared memory for high-performance packet exchange.
    ///
    /// Allocates unmanaged memory sections, zeroes them, registers with the driver,
    /// and manages the full lifecycle. On any failure, all allocated memory is freed.
    ///
    /// The primary section handles reads; secondary sections handle writes.
    /// </summary>
    /// <param name="numberOfPackets">Number of packet slots per section.</param>
    /// <param name="numberOfSecondarySections">Number of secondary Fast I/O sections (1-15).</param>
    /// <param name="fastIOSection">On success, pointer to the primary section.</param>
    /// <param name="secondaryFastIOSections">On success, array of pointers to secondary sections.</param>
    /// <returns>true if all sections were successfully initialized.</returns>
    /// <exception cref="ArgumentException">If numberOfSecondarySections is out of range.</exception>
    /// <exception cref="ArgumentException">If Fast I/O was already initialized (create a new wrapper).</exception>
    public bool InitializeFastIo(
        int numberOfPackets,
        int numberOfSecondarySections,
        out FAST_IO_SECTION* fastIOSection,
        out FAST_IO_SECTION*[] secondaryFastIOSections)
    {
        ThrowIfDisposed();

        if (numberOfPackets <= 0)
            throw new ArgumentOutOfRangeException(nameof(numberOfPackets), "Number of packets must be positive.");

        if (numberOfSecondarySections is < 1 or > 15)
            throw new ArgumentException("Number of secondary Fast I/O sections must be between 1 and 15.",
                nameof(numberOfSecondarySections));

        lock (_lock)
        {
            // Prevent reinitialization (would leak previous sections)
            if (_fastIOSectionPtr != IntPtr.Zero)
            {
                if (_fastIONumberOfPackets != numberOfPackets ||
                    _secondaryFastIOSectionPtrs?.Length != numberOfSecondarySections)
                {
                    throw new ArgumentException(
                        "Cannot reinitialize Fast I/O with different parameters. Create a new NdisApiWrapper instance.");
                }

                // Same parameters — return existing sections
                fastIOSection = (FAST_IO_SECTION*)_fastIOSectionPtr;
                secondaryFastIOSections = new FAST_IO_SECTION*[numberOfSecondarySections];
                for (int i = 0; i < numberOfSecondarySections; i++)
                    secondaryFastIOSections[i] = (FAST_IO_SECTION*)_secondaryFastIOSectionPtrs[i];
                return true;
            }
        } // Release lock before heavy allocation + IOCTL calls

        uint sectionSize = (uint)(FAST_IO_SECTION.SizeOfHeader + (IntermediateBufferSize * numberOfPackets));

        // Allocate and zero the primary section
        IntPtr primaryPtr = Marshal.AllocHGlobal((int)sectionSize);
        RtlZeroMemory(primaryPtr, (int)sectionSize);

        fastIOSection = (FAST_IO_SECTION*)primaryPtr;

        // Register primary section with driver
        if (_api.InitializeFastIo(primaryPtr, sectionSize))
        {
            var secondaryPtrs = new IntPtr[numberOfSecondarySections];
            secondaryFastIOSections = new FAST_IO_SECTION*[numberOfSecondarySections];

            for (int i = 0; i < numberOfSecondarySections; i++)
            {
                IntPtr secPtr = Marshal.AllocHGlobal((int)sectionSize);
                RtlZeroMemory(secPtr, (int)sectionSize);

                if (_api.AddSecondaryFastIo(secPtr, sectionSize))
                {
                    secondaryPtrs[i] = secPtr;
                    secondaryFastIOSections[i] = (FAST_IO_SECTION*)secPtr;
                }
                else
                {
                    // Cleanup on failure: free this and all previous secondary sections
                    Marshal.FreeHGlobal(secPtr);
                    for (int j = 0; j < i; j++)
                        Marshal.FreeHGlobal(secondaryPtrs[j]);
                    Marshal.FreeHGlobal(primaryPtr);

                    fastIOSection = null;
                    secondaryFastIOSections = null!;
                    return false;
                }
            }

            // Store for disposal (thread-safe)
            lock (_lock)
            {
                if (_fastIOSectionPtr != IntPtr.Zero)
                {
                    // Another thread initialized while we were allocating — cleanup our allocation
                    for (int j = 0; j < numberOfSecondarySections; j++)
                        Marshal.FreeHGlobal(secondaryPtrs[j]);
                    Marshal.FreeHGlobal(primaryPtr);

                    fastIOSection = (FAST_IO_SECTION*)_fastIOSectionPtr;
                    secondaryFastIOSections = new FAST_IO_SECTION*[numberOfSecondarySections];
                    IntPtr[] existingPtrs = _secondaryFastIOSectionPtrs!;
                    for (int j = 0; j < numberOfSecondarySections; j++)
                        secondaryFastIOSections[j] = (FAST_IO_SECTION*)existingPtrs[j];
                    return true;
                }

                _fastIOSectionPtr = primaryPtr;
                _secondaryFastIOSectionPtrs = secondaryPtrs;
                _fastIONumberOfPackets = numberOfPackets;
            }
            return true;
        }

        // Primary init failed
        Marshal.FreeHGlobal(primaryPtr);
        fastIOSection = null;
        secondaryFastIOSections = null!;
        return false;
    }

    /// <summary>
    /// Overload for single secondary section (most common case).
    /// </summary>
    public bool InitializeFastIo(
        int numberOfPackets,
        out FAST_IO_SECTION* fastIOSection,
        out FAST_IO_SECTION* secondaryFastIOSection)
    {
        bool result = InitializeFastIo(numberOfPackets, 1, out fastIOSection, out FAST_IO_SECTION*[] sections);
        secondaryFastIOSection = result ? sections[0] : null;
        return result;
    }

    // ============================================================
    // Network adapter enumeration
    // ============================================================

    /// <summary>
    /// Enumerates all TCP/IP-bound network adapters known to the WinpkFilter driver.
    /// Returns NetworkAdapter objects with parsed names, MAC addresses, MTU, and medium type.
    /// </summary>
    /// <returns>List of adapters, or empty list on failure.</returns>
    public IReadOnlyList<NetworkAdapter> GetNetworkAdapters()
    {
        ThrowIfDisposed();

        var adapterList = new TCP_AdapterList();
        if (!_api.GetTcpipBoundAdaptersInfo(ref adapterList))
            return Array.Empty<NetworkAdapter>();

        var result = new List<NetworkAdapter>((int)adapterList.m_nAdapterCount);

        for (int i = 0; i < adapterList.m_nAdapterCount; i++)
        {
            // Extract adapter name bytes
            byte[] nameBytes = new byte[NdisConst.ADAPTER_NAME_SIZE];
            Array.Copy(adapterList.m_szAdapterNameList,
                i * NdisConst.ADAPTER_NAME_SIZE,
                nameBytes, 0, NdisConst.ADAPTER_NAME_SIZE);

            // Extract MAC address bytes
            byte[] macBytes = adapterList.GetMacAddress(i);

            // Parse medium type
            var medium = (NDIS_MEDIUM)adapterList.m_nAdapterMediumList[i];

            result.Add(new NetworkAdapter(
                handle: adapterList.m_nAdapterHandle[i],
                nameBytes: nameBytes,
                medium: medium,
                macAddress: macBytes,
                mtu: adapterList.m_usMTU[i],
                wrapper: this));
        }

        return result;
    }

    /// <summary>
    /// Gets adapters filtered by the specified mode flags.
    /// </summary>
    public IEnumerable<NetworkAdapter> GetNetworkAdapters(MSTCP_FLAGS flags)
    {
        foreach (var adapter in GetNetworkAdapters())
        {
            var mode = new ADAPTER_MODE { hAdapterHandle = adapter.Handle };
            if (_api.GetAdapterMode(ref mode) && mode.dwFlags == (uint)flags)
                yield return adapter;
        }
    }
}

// ============================================================
// Unsafe ETH_M_REQUEST — variable-length, pointer-friendly
// Used internally by factory methods and high-level operations
// that need direct pointer access to packet arrays.
// ============================================================

/// <summary>
/// Pointer-friendly ETH_M_REQUEST layout for use with PinnedManagedArrayAllocator.
/// Unlike the managed ETH_M_REQUEST struct, this uses inline memory for the packet array
/// and provides pointer access via GetPacketsPtr().
///
/// Memory layout: [IntPtr hAdapterHandle][uint dwPacketsNumber][uint dwPacketsSuccess][NDISRD_ETH_Packet * N]
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct ETH_M_REQUEST_UNSAFE
{
    public IntPtr hAdapterHandle;
    public uint dwPacketsNumber;
    public uint dwPacketsSuccess;

    /// <summary>First packet slot — variable-length array follows.</summary>
    private NDISRD_ETH_Packet _firstPacket;

    /// <summary>
    /// Gets a pointer to the inline NDISRD_ETH_Packet array.
    /// </summary>
    public NDISRD_ETH_Packet* GetPacketsPtr()
    {
        fixed (NDISRD_ETH_Packet* p = &_firstPacket)
            return p;
    }

    /// <summary>
    /// Gets a Span over the packet array.
    /// </summary>
    public Span<NDISRD_ETH_Packet> EthPackets
    {
        get
        {
#if NETCOREAPP
            return MemoryMarshal.CreateSpan(ref _firstPacket, (int)dwPacketsNumber);
#else
            fixed (NDISRD_ETH_Packet* p = &_firstPacket)
            {
                return new Span<NDISRD_ETH_Packet>(p, (int)dwPacketsNumber);
            }
#endif
        }
    }
}
