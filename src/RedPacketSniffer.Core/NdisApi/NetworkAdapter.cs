using System;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace RedPacketSniffer.Core.NdisApi;

/// <summary>
/// High-level representation of a network adapter managed by the WinpkFilter driver.
///
/// Wraps the low-level adapter handle with metadata (name, MAC, MTU, medium type)
/// and provides convenient methods for packet event management and hardware filters.
///
/// Equality is determined solely by the adapter handle (IntPtr), meaning two
/// NetworkAdapter instances referencing the same driver handle are considered equal.
///
/// SECURITY NOTES:
/// - Adapter handles come from the kernel driver; never fabricate or reuse stale handles.
/// - SetPacketEvent creates a kernel-visible event; always call ResetPacketEvent before disposing.
/// - Friendly name resolution uses P/Invoke; null return indicates the adapter is unknown.
/// </summary>
public sealed class NetworkAdapter : IEquatable<NetworkAdapter>, IDisposable
{
    private readonly NdisApiWrapper _wrapper;
    private readonly byte[] _nameBytes;
    private string? _internalName;
    private string? _friendlyName;
    private ManualResetEvent? _packetEvent;
    private bool _disposed;

    /// <summary>
    /// Native handle identifying this adapter to the WinpkFilter driver.
    /// </summary>
    public IntPtr Handle { get; }

    /// <summary>
    /// NDIS medium type of the adapter (802.3, Wi-Fi, WAN, etc.).
    /// </summary>
    public NDIS_MEDIUM Medium { get; }

    /// <summary>
    /// Hardware (MAC) address as a PhysicalAddress.
    /// </summary>
    public PhysicalAddress PhysicalAddress { get; }

    /// <summary>
    /// Maximum transmission unit in bytes.
    /// </summary>
    public ushort Mtu { get; private set; }

    /// <summary>
    /// Whether this adapter has a valid (non-zero) driver handle.
    /// </summary>
    public bool IsValid => Handle != IntPtr.Zero;

    /// <summary>
    /// The ManualResetEvent signaled when packets arrive for this adapter.
    /// Set by <see cref="SetPacketEvent"/>; null until that method is called.
    /// </summary>
    public ManualResetEvent? WaitHandle => _packetEvent;

    /// <summary>
    /// Internal adapter name (GUID path as returned by the driver, e.g. \DEVICE\{GUID}).
    /// Lazily parsed from raw name bytes.
    /// </summary>
    public string InternalName
    {
        get
        {
            if (_internalName == null)
            {
                string raw = Encoding.ASCII.GetString(_nameBytes);
                int nullIdx = raw.IndexOf('\0');
                _internalName = nullIdx >= 0 ? raw[..nullIdx] : raw;
            }
            return _internalName;
        }
    }

    /// <summary>
    /// User-friendly adapter name (e.g. "Ethernet 1", "Wi-Fi").
    /// Lazily resolved via P/Invoke. Returns the internal name if resolution fails.
    /// </summary>
    public string FriendlyName
    {
        get
        {
            if (_friendlyName == null)
            {
                _friendlyName = NdisApiNative.ConvertAdapterName(InternalName)
                    ?? InternalName;
            }
            return _friendlyName;
        }
    }

    /// <summary>
    /// Creates a new NetworkAdapter instance.
    /// Called internally by NdisApiWrapper.GetNetworkAdapters().
    /// </summary>
    internal NetworkAdapter(
        IntPtr handle,
        byte[] nameBytes,
        NDIS_MEDIUM medium,
        byte[] macAddress,
        ushort mtu,
        NdisApiWrapper wrapper)
    {
        Handle = handle;
        _nameBytes = nameBytes ?? throw new ArgumentNullException(nameof(nameBytes));
        Medium = medium;
        PhysicalAddress = new PhysicalAddress(macAddress ?? throw new ArgumentNullException(nameof(macAddress)));
        Mtu = mtu;
        _wrapper = wrapper ?? throw new ArgumentNullException(nameof(wrapper));
    }

    /// <summary>
    /// Refreshes adapter metadata (MTU) from the driver.
    /// Re-queries the adapter list and updates Mtu if the adapter is still present.
    /// </summary>
    /// <returns>true if the adapter was found and refreshed; false if it has been removed.</returns>
    public bool Refresh()
    {
        ThrowIfDisposed();

        var adapterList = new TCP_AdapterList();
        if (!_wrapper.Api.GetTcpipBoundAdaptersInfo(ref adapterList))
            return false;

        for (int i = 0; i < adapterList.m_nAdapterCount; i++)
        {
            if (adapterList.m_nAdapterHandle[i] == Handle)
            {
                Mtu = adapterList.m_usMTU[i];
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Creates a ManualResetEvent and registers it with the driver for packet notifications.
    /// When packets arrive for this adapter, the event is signaled.
    ///
    /// Calling this multiple times reuses the existing event if already set.
    /// </summary>
    /// <returns>The ManualResetEvent that will be signaled on packet arrival.</returns>
    public ManualResetEvent SetPacketEvent()
    {
        ThrowIfDisposed();

        if (_packetEvent == null)
        {
            _packetEvent = new ManualResetEvent(false);
            _wrapper.Api.SetPacketEvent(Handle, _packetEvent.SafeWaitHandle);
        }

        return _packetEvent;
    }

    /// <summary>
    /// Unregisters and disposes the packet notification event.
    /// Must be called before disposing the adapter to avoid kernel resource leaks.
    /// </summary>
    public void ResetPacketEvent()
    {
        if (_packetEvent != null)
        {
            // Deregister by setting a closed/invalid event handle
            using var emptyEvent = new ManualResetEvent(false);
            _wrapper.Api.SetPacketEvent(Handle, emptyEvent.SafeWaitHandle);
            _packetEvent.Dispose();
            _packetEvent = null;
        }
    }

    /// <summary>
    /// Gets the current hardware packet filter (promiscuous mode, etc.) for this adapter.
    /// </summary>
    /// <returns>The current NDIS packet filter flags.</returns>
    public NDIS_PACKET_TYPE GetHwPacketFilter()
    {
        ThrowIfDisposed();

        uint filter = 0;
        _wrapper.Api.GetHwPacketFilter(Handle, ref filter);
        return (NDIS_PACKET_TYPE)filter;
    }

    /// <summary>
    /// Sets the hardware packet filter for this adapter.
    /// Use NDIS_PACKET_TYPE.NDIS_PACKET_TYPE_PROMISCUOUS to capture all traffic.
    /// </summary>
    /// <param name="filter">Combination of NDIS_PACKET_TYPE flags.</param>
    /// <returns>true on success.</returns>
    public bool SetHwPacketFilter(NDIS_PACKET_TYPE filter)
    {
        ThrowIfDisposed();
        return _wrapper.Api.SetHwPacketFilter(Handle, (uint)filter);
    }

    /// <summary>
    /// Gets the current adapter mode (tunnel/filter flags).
    /// </summary>
    /// <returns>The ADAPTER_MODE with current flags, or default if query fails.</returns>
    public ADAPTER_MODE GetAdapterMode()
    {
        ThrowIfDisposed();

        var mode = new ADAPTER_MODE { hAdapterHandle = Handle };
        _wrapper.Api.GetAdapterMode(ref mode);
        return mode;
    }

    /// <summary>
    /// Sets the adapter capture/filter mode.
    /// </summary>
    /// <param name="flags">Combination of MSTCP_FLAGS defining the capture behavior.</param>
    /// <returns>true on success.</returns>
    public bool SetAdapterMode(MSTCP_FLAGS flags)
    {
        ThrowIfDisposed();

        var mode = new ADAPTER_MODE
        {
            hAdapterHandle = Handle,
            dwFlags = (uint)flags
        };
        return _wrapper.Api.SetAdapterMode(ref mode);
    }

    /// <summary>
    /// Flushes all queued packets for this adapter.
    /// </summary>
    /// <returns>true on success.</returns>
    public bool FlushPacketQueue()
    {
        ThrowIfDisposed();
        return _wrapper.Api.FlushAdapterPacketQueue(Handle);
    }

    /// <summary>
    /// Gets the number of packets currently queued for this adapter.
    /// </summary>
    /// <returns>Number of queued packets, or 0 on failure.</returns>
    public uint GetPacketQueueSize()
    {
        ThrowIfDisposed();

        uint size = 0;
        _wrapper.Api.GetAdapterPacketQueueSize(Handle, ref size);
        return size;
    }

    /// <summary>
    /// Gets the MAC address as a formatted string (XX:XX:XX:XX:XX:XX).
    /// </summary>
    public string MacAddressString
    {
        get
        {
            byte[] bytes = PhysicalAddress.GetAddressBytes();
            if (bytes.Length < 6)
                return string.Empty;
            return $"{bytes[0]:X2}:{bytes[1]:X2}:{bytes[2]:X2}:{bytes[3]:X2}:{bytes[4]:X2}:{bytes[5]:X2}";
        }
    }

    // ============================================================
    // IDisposable
    // ============================================================

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        ResetPacketEvent();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(NetworkAdapter));
    }

    // ============================================================
    // IEquatable<NetworkAdapter>
    // ============================================================

    public bool Equals(NetworkAdapter? other)
    {
        if (other is null) return false;
        return Handle == other.Handle;
    }

    public override bool Equals(object? obj)
        => obj is NetworkAdapter adapter && Equals(adapter);

    public override int GetHashCode()
        => Handle.GetHashCode();

    public static bool operator ==(NetworkAdapter? left, NetworkAdapter? right)
        => left?.Handle == right?.Handle;

    public static bool operator !=(NetworkAdapter? left, NetworkAdapter? right)
        => !(left == right);

    public override string ToString()
        => $"[{Medium}] {FriendlyName} ({MacAddressString}) MTU={Mtu}";
}
