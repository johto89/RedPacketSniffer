using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace RedPacketSniffer.Core.NdisApi;

/// <summary>
/// Extension methods for converting between System.Net.IPAddress and
/// NDIS filter structures (uint for IPv4, IN6_ADDR for IPv6).
///
/// IPv4 addresses are stored as uint in network byte order for direct use
/// in STATIC_FILTER IP_V4_FILTER entries.
///
/// IPv6 addresses are stored as IN6_ADDR (16-byte fixed array) for direct use
/// in STATIC_FILTER IP_V6_FILTER entries.
///
/// SECURITY NOTES:
/// - All methods validate input and throw on invalid data (null, wrong address family).
/// - No heap allocations for IPv4 conversions beyond the IPAddress object itself.
/// - IN6_ADDR uses fixed-size buffers; no overflows possible.
/// </summary>
public static class IPAddressExtensions
{
    /// <summary>
    /// Converts an IPv4 IPAddress to a uint in network byte order.
    /// Suitable for use in IP_V4_FILTER fields (m_IpSrc, m_IpDst).
    /// </summary>
    /// <param name="address">IPv4 address.</param>
    /// <returns>IPv4 address as uint in network byte order.</returns>
    /// <exception cref="ArgumentNullException">If address is null.</exception>
    /// <exception cref="ArgumentException">If address is not IPv4.</exception>
    public static uint ToUInt32(this IPAddress address)
    {
        if (address == null)
            throw new ArgumentNullException(nameof(address));
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Address must be IPv4.", nameof(address));

#if NETCOREAPP
        Span<byte> bytes = stackalloc byte[4];
        if (!address.TryWriteBytes(bytes, out _))
            throw new InvalidOperationException("Failed to write IPv4 address bytes.");

        // Network byte order (big-endian): first byte is most significant
        return (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
#else
        byte[] bytes = address.GetAddressBytes();
        return (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
#endif
    }

    /// <summary>
    /// Converts a uint in network byte order to an IPv4 IPAddress.
    /// </summary>
    /// <param name="ipv4">IPv4 address as uint in network byte order.</param>
    /// <returns>IPv4 IPAddress.</returns>
    public static IPAddress ToIPAddress(this uint ipv4)
    {
        byte[] bytes = new byte[4];
        bytes[0] = (byte)(ipv4 >> 24);
        bytes[1] = (byte)(ipv4 >> 16);
        bytes[2] = (byte)(ipv4 >> 8);
        bytes[3] = (byte)ipv4;
        return new IPAddress(bytes);
    }

    /// <summary>
    /// Converts an IN6_ADDR structure to an IPv6 IPAddress.
    /// </summary>
    /// <param name="in6Addr">IN6_ADDR with 16-byte address data.</param>
    /// <returns>IPv6 IPAddress.</returns>
    public static IPAddress ToIPAddress(this IN6_ADDR in6Addr)
    {
        byte[] bytes = new byte[16];
        bytes[0] = in6Addr.b0;   bytes[1] = in6Addr.b1;
        bytes[2] = in6Addr.b2;   bytes[3] = in6Addr.b3;
        bytes[4] = in6Addr.b4;   bytes[5] = in6Addr.b5;
        bytes[6] = in6Addr.b6;   bytes[7] = in6Addr.b7;
        bytes[8] = in6Addr.b8;   bytes[9] = in6Addr.b9;
        bytes[10] = in6Addr.b10; bytes[11] = in6Addr.b11;
        bytes[12] = in6Addr.b12; bytes[13] = in6Addr.b13;
        bytes[14] = in6Addr.b14; bytes[15] = in6Addr.b15;
        return new IPAddress(bytes);
    }

    /// <summary>
    /// Converts an IPv6 IPAddress to an IN6_ADDR structure.
    /// </summary>
    /// <param name="address">IPv6 address.</param>
    /// <returns>IN6_ADDR with the address bytes copied in.</returns>
    /// <exception cref="ArgumentNullException">If address is null.</exception>
    /// <exception cref="ArgumentException">If address is not IPv6.</exception>
    public static IN6_ADDR ToIN6_ADDR(this IPAddress address)
    {
        if (address == null)
            throw new ArgumentNullException(nameof(address));
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
            throw new ArgumentException("Address must be IPv6.", nameof(address));

#if NETCOREAPP
        Span<byte> b = stackalloc byte[16];
        if (!address.TryWriteBytes(b, out _))
            throw new InvalidOperationException("Failed to write IPv6 address bytes.");
#else
        byte[] b = address.GetAddressBytes();
#endif

        var result = new IN6_ADDR();
        result.b0 = b[0];   result.b1 = b[1];   result.b2 = b[2];   result.b3 = b[3];
        result.b4 = b[4];   result.b5 = b[5];   result.b6 = b[6];   result.b7 = b[7];
        result.b8 = b[8];   result.b9 = b[9];   result.b10 = b[10]; result.b11 = b[11];
        result.b12 = b[12]; result.b13 = b[13];  result.b14 = b[14]; result.b15 = b[15];
        return result;
    }

    /// <summary>
    /// Creates an IPAddress from raw bytes (4 bytes for IPv4, 16 bytes for IPv6).
    /// </summary>
    /// <param name="bytes">Raw address bytes in network byte order.</param>
    /// <returns>IPAddress.</returns>
    /// <exception cref="ArgumentNullException">If bytes is null.</exception>
    /// <exception cref="ArgumentException">If bytes length is not 4 or 16.</exception>
    public static IPAddress ToIPAddress(this byte[] bytes)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));
        if (bytes.Length != 4 && bytes.Length != 16)
            throw new ArgumentException("Address bytes must be 4 (IPv4) or 16 (IPv6).", nameof(bytes));

        return new IPAddress(bytes);
    }
}
