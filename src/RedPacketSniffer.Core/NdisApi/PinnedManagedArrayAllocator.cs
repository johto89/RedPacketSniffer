using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RedPacketSniffer.Core.NdisApi;

/// <summary>
/// Thread-safe allocator for GC-pinned managed arrays.
///
/// When calling DeviceIoControl to pass buffers to the kernel driver, the GC must not
/// move the array during the I/O operation. This class pins arrays via GCHandle.Pinned
/// so their addresses remain stable for the lifetime of the allocation.
///
/// Usage pattern:
///   var allocator = new PinnedManagedArrayAllocator&lt;byte&gt;();
///   IntPtr ptr = allocator.AllocateArray(bufferSize);   // pinned, won't move
///   // ... pass ptr to DeviceIoControl or kernel driver ...
///   allocator.FreeArray(ptr);                            // unpin + release
///   allocator.Dispose();                                 // cleanup all remaining
///
/// Thread safety: all operations are protected by lock.
///
/// SECURITY NOTE: Pinned arrays bypass GC compaction. Excessive pinning fragments
/// the managed heap. Always free arrays when done. Dispose releases all remaining pins.
/// </summary>
#if NETCOREAPP
[SkipLocalsInit]
#endif
public sealed class PinnedManagedArrayAllocator<T> : IDisposable where T : struct
{
    private readonly object _lock = new();
    private bool _isDisposed;
    private Dictionary<IntPtr, T[]> _ptrToArrays;
    private Dictionary<IntPtr, GCHandle> _ptrToGcHandles;

    public PinnedManagedArrayAllocator()
    {
        _ptrToArrays = new Dictionary<IntPtr, T[]>();
        _ptrToGcHandles = new Dictionary<IntPtr, GCHandle>();
    }

    /// <summary>
    /// Allocates a pinned array of the specified length and returns a pointer to it.
    /// The pointer remains valid until FreeArray or Dispose is called.
    /// </summary>
    /// <param name="length">Number of elements in the array.</param>
    /// <returns>Pointer to the pinned array data.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the allocator has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if length is negative.</exception>
    public IntPtr AllocateArray(int length)
    {
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length), "Array length must be non-negative.");

#if NETCOREAPP
        T[] array = GC.AllocateUninitializedArray<T>(length);
#else
        var array = new T[length];
#endif

        var gcHandle = GCHandle.Alloc(array, GCHandleType.Pinned);
        IntPtr ptr = gcHandle.AddrOfPinnedObject();

        lock (_lock)
        {
            if (_isDisposed)
            {
                gcHandle.Free();
                throw new ObjectDisposedException(nameof(PinnedManagedArrayAllocator<T>));
            }

            _ptrToArrays.Add(ptr, array);
            _ptrToGcHandles.Add(ptr, gcHandle);
        }

        return ptr;
    }

    /// <summary>
    /// Frees a previously allocated pinned array. The pointer becomes invalid after this call.
    /// No-op if the pointer is not tracked (idempotent).
    /// </summary>
    /// <param name="arrayPointer">Pointer returned by AllocateArray.</param>
    public void FreeArray(IntPtr arrayPointer)
    {
        lock (_lock)
        {
            if (_isDisposed)
                return;

#if NETCOREAPP
            if (_ptrToGcHandles.Remove(arrayPointer, out GCHandle handle))
                handle.Free();
#else
            if (_ptrToGcHandles.TryGetValue(arrayPointer, out GCHandle handle))
            {
                _ptrToGcHandles.Remove(arrayPointer);
                handle.Free();
            }
#endif
            _ptrToArrays.Remove(arrayPointer);
        }
    }

    /// <summary>
    /// Gets the managed array backing the specified pointer.
    /// Useful for reading packet data after kernel I/O completes.
    /// </summary>
    /// <param name="arrayPointer">Pointer returned by AllocateArray.</param>
    /// <returns>The managed array.</returns>
    /// <exception cref="KeyNotFoundException">Thrown if the pointer is not tracked.</exception>
    public T[] GetArray(IntPtr arrayPointer)
    {
        lock (_lock)
            return _ptrToArrays[arrayPointer];
    }

    /// <summary>
    /// Checks whether the specified pointer is currently tracked by this allocator.
    /// </summary>
    public bool ContainsPointer(IntPtr arrayPointer)
    {
        lock (_lock)
            return _ptrToArrays.ContainsKey(arrayPointer);
    }

    /// <summary>
    /// Gets the number of currently allocated (pinned) arrays.
    /// </summary>
    public int AllocatedCount
    {
        get
        {
            lock (_lock)
                return _isDisposed ? 0 : _ptrToArrays.Count;
        }
    }

    /// <summary>
    /// Releases all pinned arrays. After disposal, AllocateArray throws ObjectDisposedException.
    /// </summary>
    public void Dispose()
    {
        lock (_lock)
        {
            if (_isDisposed)
                return;

            _isDisposed = true;

            foreach (KeyValuePair<IntPtr, GCHandle> ptrToGcHandle in _ptrToGcHandles)
                ptrToGcHandle.Value.Free();

            _ptrToGcHandles = null!;
            _ptrToArrays = null!;
        }
    }
}
