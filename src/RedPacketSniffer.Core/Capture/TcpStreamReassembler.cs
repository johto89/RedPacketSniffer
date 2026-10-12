namespace RedPacketSniffer.Core.Capture;

/// <summary>
/// Reassembles per-direction TCP byte streams from individual captured segments.
///
/// The capture pipeline delivers one <see cref="CapturedPacket"/> per Ethernet frame,
/// but TCP is a byte stream: a single HTTP request (headers + body) or a multi-line
/// SMTP AUTH exchange is routinely split across several segments, may arrive out of
/// order, and may be retransmitted. Pattern matching on a single frame therefore misses
/// anything that straddles a segment boundary — most notably HTTP form-POST bodies,
/// which usually land in a segment after the one carrying the headers.
///
/// This class buffers each half-connection (one direction of one 4-tuple) keyed by
/// <see cref="TcpFlowKey"/>, orders segments by sequence number, and raises
/// <see cref="OnStreamData"/> with the contiguous bytes assembled so far whenever new
/// in-order data becomes available. A consumer (e.g. a stream-based credential parser)
/// then runs its patterns over the assembled buffer instead of over a lone frame.
///
/// Scope and known limits — this is a pragmatic reassembler aimed at recovering the
/// START of a flow (where credentials live), NOT a full IDS-grade TCP engine:
///   - Only the first <see cref="TcpReassemblyOptions.MaxStreamBytes"/> bytes of each
///     half-stream are retained; once that cap is hit the half-stream is marked done and
///     ignored. Credentials appear early, so this is deliberate, not a gap.
///   - Out-of-order flushing matches segments whose sequence equals the next expected
///     sequence exactly. Segments that only partially fill a gap are not spliced; a
///     permanently unfillable gap simply stalls that half-stream until it is evicted.
///   - SYN segments carrying data (TCP Fast Open) are handled: the payload is
///     appended at ISN+1, correctly accounting for the SYN-consumed sequence byte.
///   - No IP-layer defragmentation; IP fragments are handled (or not) upstream.
///
/// Threading: <see cref="Feed"/> is expected to be called from a single producer thread
/// (the capture loop), exactly as <see cref="PacketCaptureEngine.OnPacketCaptured"/> is
/// invoked today. <see cref="Clear"/>, <see cref="EvictIdle"/> and the stat properties
/// may be called from other threads; all shared state is guarded by a single lock.
/// <see cref="OnStreamData"/> is raised outside the lock with a private copy of the
/// buffer, so a handler can take as long as it likes without blocking capture.
/// </summary>
public sealed class TcpStreamReassembler
{
    private readonly TcpReassemblyOptions _opt;
    private readonly Dictionary<TcpFlowKey, HalfStream> _flows = new();
    private readonly object _lock = new();
    private long _feedCounter;

    // Stats
    private long _segmentsProcessed;
    private long _bytesAssembled;
    private long _flowsEvicted;
    private long _outOfOrderSegments;
    private long _retransmitSegments;

    public event Action<TcpStreamData>? OnStreamData;

    public TcpStreamReassembler(TcpReassemblyOptions? options = null)
    {
        _opt = options ?? new TcpReassemblyOptions();
    }

    public int ActiveFlows { get { lock (_lock) { return _flows.Count; } } }
    public long SegmentsProcessed => Interlocked.Read(ref _segmentsProcessed);
    public long BytesAssembled => Interlocked.Read(ref _bytesAssembled);
    public long FlowsEvicted => Interlocked.Read(ref _flowsEvicted);
    public long OutOfOrderSegments => Interlocked.Read(ref _outOfOrderSegments);
    public long RetransmitSegments => Interlocked.Read(ref _retransmitSegments);

    /// <summary>
    /// Feed one captured TCP segment into the reassembler. Non-TCP packets are ignored.
    /// Raises <see cref="OnStreamData"/> synchronously (on the calling thread) if new
    /// contiguous bytes became available for this half-stream.
    /// </summary>
    public void Feed(CapturedPacket packet)
    {
        if (packet.IpProtocol != 6) return;                 // TCP only
        if (packet.SourceIP == null || packet.DestIP == null) return;

        byte flags = packet.TcpFlags;
        bool syn = (flags & 0x02) != 0;
        bool ack = (flags & 0x10) != 0;
        bool fin = (flags & 0x01) != 0;
        bool rst = (flags & 0x04) != 0;

        uint seq = packet.TcpSeq;
        ReadOnlySpan<byte> payload = packet.GetPayload();

        TcpStreamData? toEmit = null;

        lock (_lock)
        {
            // Periodic idle sweep so long-running captures do not accumulate dead flows.
            if ((++_feedCounter % _opt.SweepEveryNSegments) == 0)
                EvictIdleLocked(packet.Timestamp);

            var key = new TcpFlowKey(packet.SourceIP, packet.SourcePort, packet.DestIP, packet.DestPort);

            if (!_flows.TryGetValue(key, out var s))
            {
                if (_flows.Count >= _opt.MaxFlows)
                    EvictOldestLocked();

                s = new HalfStream(_opt.InitialBufferBytes) { LastActivity = packet.Timestamp };
                _flows[key] = s;
            }

            s.LastActivity = packet.Timestamp;
            Interlocked.Increment(ref _segmentsProcessed);

            // SECURITY NOTE: an attacker can inject a spoofed RST on the wire to kill
            // reassembly for a targeted flow.  Full mitigation (validating the RST sequence
            // number falls inside the receive window) would require tracking the peer's ACK
            // and window size, which is out of scope for this lightweight reassembler.
            // Awareness: if the tool is used against a hostile network where the attacker
            // controls the path, RST injection can blind credential capture.
            if (rst)
            {
                s.Closed = true;
            }

            int oldLen = s.Length;

            // Establish the sequence baseline.
            bool synHandled = false;
            if (syn && !ack)
            {
                // Pure SYN — this side initiated the connection (client -> server).
                s.Established = true;
                s.SawSyn = true;
                s.IsInitiator = true;
                s.NextSeq = seq + 1;                        // SYN consumes one sequence number
                synHandled = true;

                // TCP Fast Open: SYN carries data. Append directly at NextSeq (ISN+1)
                // to avoid the diff calculation treating the SYN-consumed byte as overlap.
                // Guard: only on first SYN (Length==0) to prevent re-appending on SYN retransmit.
                if (payload.Length > 0 && !s.Done && s.Length == 0)
                {
                    AppendCapped(s, payload);
                    s.NextSeq += (uint)payload.Length;
                }
            }
            else if (syn && ack)
            {
                // SYN-ACK — this side is the responder (server -> client).
                s.Established = true;
                s.NextSeq = seq + 1;
                synHandled = true;

                // SYN-ACK with data (rare but valid in TFO server response).
                // Guard: only on first SYN-ACK (Length==0) to prevent duplicate on retransmit.
                if (payload.Length > 0 && !s.Done && s.Length == 0)
                {
                    AppendCapped(s, payload);
                    s.NextSeq += (uint)payload.Length;
                }
            }

            if (payload.Length > 0 && !s.Done && !synHandled)
            {
                if (!s.Established)
                {
                    // Capture started mid-flow (handshake missed): take this segment as the
                    // baseline. Direction is then a guess: the client normally uses the higher
                    // ephemeral port, the server the lower well-known port.
                    s.Established = true;
                    s.NextSeq = seq;
                    s.IsInitiator = packet.SourcePort > packet.DestPort;
                }

                int diff = unchecked((int)(seq - s.NextSeq));

                if (diff == 0)
                {
                    // In order.
                    AppendCapped(s, payload);
                    s.NextSeq += (uint)payload.Length;
                    FlushPendingLocked(s);
                }
                else if (diff > 0)
                {
                    // Ahead of the expected sequence — buffer as out-of-order.
                    StorePendingLocked(s, seq, payload);
                    Interlocked.Increment(ref _outOfOrderSegments);
                }
                else
                {
                    // diff < 0: overlaps already-assembled data (retransmit or partial overlap).
                    int overlap = -diff;
                    Interlocked.Increment(ref _retransmitSegments);
                    if (overlap < payload.Length)
                    {
                        ReadOnlySpan<byte> fresh = payload[overlap..];
                        AppendCapped(s, fresh);
                        s.NextSeq += (uint)fresh.Length;
                        FlushPendingLocked(s);
                    }
                    // else: entirely old data, drop.
                }
            }

            if (fin)
                s.Closed = true;

            // Build the emission (a private copy) while still holding the lock, so the
            // buffer cannot be reset by Clear/eviction between here and the callback.
            bool hasNewData = s.Length > oldLen;

            // Emit when new data arrived, OR when the stream is closing with existing data
            // (so the consumer receives the Closed=true notification even on an empty FIN/RST).
            if (hasNewData || (s.Closed && s.Length > 0))
            {
                var snapshot = new byte[s.Length];
                Array.Copy(s.Buffer, snapshot, s.Length);
                toEmit = new TcpStreamData
                {
                    Flow = key,
                    Timestamp = packet.Timestamp,
                    Data = snapshot,
                    NewDataOffset = hasNewData ? oldLen : s.Length, // no-new-data: offset == length
                    IsInitiator = s.IsInitiator,
                    Closed = s.Closed
                };
                if (hasNewData)
                    Interlocked.Add(ref _bytesAssembled, s.Length - oldLen);
            }

            if (s.Closed)
                _flows.Remove(key);
        }

        if (toEmit != null)
            OnStreamData?.Invoke(toEmit);
    }

    /// <summary>Remove every half-stream whose last activity is older than the idle timeout.</summary>
    public int EvictIdle(DateTime now)
    {
        lock (_lock) { return EvictIdleLocked(now); }
    }

    /// <summary>Drop all buffered state.</summary>
    public void Clear()
    {
        lock (_lock) { _flows.Clear(); }
    }

    // ============================================================
    // Internal helpers (all called with _lock held)
    // ============================================================

    private int EvictIdleLocked(DateTime now)
    {
        DateTime cutoff = now - _opt.IdleTimeout;
        List<TcpFlowKey>? dead = null;
        foreach (var kv in _flows)
        {
            if (kv.Value.LastActivity < cutoff)
                (dead ??= new List<TcpFlowKey>()).Add(kv.Key);
        }

        if (dead == null) return 0;
        foreach (var k in dead) _flows.Remove(k);
        Interlocked.Add(ref _flowsEvicted, dead.Count);
        return dead.Count;
    }

    private void EvictOldestLocked()
    {
        TcpFlowKey oldestKey = default;
        DateTime oldest = DateTime.MaxValue;
        bool found = false;
        foreach (var kv in _flows)
        {
            if (kv.Value.LastActivity < oldest)
            {
                oldest = kv.Value.LastActivity;
                oldestKey = kv.Key;
                found = true;
            }
        }
        if (found)
        {
            _flows.Remove(oldestKey);
            Interlocked.Increment(ref _flowsEvicted);
        }
    }

    private void StorePendingLocked(HalfStream s, uint seq, ReadOnlySpan<byte> payload)
    {
        if (s.Pending.Count >= _opt.MaxOutOfOrderSegments) return;
        if (s.PendingBytes + payload.Length > _opt.MaxOutOfOrderBytes) return;
        if (s.Pending.ContainsKey(seq)) return;             // keep the first copy seen

        s.Pending[seq] = payload.ToArray();
        s.PendingBytes += payload.Length;
    }

    private void FlushPendingLocked(HalfStream s)
    {
        while (!s.Done && s.Pending.TryGetValue(s.NextSeq, out var seg))
        {
            s.Pending.Remove(s.NextSeq);
            s.PendingBytes -= seg.Length;
            AppendCapped(s, seg);
            s.NextSeq += (uint)seg.Length;
        }
    }

    /// <summary>
    /// Append bytes to the contiguous buffer, honouring the per-stream cap. Once the cap is
    /// reached the stream is marked done and its pending buffer is discarded.
    /// </summary>
    private void AppendCapped(HalfStream s, ReadOnlySpan<byte> data)
    {
        if (s.Done || data.Length == 0) return;

        int room = _opt.MaxStreamBytes - s.Length;
        if (room <= 0)
        {
            MarkDone(s);
            return;
        }

        int take = Math.Min(room, data.Length);
        EnsureCapacity(s, s.Length + take);
        data[..take].CopyTo(s.Buffer.AsSpan(s.Length));
        s.Length += take;

        if (s.Length >= _opt.MaxStreamBytes)
            MarkDone(s);
    }

    private static void MarkDone(HalfStream s)
    {
        s.Done = true;
        s.Pending.Clear();
        s.PendingBytes = 0;
    }

    private static void EnsureCapacity(HalfStream s, int needed)
    {
        if (s.Buffer.Length >= needed) return;
        int newCap = s.Buffer.Length == 0 ? 1024 : s.Buffer.Length;
        while (newCap < needed)
        {
            int doubled = newCap * 2;
            if (doubled <= newCap)       // overflow guard (int wraparound)
            {
                newCap = needed;
                break;
            }
            newCap = doubled;
        }
        Array.Resize(ref s.Buffer, newCap);
    }

    // ============================================================
    // Per-half-connection state
    // ============================================================

    private sealed class HalfStream
    {
        public bool Established;
        public bool SawSyn;
        public bool IsInitiator;
        public bool Closed;
        public bool Done;                 // hit the byte cap; ignore further data
        public uint NextSeq;              // next expected absolute sequence number
        public byte[] Buffer;
        public int Length;
        public DateTime LastActivity;
        public readonly Dictionary<uint, byte[]> Pending = new();  // out-of-order, keyed by absolute seq
        public int PendingBytes;

        public HalfStream(int initialBytes)
        {
            Buffer = initialBytes > 0 ? new byte[initialBytes] : Array.Empty<byte>();
        }
    }
}

/// <summary>
/// Tuning knobs for <see cref="TcpStreamReassembler"/>. Defaults are sized for credential
/// recovery (the interesting bytes are at the start of a flow), not full session capture.
/// </summary>
public sealed class TcpReassemblyOptions
{
    /// <summary>Max contiguous bytes retained per half-stream. Beyond this the stream is dropped.</summary>
    public int MaxStreamBytes { get; set; } = 64 * 1024;

    /// <summary>Initial buffer allocation per half-stream (grows on demand up to the cap).</summary>
    public int InitialBufferBytes { get; set; } = 2 * 1024;

    /// <summary>Max total bytes held as out-of-order segments per half-stream.</summary>
    public int MaxOutOfOrderBytes { get; set; } = 256 * 1024;

    /// <summary>Max number of out-of-order segments buffered per half-stream.</summary>
    public int MaxOutOfOrderSegments { get; set; } = 64;

    /// <summary>Half-streams idle longer than this are evicted.</summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Hard cap on concurrent half-streams; the oldest is evicted when exceeded.</summary>
    public int MaxFlows { get; set; } = 4096;

    /// <summary>Run an idle sweep once every N fed segments.</summary>
    public long SweepEveryNSegments { get; set; } = 4096;
}

/// <summary>
/// Identifies one direction of a TCP connection (a half-connection). The reverse direction
/// is a distinct key, so each direction is reassembled independently.
/// </summary>
public readonly struct TcpFlowKey : IEquatable<TcpFlowKey>
{
    public string SrcIP { get; }
    public string DstIP { get; }
    public ushort SrcPort { get; }
    public ushort DstPort { get; }

    public TcpFlowKey(string srcIp, ushort srcPort, string dstIp, ushort dstPort)
    {
        SrcIP = srcIp;
        SrcPort = srcPort;
        DstIP = dstIp;
        DstPort = dstPort;
    }

    public bool Equals(TcpFlowKey other) =>
        SrcPort == other.SrcPort && DstPort == other.DstPort &&
        SrcIP == other.SrcIP && DstIP == other.DstIP;

    public override bool Equals(object? obj) => obj is TcpFlowKey k && Equals(k);
    public override int GetHashCode() => HashCode.Combine(SrcIP, DstIP, SrcPort, DstPort);
    public override string ToString() => $"{SrcIP}:{SrcPort} -> {DstIP}:{DstPort}";
}

/// <summary>
/// A snapshot of the contiguous bytes assembled for one half-stream, raised on each update.
/// <see cref="Data"/> is a private copy owned by the subscriber for the duration of the call.
/// </summary>
public sealed class TcpStreamData
{
    /// <summary>The half-connection these bytes belong to.</summary>
    public TcpFlowKey Flow { get; init; }

    /// <summary>Timestamp of the segment that triggered this update.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>All contiguous bytes assembled so far (capped at MaxStreamBytes).</summary>
    public ReadOnlyMemory<byte> Data { get; init; }

    /// <summary>Offset within <see cref="Data"/> where the bytes new to this update begin.</summary>
    public int NewDataOffset { get; init; }

    /// <summary>True if this side appears to be the connection initiator (client -> server).</summary>
    public bool IsInitiator { get; init; }

    /// <summary>True once a FIN or RST has been seen for this half-stream.</summary>
    public bool Closed { get; init; }
}
