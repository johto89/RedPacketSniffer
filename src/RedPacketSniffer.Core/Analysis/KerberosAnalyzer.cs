using System.Text;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// Passive Kerberos protocol analyzer for red team operations.
///
/// Capabilities:
/// 1. AS-REQ / AS-REP / TGS-REQ / TGS-REP / AP-REQ / KRB-ERROR parsing via ASN.1 DER
/// 2. Kerberoasting detection — TGS-REQ targeting service principals with RC4 (etype 23)
/// 3. AS-REP Roasting detection — AS-REP returning RC4 encrypted data (no preauth)
/// 4. Hash extraction in hashcat-compatible format ($krb5asrep$23$, $krb5tgs$23$)
/// 5. Encryption downgrade detection — RC4 usage in environment preferring AES
/// 6. Pass-the-Ticket indicators — same service ticket used from multiple source IPs
/// 7. Golden/Silver Ticket indicators — abnormal TGT/TGS lifetimes or forged PAC
/// 8. Overpass-the-Hash — AS-REQ with only RC4 etype from hosts that normally use AES
///
/// Kerberos runs on port 88 (TCP and UDP). The protocol uses ASN.1 DER encoding
/// with APPLICATION-tagged top-level messages:
///   AS-REQ    = [APPLICATION 10]
///   AS-REP    = [APPLICATION 11]
///   TGS-REQ   = [APPLICATION 12]
///   TGS-REP   = [APPLICATION 13]
///   AP-REQ    = [APPLICATION 14]
///   AP-REP    = [APPLICATION 15]
///   KRB-ERROR = [APPLICATION 30]
///
/// Threading: all mutable state is guarded by <see cref="_lock"/>.
/// <see cref="Analyze"/> is safe to call from multiple capture threads.
/// Events are raised outside the lock to prevent deadlocks.
/// </summary>
public sealed class KerberosAnalyzer
{
    // ============================================================
    // Constants
    // ============================================================

    private const int KerberosPort = 88;

    // ASN.1 APPLICATION tags for Kerberos message types
    private const byte TagAsReq    = 10; // [APPLICATION 10]
    private const byte TagAsRep    = 11; // [APPLICATION 11]
    private const byte TagTgsReq   = 12; // [APPLICATION 12]
    private const byte TagTgsRep   = 13; // [APPLICATION 13]
    private const byte TagApReq    = 14; // [APPLICATION 14]
    private const byte TagApRep    = 15; // [APPLICATION 15]
    private const byte TagKrbError = 30; // [APPLICATION 30]

    // Kerberos encryption types (RFC 3961 / RFC 4757)
    private const int EtypeDES_CBC_CRC       = 1;
    private const int EtypeDES_CBC_MD4       = 2;
    private const int EtypeDES_CBC_MD5       = 3;
    private const int EtypeRC4_HMAC          = 23; // arcfour-hmac-md5
    private const int EtypeRC4_HMAC_EXP      = 24; // arcfour-hmac-md5-exp (export)
    private const int EtypeAES128_CTS_SHA1   = 17;
    private const int EtypeAES256_CTS_SHA1   = 18;
    private const int EtypeAES128_CTS_SHA256 = 19;
    private const int EtypeAES256_CTS_SHA384 = 20;

    // KRB-ERROR codes of interest
    private const int KDC_ERR_PREAUTH_REQUIRED  = 25; // Need preauth
    private const int KDC_ERR_PREAUTH_FAILED    = 24; // Preauth failed (wrong password)
    private const int KDC_ERR_C_PRINCIPAL_UNKNOWN = 6; // Client not found
    private const int KDC_ERR_S_PRINCIPAL_UNKNOWN = 7; // Server not found

    // Deduplication / tracking thresholds
    private static readonly TimeSpan DedupWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan StateMaxAge = TimeSpan.FromMinutes(30);
    private const int MaxTrackedEntries = 10_000;
    private const int PruneEveryPackets = 2048;

    // ============================================================
    // State
    // ============================================================

    private readonly List<KerberosEvent> _events = new();
    private readonly object _lock = new();

    // Deduplication: signature -> last report time
    private readonly Dictionary<string, DateTime> _seen = new();
    private DateTime _lastSeenCleanup = DateTime.MinValue;

    // Encryption type tracking per principal: "realm\principal" -> set of etypes used in AS-REQ
    private readonly Dictionary<string, HashSet<int>> _principalEtypes = new();

    // Host etype profile: srcIP -> set of etypes seen in AS-REQ
    private readonly Dictionary<string, HashSet<int>> _hostEtypeProfile = new();

    // Ticket reuse tracking: "sname@realm" -> dict of (srcIP -> last seen)
    private readonly Dictionary<string, Dictionary<string, DateTime>> _ticketSourceTracker = new();

    // TGS-REQ tracking for Kerberoasting: srcIP -> list of (sname, timestamp) within window
    private readonly Dictionary<string, List<(string sname, DateTime time)>> _tgsReqBurst = new();

    private long _packetCounter;

    // ============================================================
    // Events
    // ============================================================

    /// <summary>Raised when a Kerberos security event is detected.</summary>
    public event Action<KerberosEvent>? OnKerberosEvent;

    /// <summary>Raised on parsing errors for diagnostics.</summary>
    public event Action<Exception>? OnError;

    // ============================================================
    // Public API
    // ============================================================

    /// <summary>
    /// Analyze a single packet for Kerberos protocol activity.
    /// </summary>
    public void Analyze(CapturedPacket packet)
    {
        if (packet.RawData.Length == 0) return;

        // Kerberos runs on port 88 TCP/UDP
        if (packet.IpProtocol != 6 && packet.IpProtocol != 17) return;
        if (packet.SourcePort != KerberosPort && packet.DestPort != KerberosPort) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 10) return; // Minimum viable Kerberos message

        // For TCP, Kerberos prepends a 4-byte record length mark (RFC 4120 §7.2.1)
        if (packet.IpProtocol == 6)
        {
            if (payload.Length < 14) return;
            int recordLen = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
            if (recordLen < 10 || recordLen > payload.Length - 4) return;
            payload = payload.Slice(4, recordLen);
        }

        // Periodic state cleanup
        if (Interlocked.Increment(ref _packetCounter) % PruneEveryPackets == 0)
            PruneState(packet.Timestamp);

        try
        {
            // Identify the message type from the ASN.1 APPLICATION tag
            if (payload.Length < 2) return;
            byte tag = payload[0];

            // APPLICATION tags are encoded as 0x60 | tag_number for tags 0-30
            // For tag > 30: 0x7F followed by tag_number (long form)
            int msgType;
            int contentOffset;

            if ((tag & 0xE0) == 0x60) // APPLICATION CONSTRUCTED, short tag
            {
                msgType = tag & 0x1F;
                if (msgType == 0x1F) // long form tag
                {
                    if (payload.Length < 3) return;
                    msgType = payload[1] & 0x7F;
                    contentOffset = 2;
                }
                else
                {
                    contentOffset = 1;
                }
            }
            else
            {
                return; // Not a Kerberos APPLICATION message
            }

            // Parse the length field
            if (!TryReadAsn1Length(payload, ref contentOffset, out int contentLength)) return;
            if (contentOffset + contentLength > payload.Length) return;

            var content = payload.Slice(contentOffset, Math.Min(contentLength, payload.Length - contentOffset));

            // Set ApplicationProtocol hint on the packet
            packet.ApplicationProtocol = "Kerberos";

            switch (msgType)
            {
                case TagAsReq:
                    HandleAsReq(content, packet);
                    break;
                case TagAsRep:
                    HandleAsRep(content, packet);
                    break;
                case TagTgsReq:
                    HandleTgsReq(content, packet);
                    break;
                case TagTgsRep:
                    HandleTgsRep(content, packet);
                    break;
                case TagApReq:
                    HandleApReq(content, packet);
                    break;
                case TagKrbError:
                    HandleKrbError(content, packet);
                    break;
            }
        }
        catch (Exception ex)
        {
            OnError?.Invoke(ex);
        }
    }

    /// <summary>Returns a snapshot of all detected Kerberos events.</summary>
    public List<KerberosEvent> GetEvents()
    {
        lock (_lock) { return new List<KerberosEvent>(_events); }
    }

    /// <summary>Clears all tracked state and events.</summary>
    public void Clear()
    {
        lock (_lock)
        {
            _events.Clear();
            _seen.Clear();
            _principalEtypes.Clear();
            _hostEtypeProfile.Clear();
            _ticketSourceTracker.Clear();
            _tgsReqBurst.Clear();
        }
    }

    // ============================================================
    // Message Handlers
    // ============================================================

    /// <summary>
    /// Parse AS-REQ (Authentication Service Request).
    /// Extract: client principal (cname), realm, requested etypes, padata (preauth data).
    ///
    /// AS-REQ structure (RFC 4120 §5.4.1):
    ///   AS-REQ ::= [APPLICATION 10] KDC-REQ
    ///   KDC-REQ ::= SEQUENCE {
    ///     pvno     [1] INTEGER,
    ///     msg-type [2] INTEGER,
    ///     padata   [3] SEQUENCE OF PA-DATA OPTIONAL,
    ///     req-body [4] KDC-REQ-BODY
    ///   }
    ///   KDC-REQ-BODY ::= SEQUENCE {
    ///     kdc-options [0] BIT STRING,
    ///     cname       [1] PrincipalName OPTIONAL,
    ///     realm       [2] Realm,
    ///     sname       [3] PrincipalName OPTIONAL,
    ///     ...
    ///     etype       [8] SEQUENCE OF Int32,
    ///     ...
    ///   }
    /// </summary>
    private void HandleAsReq(ReadOnlySpan<byte> data, CapturedPacket packet)
    {
        // Navigate into the KDC-REQ SEQUENCE
        if (!TryEnterSequence(data, out var seqContent)) return;

        string? clientPrincipal = null;
        string? realm = null;
        List<int>? requestedEtypes = null;
        bool hasPaEncTimestamp = false;
        byte[]? paEncTimestampData = null;
        int paEncTimestampEtype = 0;

        // Walk the tagged fields of KDC-REQ
        int pos = 0;
        while (pos < seqContent.Length)
        {
            if (!TryReadContextTag(seqContent, ref pos, out int tagNum, out var tagContent)) break;

            switch (tagNum)
            {
                case 3: // padata — SEQUENCE OF PA-DATA
                    ParsePaData(tagContent, out hasPaEncTimestamp, out paEncTimestampData, out paEncTimestampEtype);
                    break;
                case 4: // req-body
                    if (TryEnterSequence(tagContent, out var bodyContent))
                        ParseKdcReqBody(bodyContent, out clientPrincipal, out realm, out _, out requestedEtypes);
                    break;
            }
        }

        if (clientPrincipal == null || realm == null) return;

        string fullPrincipal = $"{clientPrincipal}@{realm}";

        // Track encryption types requested by this principal/host
        if (requestedEtypes != null)
        {
            TrackPrincipalEtypes(fullPrincipal, requestedEtypes);
            TrackHostEtypes(packet.SourceIP ?? "", requestedEtypes);

            // Check for encryption downgrade: AS-REQ requesting only weak etypes
            CheckEncryptionDowngrade(requestedEtypes, fullPrincipal, packet, "AS-REQ");
        }

        // Check for Overpass-the-Hash: AS-REQ with only RC4 from a host that previously used AES
        if (requestedEtypes != null)
            CheckOverpassTheHash(requestedEtypes, packet);

        // If padata contains PA-ENC-TIMESTAMP with RC4, extract the hash
        if (hasPaEncTimestamp && paEncTimestampData != null && paEncTimestampEtype == EtypeRC4_HMAC)
        {
            string hashHex = BytesToHex(paEncTimestampData);
            string hashcatHash = $"$krb5pa$23${clientPrincipal}${realm}$${hashHex}";

            ReportEvent(new KerberosEvent
            {
                Timestamp = packet.Timestamp,
                EventType = KerberosEventType.HashCaptured,
                Category = "Credential",
                Name = "Kerberos PA-ENC-TIMESTAMP Hash (RC4)",
                Description = $"Captured RC4-encrypted PA-ENC-TIMESTAMP from AS-REQ for {fullPrincipal}. " +
                              "This hash can be cracked offline to recover the user's password.",
                SourceIP = packet.SourceIP ?? "",
                DestIP = packet.DestIP ?? "",
                Port = packet.DestPort,
                Severity = KerberosEventSeverity.Critical,
                Principal = fullPrincipal,
                Realm = realm,
                EncryptionType = EtypeRC4_HMAC,
                HashcatHash = hashcatHash,
                HashcatMode = 7500,
                ExploitPath = "Crack offline with hashcat -m 7500. RC4 PA-ENC-TIMESTAMP hashes are fast to crack.",
                Mitigation = "Enforce AES-only Kerberos encryption. Disable RC4 via GPO: " +
                             "Computer Configuration > Policies > Windows Settings > Security Settings > " +
                             "Local Policies > Security Options > Network security: Configure encryption types allowed for Kerberos.",
                PacketId = packet.Id
            });
        }

        // Informational event
        string etypeStr = requestedEtypes != null ? string.Join(",", requestedEtypes.Select(EtypeName)) : "?";
        ReportEvent(new KerberosEvent
        {
            Timestamp = packet.Timestamp,
            EventType = KerberosEventType.AsReq,
            Category = "Authentication",
            Name = "Kerberos AS-REQ",
            Description = $"AS-REQ from {packet.SourceIP} for {fullPrincipal}, requested etypes: [{etypeStr}], " +
                          $"preauth: {(hasPaEncTimestamp ? "PA-ENC-TIMESTAMP" : "none")}",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = packet.DestPort,
            Severity = KerberosEventSeverity.Info,
            Principal = fullPrincipal,
            Realm = realm,
            PacketId = packet.Id
        }, dedup: true);
    }

    /// <summary>
    /// Parse AS-REP (Authentication Service Reply).
    /// Detect AS-REP Roasting: if the reply uses RC4 encryption for the enc-part,
    /// extract the hash in hashcat $krb5asrep$23$ format.
    ///
    /// AS-REP structure (RFC 4120 §5.4.2):
    ///   AS-REP ::= [APPLICATION 11] KDC-REP
    ///   KDC-REP ::= SEQUENCE {
    ///     pvno     [0] INTEGER,
    ///     msg-type [1] INTEGER,
    ///     padata   [2] SEQUENCE OF PA-DATA OPTIONAL,
    ///     crealm   [3] Realm,
    ///     cname    [4] PrincipalName,
    ///     ticket   [5] Ticket,
    ///     enc-part [6] EncryptedData
    ///   }
    ///   EncryptedData ::= SEQUENCE {
    ///     etype  [0] Int32,
    ///     kvno   [1] UInt32 OPTIONAL,
    ///     cipher [2] OCTET STRING
    ///   }
    /// </summary>
    private void HandleAsRep(ReadOnlySpan<byte> data, CapturedPacket packet)
    {
        if (!TryEnterSequence(data, out var seqContent)) return;

        string? crealm = null;
        string? cname = null;
        int encPartEtype = 0;
        byte[]? encPartCipher = null;
        int ticketEtype = 0;
        byte[]? ticketCipher = null;

        int pos = 0;
        while (pos < seqContent.Length)
        {
            if (!TryReadContextTag(seqContent, ref pos, out int tagNum, out var tagContent)) break;

            switch (tagNum)
            {
                case 3: // crealm
                    crealm = TryReadAsn1String(tagContent);
                    break;
                case 4: // cname
                    cname = ParsePrincipalName(tagContent);
                    break;
                case 5: // ticket — parse for Golden Ticket detection
                    ParseTicketForAnalysis(tagContent, out ticketEtype, out ticketCipher);
                    break;
                case 6: // enc-part
                    ParseEncryptedData(tagContent, out encPartEtype, out _, out encPartCipher);
                    break;
            }
        }

        if (cname == null || crealm == null) return;

        string fullPrincipal = $"{cname}@{crealm}";

        // AS-REP Roasting: if enc-part uses RC4 and this principal had no preauth required
        if (encPartEtype == EtypeRC4_HMAC && encPartCipher != null && encPartCipher.Length > 0)
        {
            // hashcat format for AS-REP roast: $krb5asrep$23$user@REALM:cipher
            // The cipher is the full EncryptedData cipher field
            string cipherHex = BytesToHex(encPartCipher);

            // Split cipher into checksum (first 32 hex = 16 bytes) and edata2 (rest)
            string hashcatHash;
            if (cipherHex.Length > 32)
            {
                string checksum = cipherHex.Substring(0, 32);
                string edata2 = cipherHex.Substring(32);
                hashcatHash = $"$krb5asrep$23${cname}@{crealm}:{checksum}${edata2}";
            }
            else
            {
                hashcatHash = $"$krb5asrep$23${cname}@{crealm}:{cipherHex}";
            }

            ReportEvent(new KerberosEvent
            {
                Timestamp = packet.Timestamp,
                EventType = KerberosEventType.AsRepRoast,
                Category = "Credential",
                Name = "AS-REP Roasting — Hash Captured",
                Description = $"AS-REP for {fullPrincipal} returned RC4-encrypted data without preauthentication. " +
                              "This account has 'Do not require Kerberos preauthentication' enabled, " +
                              "allowing offline password cracking.",
                SourceIP = packet.SourceIP ?? "", // KDC
                DestIP = packet.DestIP ?? "",     // Client
                Port = packet.SourcePort,
                Severity = KerberosEventSeverity.Critical,
                Principal = fullPrincipal,
                Realm = crealm,
                EncryptionType = EtypeRC4_HMAC,
                HashcatHash = hashcatHash,
                HashcatMode = 18200,
                ExploitPath = "Crack offline with hashcat -m 18200. AS-REP roast hashes are as fast as NTLM to crack. " +
                              "Tool: GetNPUsers.py (Impacket) or Rubeus asreproast.",
                Mitigation = "Disable 'Do not require Kerberos preauthentication' on all accounts. " +
                             "Enforce AES encryption and disable RC4.",
                PacketId = packet.Id
            });
        }

        // Check if ticket uses weak encryption (potential for Golden/Silver ticket forging)
        if (ticketEtype is EtypeRC4_HMAC or EtypeDES_CBC_MD5 or EtypeDES_CBC_CRC or EtypeDES_CBC_MD4)
        {
            ReportEvent(new KerberosEvent
            {
                Timestamp = packet.Timestamp,
                EventType = KerberosEventType.WeakTicketEncryption,
                Category = "Weakness",
                Name = "Weak Ticket Encryption in AS-REP",
                Description = $"TGT for {fullPrincipal} encrypted with {EtypeName(ticketEtype)}. " +
                              "Weak encryption makes the KRBTGT hash easier to abuse for Golden Ticket attacks.",
                SourceIP = packet.SourceIP ?? "",
                DestIP = packet.DestIP ?? "",
                Port = packet.SourcePort,
                Severity = KerberosEventSeverity.High,
                Principal = fullPrincipal,
                Realm = crealm,
                EncryptionType = ticketEtype,
                ExploitPath = "If KRBTGT hash is obtained (DCSync), forging Golden Tickets with RC4 is trivial. " +
                              "Tool: ticketer.py (Impacket) or mimikatz kerberos::golden.",
                Mitigation = "Disable RC4/DES for Kerberos via GPO. Rotate KRBTGT password twice.",
                PacketId = packet.Id
            }, dedup: true);
        }

        // Informational
        ReportEvent(new KerberosEvent
        {
            Timestamp = packet.Timestamp,
            EventType = KerberosEventType.AsRep,
            Category = "Authentication",
            Name = "Kerberos AS-REP",
            Description = $"AS-REP from KDC {packet.SourceIP} for {fullPrincipal}, " +
                          $"enc-part etype: {EtypeName(encPartEtype)}, " +
                          $"ticket etype: {EtypeName(ticketEtype)}",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = packet.SourcePort,
            Severity = KerberosEventSeverity.Info,
            Principal = fullPrincipal,
            Realm = crealm,
            EncryptionType = encPartEtype,
            PacketId = packet.Id
        }, dedup: true);
    }

    /// <summary>
    /// Parse TGS-REQ (Ticket Granting Service Request).
    /// Detect Kerberoasting: rapid TGS-REQ for service principals requesting RC4.
    ///
    /// TGS-REQ has the same structure as AS-REQ (KDC-REQ) but with APPLICATION tag 12.
    /// The sname in req-body identifies the service principal being requested.
    /// </summary>
    private void HandleTgsReq(ReadOnlySpan<byte> data, CapturedPacket packet)
    {
        if (!TryEnterSequence(data, out var seqContent)) return;

        string? clientPrincipal = null;
        string? realm = null;
        string? servicePrincipal = null;
        List<int>? requestedEtypes = null;

        int pos = 0;
        while (pos < seqContent.Length)
        {
            if (!TryReadContextTag(seqContent, ref pos, out int tagNum, out var tagContent)) break;

            switch (tagNum)
            {
                case 4: // req-body
                    if (TryEnterSequence(tagContent, out var bodyContent))
                        ParseKdcReqBody(bodyContent, out clientPrincipal, out realm, out servicePrincipal, out requestedEtypes);
                    break;
            }
        }

        if (realm == null) return;

        string sname = servicePrincipal ?? "unknown";
        string srcIp = packet.SourceIP ?? "";

        // Kerberoasting detection: TGS-REQ requesting RC4 for a service principal
        bool requestsRc4 = requestedEtypes?.Contains(EtypeRC4_HMAC) == true;
        bool isSPN = sname.Contains('/'); // Service principals have format service/hostname

        if (requestsRc4 && isSPN)
        {
            ReportEvent(new KerberosEvent
            {
                Timestamp = packet.Timestamp,
                EventType = KerberosEventType.Kerberoast,
                Category = "Credential",
                Name = "Kerberoasting — TGS-REQ with RC4 for SPN",
                Description = $"TGS-REQ from {srcIp} requesting RC4 (etype 23) for service principal {sname}@{realm}. " +
                              "This is a classic Kerberoasting pattern — requesting a service ticket with weak encryption " +
                              "to crack offline and recover the service account password.",
                SourceIP = srcIp,
                DestIP = packet.DestIP ?? "",
                Port = packet.DestPort,
                Severity = KerberosEventSeverity.Critical,
                Principal = sname,
                Realm = realm,
                EncryptionType = EtypeRC4_HMAC,
                ExploitPath = "Capture TGS-REP, extract hash, crack with hashcat -m 13100. " +
                              "Tool: GetUserSPNs.py (Impacket) or Rubeus kerberoast.",
                Mitigation = "Use Group Managed Service Accounts (gMSA) with 120+ character passwords. " +
                             "Disable RC4 for Kerberos. Monitor for TGS-REQ bursts targeting multiple SPNs.",
                PacketId = packet.Id
            });
        }

        // Track TGS-REQ burst for Kerberoasting pattern (multiple SPNs from same source)
        if (isSPN)
        {
            lock (_lock)
            {
                if (!_tgsReqBurst.TryGetValue(srcIp, out var burstList))
                {
                    burstList = new List<(string, DateTime)>();
                    _tgsReqBurst[srcIp] = burstList;
                }

                // Remove old entries
                burstList.RemoveAll(e => packet.Timestamp - e.time > TimeSpan.FromMinutes(2));
                burstList.Add((sname, packet.Timestamp));

                // Alert if many distinct SPNs queried in a short window
                int distinctSpns = burstList.Select(e => e.sname).Distinct().Count();
                if (distinctSpns >= 5)
                {
                    string sig = $"kerberoast-burst|{srcIp}";
                    if (ShouldReport(sig, packet.Timestamp))
                    {
                        var spnList = burstList.Select(e => e.sname).Distinct().Take(10);
                        var evt = new KerberosEvent
                        {
                            Timestamp = packet.Timestamp,
                            EventType = KerberosEventType.KerberoastBurst,
                            Category = "Attack",
                            Name = "Kerberoasting Burst Detected",
                            Description = $"Host {srcIp} requested {distinctSpns} distinct service tickets within 2 minutes. " +
                                          $"SPNs targeted: {string.Join(", ", spnList)}" +
                                          (distinctSpns > 10 ? $" (and {distinctSpns - 10} more)" : ""),
                            SourceIP = srcIp,
                            DestIP = packet.DestIP ?? "",
                            Port = packet.DestPort,
                            Severity = KerberosEventSeverity.Critical,
                            Realm = realm,
                            ExploitPath = "This is an active Kerberoasting attack in progress. The attacker is " +
                                          "enumerating service accounts by requesting tickets for multiple SPNs.",
                            Mitigation = "Isolate the source host immediately. Check for compromised credentials. " +
                                          "Review service account passwords and convert to gMSA.",
                            PacketId = packet.Id
                        };
                        lock (_lock) { _events.Add(evt); }
                        OnKerberosEvent?.Invoke(evt);
                    }
                }
            }
        }

        // Encryption downgrade in TGS-REQ
        if (requestedEtypes != null)
            CheckEncryptionDowngrade(requestedEtypes, sname, packet, "TGS-REQ");

        // Informational
        string etypeStr = requestedEtypes != null ? string.Join(",", requestedEtypes.Select(EtypeName)) : "?";
        ReportEvent(new KerberosEvent
        {
            Timestamp = packet.Timestamp,
            EventType = KerberosEventType.TgsReq,
            Category = "Service Ticket",
            Name = "Kerberos TGS-REQ",
            Description = $"TGS-REQ from {srcIp} for {sname}@{realm}, requested etypes: [{etypeStr}]",
            SourceIP = srcIp,
            DestIP = packet.DestIP ?? "",
            Port = packet.DestPort,
            Severity = KerberosEventSeverity.Info,
            Principal = sname,
            Realm = realm,
            PacketId = packet.Id
        }, dedup: true);
    }

    /// <summary>
    /// Parse TGS-REP (Ticket Granting Service Reply).
    /// Extract Kerberoast hash when ticket is encrypted with RC4.
    ///
    /// TGS-REP structure follows KDC-REP (same as AS-REP but APPLICATION 13).
    /// The ticket's enc-part cipher is the hash we need for Kerberoasting.
    /// </summary>
    private void HandleTgsRep(ReadOnlySpan<byte> data, CapturedPacket packet)
    {
        if (!TryEnterSequence(data, out var seqContent)) return;

        string? crealm = null;
        string? cname = null;
        int ticketEtype = 0;
        byte[]? ticketCipher = null;
        string? ticketSname = null;
        string? ticketRealm = null;

        int pos = 0;
        while (pos < seqContent.Length)
        {
            if (!TryReadContextTag(seqContent, ref pos, out int tagNum, out var tagContent)) break;

            switch (tagNum)
            {
                case 3: // crealm
                    crealm = TryReadAsn1String(tagContent);
                    break;
                case 4: // cname
                    cname = ParsePrincipalName(tagContent);
                    break;
                case 5: // ticket
                    ParseTicketFull(tagContent, out ticketEtype, out ticketCipher, out ticketSname, out ticketRealm);
                    break;
            }
        }

        if (cname == null || crealm == null) return;

        string fullPrincipal = $"{cname}@{crealm}";
        string sname = ticketSname ?? "unknown";

        // Kerberoasting hash extraction: if ticket encrypted with RC4
        if (ticketEtype == EtypeRC4_HMAC && ticketCipher != null && ticketCipher.Length > 0)
        {
            string cipherHex = BytesToHex(ticketCipher);

            // hashcat format for TGS (Kerberoast): $krb5tgs$23$*user$realm$spn*$checksum$edata2
            string hashcatHash;
            if (cipherHex.Length > 32)
            {
                string checksum = cipherHex.Substring(0, 32);
                string edata2 = cipherHex.Substring(32);
                hashcatHash = $"$krb5tgs$23$*{cname}${crealm}${sname}*${checksum}${edata2}";
            }
            else
            {
                hashcatHash = $"$krb5tgs$23$*{cname}${crealm}${sname}*${cipherHex}";
            }

            ReportEvent(new KerberosEvent
            {
                Timestamp = packet.Timestamp,
                EventType = KerberosEventType.KerberoastHash,
                Category = "Credential",
                Name = "Kerberoast Hash Captured (TGS-REP)",
                Description = $"TGS-REP from KDC for {sname} (requested by {fullPrincipal}) " +
                              $"encrypted with RC4. Service account password can be cracked offline.",
                SourceIP = packet.SourceIP ?? "", // KDC
                DestIP = packet.DestIP ?? "",     // Client
                Port = packet.SourcePort,
                Severity = KerberosEventSeverity.Critical,
                Principal = sname,
                Realm = ticketRealm ?? crealm,
                EncryptionType = EtypeRC4_HMAC,
                HashcatHash = hashcatHash,
                HashcatMode = 13100,
                ExploitPath = "Crack offline with hashcat -m 13100. RC4 TGS tickets are equivalent " +
                              "to cracking NTLM. A weak service account password falls in seconds.",
                Mitigation = "Convert service accounts to gMSA (128-char auto-rotated passwords). " +
                             "Disable RC4 encryption. Set long (25+ char) passwords on legacy service accounts.",
                PacketId = packet.Id
            });
        }

        // Track ticket reuse for Pass-the-Ticket detection
        if (ticketSname != null)
            TrackTicketSource(ticketSname, ticketRealm ?? crealm, packet.DestIP ?? "", packet.Timestamp);

        ReportEvent(new KerberosEvent
        {
            Timestamp = packet.Timestamp,
            EventType = KerberosEventType.TgsRep,
            Category = "Service Ticket",
            Name = "Kerberos TGS-REP",
            Description = $"TGS-REP from KDC {packet.SourceIP} for {sname}@{ticketRealm ?? crealm}, " +
                          $"ticket etype: {EtypeName(ticketEtype)}, client: {fullPrincipal}",
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            Port = packet.SourcePort,
            Severity = KerberosEventSeverity.Info,
            Principal = sname,
            Realm = ticketRealm ?? crealm,
            EncryptionType = ticketEtype,
            PacketId = packet.Id
        }, dedup: true);
    }

    /// <summary>
    /// Parse AP-REQ (Application Request) — detects ticket reuse across IPs (Pass-the-Ticket).
    /// AP-REQ contains the service ticket being presented to a service.
    /// We track which source IPs present tickets for the same service to detect lateral movement.
    /// </summary>
    private void HandleApReq(ReadOnlySpan<byte> data, CapturedPacket packet)
    {
        // AP-REQ ::= [APPLICATION 14] SEQUENCE {
        //   pvno     [0] INTEGER,
        //   msg-type [1] INTEGER,
        //   ap-options [2] BIT STRING,
        //   ticket   [3] Ticket,
        //   authenticator [4] EncryptedData
        // }
        if (!TryEnterSequence(data, out var seqContent)) return;

        int ticketEtype = 0;
        string? ticketSname = null;
        string? ticketRealm = null;

        int pos = 0;
        while (pos < seqContent.Length)
        {
            if (!TryReadContextTag(seqContent, ref pos, out int tagNum, out var tagContent)) break;

            if (tagNum == 3) // ticket
            {
                ParseTicketFull(tagContent, out ticketEtype, out _, out ticketSname, out ticketRealm);
            }
        }

        if (ticketSname != null && ticketRealm != null)
        {
            TrackTicketSource(ticketSname, ticketRealm, packet.SourceIP ?? "", packet.Timestamp);
        }
    }

    /// <summary>
    /// Parse KRB-ERROR — detect preauth-not-required (AS-REP Roasting candidate),
    /// failed authentications, and unknown principals (user enumeration).
    ///
    /// KRB-ERROR ::= [APPLICATION 30] SEQUENCE {
    ///   pvno       [0] INTEGER,
    ///   msg-type   [1] INTEGER,
    ///   ctime      [2] KerberosTime OPTIONAL,
    ///   cusec      [3] Microseconds OPTIONAL,
    ///   stime      [4] KerberosTime,
    ///   susec      [5] Microseconds,
    ///   error-code [6] Int32,
    ///   crealm     [7] Realm OPTIONAL,
    ///   cname      [8] PrincipalName OPTIONAL,
    ///   realm      [9] Realm,
    ///   sname      [10] PrincipalName,
    ///   e-text     [11] KerberosString OPTIONAL,
    ///   e-data     [12] OCTET STRING OPTIONAL
    /// }
    /// </summary>
    private void HandleKrbError(ReadOnlySpan<byte> data, CapturedPacket packet)
    {
        if (!TryEnterSequence(data, out var seqContent)) return;

        int errorCode = -1;
        string? crealm = null;
        string? cname = null;
        string? srealm = null;
        string? sname = null;
        string? etext = null;

        int pos = 0;
        while (pos < seqContent.Length)
        {
            if (!TryReadContextTag(seqContent, ref pos, out int tagNum, out var tagContent)) break;

            switch (tagNum)
            {
                case 6: // error-code
                    errorCode = TryReadAsn1Integer(tagContent);
                    break;
                case 7: // crealm
                    crealm = TryReadAsn1String(tagContent);
                    break;
                case 8: // cname
                    cname = ParsePrincipalName(tagContent);
                    break;
                case 9: // realm
                    srealm = TryReadAsn1String(tagContent);
                    break;
                case 10: // sname
                    sname = ParsePrincipalName(tagContent);
                    break;
                case 11: // e-text
                    etext = TryReadAsn1String(tagContent);
                    break;
            }
        }

        string principal = cname != null && crealm != null ? $"{cname}@{crealm}" :
                           cname ?? "unknown";

        // KDC_ERR_PREAUTH_REQUIRED = account exists but needs preauth
        // Absence of this error for a valid principal = no preauth required = AS-REP Roastable
        if (errorCode == KDC_ERR_PREAUTH_REQUIRED && cname != null && crealm != null)
        {
            // This is normal — account requires preauth. But track it:
            // if we later see an AS-REP without preauth for the same principal, that's interesting.
        }

        // KDC_ERR_PREAUTH_FAILED — wrong password attempt
        if (errorCode == KDC_ERR_PREAUTH_FAILED)
        {
            ReportEvent(new KerberosEvent
            {
                Timestamp = packet.Timestamp,
                EventType = KerberosEventType.PreauthFailed,
                Category = "Authentication",
                Name = "Kerberos Preauth Failed",
                Description = $"Preauthentication failed for {principal} from {packet.DestIP}. " +
                              "Incorrect password was supplied. May indicate brute-force or password spraying.",
                SourceIP = packet.SourceIP ?? "",
                DestIP = packet.DestIP ?? "",
                Port = packet.SourcePort,
                Severity = KerberosEventSeverity.Medium,
                Principal = principal,
                Realm = crealm ?? srealm ?? "",
                ExploitPath = "Multiple failures from same source may indicate password spraying. " +
                              "Monitor for pattern: same source, different usernames, short intervals.",
                Mitigation = "Enable account lockout policies. Monitor event IDs 4771 (Kerberos preauth failed) " +
                             "and 4768 (TGT requested). Consider smart card authentication.",
                PacketId = packet.Id
            }, dedup: true);
        }

        // KDC_ERR_C_PRINCIPAL_UNKNOWN — user enumeration
        if (errorCode == KDC_ERR_C_PRINCIPAL_UNKNOWN)
        {
            ReportEvent(new KerberosEvent
            {
                Timestamp = packet.Timestamp,
                EventType = KerberosEventType.UserEnumeration,
                Category = "Reconnaissance",
                Name = "Kerberos User Enumeration",
                Description = $"KDC responded 'client principal unknown' for {principal}. " +
                              "Differential responses (unknown vs preauth-required) enable user enumeration.",
                SourceIP = packet.DestIP ?? "", // The client who sent the AS-REQ
                DestIP = packet.SourceIP ?? "", // KDC
                Port = packet.SourcePort,
                Severity = KerberosEventSeverity.Medium,
                Principal = principal,
                Realm = crealm ?? srealm ?? "",
                ExploitPath = "Use kerbrute or nmap krb5-enum-users to enumerate valid usernames. " +
                              "Combine with AS-REP Roasting or password spraying.",
                Mitigation = "Cannot fully prevent — Kerberos protocol inherently reveals principal existence. " +
                             "Monitor for high-volume AS-REQ from single source with varied principals.",
                PacketId = packet.Id
            }, dedup: true);
        }
    }

    // ============================================================
    // Detection Logic
    // ============================================================

    /// <summary>
    /// Detect encryption downgrade: AS-REQ or TGS-REQ requesting only weak etypes
    /// (RC4, DES) without any AES option.
    /// </summary>
    private void CheckEncryptionDowngrade(List<int> etypes, string principal, CapturedPacket packet, string msgType)
    {
        bool hasAes = etypes.Any(e => e is EtypeAES128_CTS_SHA1 or EtypeAES256_CTS_SHA1
                                       or EtypeAES128_CTS_SHA256 or EtypeAES256_CTS_SHA384);
        bool hasWeak = etypes.Any(e => e is EtypeRC4_HMAC or EtypeRC4_HMAC_EXP
                                        or EtypeDES_CBC_CRC or EtypeDES_CBC_MD4 or EtypeDES_CBC_MD5);

        // Only flag if ONLY weak etypes are requested — no AES at all
        if (hasWeak && !hasAes)
        {
            string weakList = string.Join(", ", etypes.Where(e => e is EtypeRC4_HMAC or EtypeRC4_HMAC_EXP
                or EtypeDES_CBC_CRC or EtypeDES_CBC_MD4 or EtypeDES_CBC_MD5).Select(EtypeName));

            ReportEvent(new KerberosEvent
            {
                Timestamp = packet.Timestamp,
                EventType = KerberosEventType.EncryptionDowngrade,
                Category = "Weakness",
                Name = $"Kerberos Encryption Downgrade ({msgType})",
                Description = $"{msgType} for {principal} requests only weak encryption: [{weakList}]. " +
                              "No AES variant is offered, indicating legacy configuration or deliberate downgrade.",
                SourceIP = packet.SourceIP ?? "",
                DestIP = packet.DestIP ?? "",
                Port = packet.DestPort,
                Severity = KerberosEventSeverity.High,
                Principal = principal,
                EncryptionType = etypes.First(),
                ExploitPath = "RC4-encrypted tickets are trivial to crack offline. DES is even weaker. " +
                              "An attacker forcing etype downgrade can Kerberoast at NTLM-crack speed.",
                Mitigation = "Disable DES and RC4 in domain GPO. Ensure all systems support AES. " +
                             "Check msDS-SupportedEncryptionTypes on service accounts.",
                PacketId = packet.Id
            }, dedup: true);
        }
    }

    /// <summary>
    /// Detect Overpass-the-Hash (Pass-the-Key): AS-REQ with only RC4 from a host
    /// that previously used AES. This happens when an attacker uses an NTLM hash
    /// to request a TGT via RC4, downgrading from the host's normal AES profile.
    /// </summary>
    private void CheckOverpassTheHash(List<int> etypes, CapturedPacket packet)
    {
        string srcIp = packet.SourceIP ?? "";
        if (string.IsNullOrEmpty(srcIp)) return;

        bool onlyRc4 = etypes.All(e => e is EtypeRC4_HMAC or EtypeRC4_HMAC_EXP);
        if (!onlyRc4) return;

        bool shouldAlert = false;

        lock (_lock)
        {
            if (_hostEtypeProfile.TryGetValue(srcIp, out var historicalEtypes))
            {
                shouldAlert = historicalEtypes.Any(e => e is EtypeAES128_CTS_SHA1 or EtypeAES256_CTS_SHA1
                                                          or EtypeAES128_CTS_SHA256 or EtypeAES256_CTS_SHA384);
            }
        }

        if (shouldAlert)
        {
            string sig = $"overpass|{srcIp}";
            if (ShouldReport(sig, packet.Timestamp))
            {
                var evt = new KerberosEvent
                {
                    Timestamp = packet.Timestamp,
                    EventType = KerberosEventType.OverpassTheHash,
                    Category = "Attack",
                    Name = "Overpass-the-Hash (Pass-the-Key) Suspected",
                    Description = $"Host {srcIp} sent AS-REQ with only RC4 encryption, but historically " +
                                  "used AES. This pattern matches Overpass-the-Hash: an attacker with an " +
                                  "NTLM hash (but not the plaintext password) requests a TGT using RC4.",
                    SourceIP = srcIp,
                    DestIP = packet.DestIP ?? "",
                    Port = packet.DestPort,
                    Severity = KerberosEventSeverity.Critical,
                    ExploitPath = "Attacker has compromised an NTLM hash (via LSASS dump, relay, or crack) " +
                                  "and is requesting a legitimate TGT. Tool: Rubeus asktgt /enctype:rc4, " +
                                  "or mimikatz sekurlsa::pth.",
                    Mitigation = "Isolate the source host. Check for credential compromise. " +
                                 "Enforce AES-only and block RC4 in Kerberos policy.",
                    PacketId = packet.Id
                };
                lock (_lock) { _events.Add(evt); }
                OnKerberosEvent?.Invoke(evt);
            }
        }
    }

    /// <summary>
    /// Track ticket usage per source IP. When a ticket for the same service
    /// is presented from multiple source IPs, raise a Pass-the-Ticket alert.
    /// </summary>
    private void TrackTicketSource(string sname, string realm, string srcIp, DateTime timestamp)
    {
        if (string.IsNullOrEmpty(srcIp)) return;
        string key = $"{sname}@{realm}";

        lock (_lock)
        {
            if (!_ticketSourceTracker.TryGetValue(key, out var sources))
            {
                sources = new Dictionary<string, DateTime>();
                _ticketSourceTracker[key] = sources;
            }

            sources[srcIp] = timestamp;

            // Evict stale entries
            var stale = sources.Where(kv => timestamp - kv.Value > StateMaxAge).Select(kv => kv.Key).ToList();
            foreach (var s in stale) sources.Remove(s);

            // Detect: same ticket from multiple IPs within 30 minutes
            var recentSources = sources.Where(kv => timestamp - kv.Value < TimeSpan.FromMinutes(30)).ToList();
            if (recentSources.Count >= 2)
            {
                string sig = $"ptt|{key}|{string.Join(",", recentSources.Select(kv => kv.Key).OrderBy(x => x))}";
                if (ShouldReport(sig, timestamp))
                {
                    string ips = string.Join(", ", recentSources.Select(kv => kv.Key));
                    var evt = new KerberosEvent
                    {
                        Timestamp = timestamp,
                        EventType = KerberosEventType.PassTheTicket,
                        Category = "Attack",
                        Name = "Pass-the-Ticket Suspected",
                        Description = $"Service ticket for {key} presented from multiple source IPs within 30 minutes: [{ips}]. " +
                                      "This pattern indicates a Kerberos ticket was stolen and replayed from a different host.",
                        SourceIP = srcIp,
                        Severity = KerberosEventSeverity.Critical,
                        Principal = sname,
                        Realm = realm,
                        ExploitPath = "Attacker exported tickets from one compromised host (mimikatz sekurlsa::tickets /export) " +
                                      "and imported them on another (kerberos::ptt). Check both source IPs for compromise.",
                        Mitigation = "Investigate both hosts for signs of compromise. Reset the service account password " +
                                     "to invalidate stolen tickets. Enable Credential Guard on endpoints."
                    };
                    _events.Add(evt);
                    OnKerberosEvent?.Invoke(evt);
                }
            }
        }
    }

    // ============================================================
    // ASN.1 DER Parsing Helpers
    // ============================================================

    /// <summary>
    /// Read an ASN.1 DER length field. Returns false if malformed.
    /// On success, advances pos past the length bytes and sets length.
    /// </summary>
    private static bool TryReadAsn1Length(ReadOnlySpan<byte> data, ref int pos, out int length)
    {
        length = 0;
        if (pos >= data.Length) return false;

        byte b = data[pos++];
        if (b < 0x80)
        {
            length = b;
            return true;
        }

        int numBytes = b & 0x7F;
        if (numBytes == 0 || numBytes > 4 || pos + numBytes > data.Length) return false;

        for (int i = 0; i < numBytes; i++)
            length = (length << 8) | data[pos++];

        return length >= 0;
    }

    /// <summary>
    /// Try to enter a SEQUENCE (tag 0x30): skip tag + length, return inner content.
    /// </summary>
    private static bool TryEnterSequence(ReadOnlySpan<byte> data, out ReadOnlySpan<byte> content)
    {
        content = ReadOnlySpan<byte>.Empty;
        if (data.Length < 2 || data[0] != 0x30) return false;

        int pos = 1;
        if (!TryReadAsn1Length(data, ref pos, out int len)) return false;
        if (pos + len > data.Length) return false;

        content = data.Slice(pos, len);
        return true;
    }

    /// <summary>
    /// Read a context-specific tagged field [N] CONSTRUCTED.
    /// Context tags are encoded as 0xA0 | tag_number.
    /// Advances pos past the entire tagged field.
    /// </summary>
    private static bool TryReadContextTag(ReadOnlySpan<byte> data, ref int pos, out int tagNum, out ReadOnlySpan<byte> content)
    {
        tagNum = 0;
        content = ReadOnlySpan<byte>.Empty;

        if (pos >= data.Length) return false;

        byte tag = data[pos];
        // Context-specific constructed: 0xA0-0xBE
        if ((tag & 0xC0) != 0x80) // Not context-specific
        {
            // Skip this element entirely
            int skipPos = pos + 1;
            if (!TryReadAsn1Length(data, ref skipPos, out int skipLen)) return false;
            pos = skipPos + skipLen;
            return false;
        }

        tagNum = tag & 0x1F;
        pos++;
        if (!TryReadAsn1Length(data, ref pos, out int len)) return false;
        if (pos + len > data.Length) return false;

        content = data.Slice(pos, len);
        pos += len;
        return true;
    }

    /// <summary>
    /// Read an ASN.1 INTEGER value from the content of a tagged field.
    /// The content should start with 0x02 (INTEGER tag).
    /// </summary>
    private static int TryReadAsn1Integer(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2) return -1;
        if (data[0] != 0x02) return -1; // Not INTEGER

        int pos = 1;
        if (!TryReadAsn1Length(data, ref pos, out int len)) return -1;
        if (pos + len > data.Length || len > 4) return -1;

        int value = 0;
        bool negative = len > 0 && (data[pos] & 0x80) != 0;
        for (int i = 0; i < len; i++)
            value = (value << 8) | data[pos + i];

        // Handle sign extension for negative values
        if (negative && len < 4)
            value |= unchecked((int)(0xFFFFFFFF << (len * 8)));

        return value;
    }

    /// <summary>
    /// Read an ASN.1 string (GeneralString, UTF8String, or IA5String) from tagged content.
    /// </summary>
    private static string? TryReadAsn1String(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2) return null;

        byte tag = data[0];
        // GeneralString = 0x1B, UTF8String = 0x0C, IA5String = 0x16, OctetString = 0x04
        if (tag != 0x1B && tag != 0x0C && tag != 0x16 && tag != 0x04) return null;

        int pos = 1;
        if (!TryReadAsn1Length(data, ref pos, out int len)) return null;
        if (pos + len > data.Length) return null;

        return Encoding.ASCII.GetString(data.Slice(pos, len).ToArray());
    }

    /// <summary>
    /// Parse a PrincipalName from ASN.1.
    /// PrincipalName ::= SEQUENCE {
    ///   name-type [0] Int32,
    ///   name-string [1] SEQUENCE OF KerberosString
    /// }
    /// Returns "component1/component2" for multi-component names.
    /// </summary>
    private static string? ParsePrincipalName(ReadOnlySpan<byte> data)
    {
        if (!TryEnterSequence(data, out var seqContent)) return null;

        int pos = 0;
        var components = new List<string>();

        while (pos < seqContent.Length)
        {
            if (!TryReadContextTag(seqContent, ref pos, out int tagNum, out var tagContent)) break;

            if (tagNum == 1) // name-string
            {
                // SEQUENCE OF KerberosString
                if (TryEnterSequence(tagContent, out var strSeq))
                {
                    components = ParseSequenceOfStrings(strSeq);
                }
            }
        }

        return components.Count > 0 ? string.Join("/", components) : null;
    }

    /// <summary>
    /// Parse a SEQUENCE OF KerberosString, returning all string components.
    /// </summary>
    private static List<string> ParseSequenceOfStrings(ReadOnlySpan<byte> data)
    {
        var result = new List<string>();
        int pos = 0;

        while (pos < data.Length)
        {
            byte tag = data[pos];
            if (tag != 0x1B && tag != 0x0C && tag != 0x16) break; // Not a string type

            pos++; // Skip tag

            if (!TryReadAsn1Length(data, ref pos, out int len)) break;
            if (pos + len > data.Length) break;

            result.Add(Encoding.ASCII.GetString(data.Slice(pos, len).ToArray()));
            pos += len;
        }

        return result;
    }

    /// <summary>
    /// Parse KDC-REQ-BODY to extract cname, realm, sname, and etype list.
    /// </summary>
    private static void ParseKdcReqBody(ReadOnlySpan<byte> data,
        out string? cname, out string? realm, out string? sname, out List<int>? etypes)
    {
        cname = null;
        realm = null;
        sname = null;
        etypes = null;

        int pos = 0;
        while (pos < data.Length)
        {
            if (!TryReadContextTag(data, ref pos, out int tagNum, out var tagContent)) break;

            switch (tagNum)
            {
                case 1: // cname
                    cname = ParsePrincipalName(tagContent);
                    break;
                case 2: // realm
                    realm = TryReadAsn1String(tagContent);
                    break;
                case 3: // sname
                    sname = ParsePrincipalName(tagContent);
                    break;
                case 8: // etype — SEQUENCE OF Int32
                    etypes = ParseSequenceOfIntegers(tagContent);
                    break;
            }
        }
    }

    /// <summary>
    /// Parse a SEQUENCE OF INTEGER.
    /// </summary>
    private static List<int> ParseSequenceOfIntegers(ReadOnlySpan<byte> data)
    {
        var result = new List<int>();

        // The content should be a SEQUENCE wrapping the integers
        if (!TryEnterSequence(data, out var seqContent))
        {
            // Maybe it's directly integers without a wrapping SEQUENCE
            seqContent = data;
        }

        int pos = 0;
        while (pos < seqContent.Length)
        {
            if (seqContent[pos] != 0x02) break; // Not INTEGER

            int val = TryReadAsn1Integer(seqContent.Slice(pos));
            if (val == -1 && seqContent.Length > pos + 2) break;

            result.Add(val);

            // Advance past this INTEGER
            pos++; // tag
            if (!TryReadAsn1Length(seqContent, ref pos, out int len)) break;
            pos += len;
        }

        return result;
    }

    /// <summary>
    /// Parse PA-DATA sequence to find PA-ENC-TIMESTAMP.
    /// PA-DATA ::= SEQUENCE {
    ///   padata-type [1] Int32,
    ///   padata-value [2] OCTET STRING
    /// }
    /// PA-ENC-TIMESTAMP has padata-type = 2.
    /// </summary>
    private static void ParsePaData(ReadOnlySpan<byte> data,
        out bool hasEncTimestamp, out byte[]? encTimestampData, out int encTimestampEtype)
    {
        hasEncTimestamp = false;
        encTimestampData = null;
        encTimestampEtype = 0;

        // data should be SEQUENCE OF PA-DATA
        if (!TryEnterSequence(data, out var seqOfContent))
            seqOfContent = data;

        int pos = 0;
        while (pos < seqOfContent.Length)
        {
            // Each PA-DATA is a SEQUENCE
            if (pos >= seqOfContent.Length || seqOfContent[pos] != 0x30) break;

            pos++; // tag
            if (!TryReadAsn1Length(seqOfContent, ref pos, out int elemLen)) break;
            if (pos + elemLen > seqOfContent.Length) break;

            var paData = seqOfContent.Slice(pos, elemLen);
            pos += elemLen;

            // Parse this PA-DATA
            int paType = -1;
            byte[]? paValue = null;

            int paPos = 0;
            while (paPos < paData.Length)
            {
                if (!TryReadContextTag(paData, ref paPos, out int tagNum, out var tagContent)) break;
                switch (tagNum)
                {
                    case 1: // padata-type
                        paType = TryReadAsn1Integer(tagContent);
                        break;
                    case 2: // padata-value (OCTET STRING)
                        if (tagContent.Length >= 2 && tagContent[0] == 0x04)
                        {
                            int valPos = 1;
                            if (TryReadAsn1Length(tagContent, ref valPos, out int valLen) &&
                                valPos + valLen <= tagContent.Length)
                            {
                                paValue = tagContent.Slice(valPos, valLen).ToArray();
                            }
                        }
                        else
                        {
                            paValue = tagContent.ToArray();
                        }
                        break;
                }
            }

            // PA-ENC-TIMESTAMP = padata-type 2
            if (paType == 2 && paValue != null && paValue.Length > 0)
            {
                hasEncTimestamp = true;
                // paValue contains EncryptedData
                ParseEncryptedData(paValue, out encTimestampEtype, out _, out encTimestampData);
            }
        }
    }

    /// <summary>
    /// Parse EncryptedData structure.
    /// EncryptedData ::= SEQUENCE {
    ///   etype  [0] Int32,
    ///   kvno   [1] UInt32 OPTIONAL,
    ///   cipher [2] OCTET STRING
    /// }
    /// </summary>
    private static void ParseEncryptedData(ReadOnlySpan<byte> data,
        out int etype, out int kvno, out byte[]? cipher)
    {
        etype = 0;
        kvno = 0;
        cipher = null;

        if (!TryEnterSequence(data, out var seqContent))
            seqContent = data;

        int pos = 0;
        while (pos < seqContent.Length)
        {
            if (!TryReadContextTag(seqContent, ref pos, out int tagNum, out var tagContent)) break;

            switch (tagNum)
            {
                case 0: // etype
                    etype = TryReadAsn1Integer(tagContent);
                    break;
                case 1: // kvno
                    kvno = TryReadAsn1Integer(tagContent);
                    break;
                case 2: // cipher
                    if (tagContent.Length >= 2 && tagContent[0] == 0x04) // OCTET STRING
                    {
                        int cPos = 1;
                        if (TryReadAsn1Length(tagContent, ref cPos, out int cLen) &&
                            cPos + cLen <= tagContent.Length)
                        {
                            cipher = tagContent.Slice(cPos, cLen).ToArray();
                        }
                    }
                    else
                    {
                        cipher = tagContent.ToArray();
                    }
                    break;
            }
        }
    }

    /// <summary>
    /// Parse a Ticket structure just enough to extract the enc-part encryption type and cipher.
    /// Ticket ::= [APPLICATION 1] SEQUENCE {
    ///   tkt-vno [0] INTEGER,
    ///   realm   [1] Realm,
    ///   sname   [2] PrincipalName,
    ///   enc-part [3] EncryptedData
    /// }
    /// </summary>
    private static void ParseTicketForAnalysis(ReadOnlySpan<byte> data, out int etype, out byte[]? cipher)
    {
        etype = 0;
        cipher = null;

        // Strip APPLICATION 1 tag if present
        var content = StripApplicationTag(data, 1);
        if (content.IsEmpty) content = data; // Fallback

        if (!TryEnterSequence(content, out var seqContent)) return;

        int pos = 0;
        while (pos < seqContent.Length)
        {
            if (!TryReadContextTag(seqContent, ref pos, out int tagNum, out var tagContent)) break;

            if (tagNum == 3) // enc-part
            {
                ParseEncryptedData(tagContent, out etype, out _, out cipher);
            }
        }
    }

    /// <summary>
    /// Parse a Ticket with full details (sname, realm, etype, cipher).
    /// </summary>
    private static void ParseTicketFull(ReadOnlySpan<byte> data,
        out int etype, out byte[]? cipher, out string? sname, out string? realm)
    {
        etype = 0;
        cipher = null;
        sname = null;
        realm = null;

        var content = StripApplicationTag(data, 1);
        if (content.IsEmpty) content = data;

        if (!TryEnterSequence(content, out var seqContent)) return;

        int pos = 0;
        while (pos < seqContent.Length)
        {
            if (!TryReadContextTag(seqContent, ref pos, out int tagNum, out var tagContent)) break;

            switch (tagNum)
            {
                case 1: // realm
                    realm = TryReadAsn1String(tagContent);
                    break;
                case 2: // sname
                    sname = ParsePrincipalName(tagContent);
                    break;
                case 3: // enc-part
                    ParseEncryptedData(tagContent, out etype, out _, out cipher);
                    break;
            }
        }
    }

    /// <summary>
    /// Strip an APPLICATION tag wrapper. Returns inner content or empty span.
    /// </summary>
    private static ReadOnlySpan<byte> StripApplicationTag(ReadOnlySpan<byte> data, int expectedTag)
    {
        if (data.Length < 2) return ReadOnlySpan<byte>.Empty;

        byte tag = data[0];
        int actualTag;

        if ((tag & 0xE0) == 0x60) // APPLICATION CONSTRUCTED
        {
            actualTag = tag & 0x1F;
            if (actualTag == 0x1F && data.Length >= 3) // long form
                actualTag = data[1] & 0x7F;
        }
        else
        {
            return ReadOnlySpan<byte>.Empty;
        }

        // Don't enforce strict tag matching — Kerberos implementations vary
        int pos = (tag & 0x1F) == 0x1F ? 2 : 1;
        if (!TryReadAsn1Length(data, ref pos, out int len)) return ReadOnlySpan<byte>.Empty;
        if (pos + len > data.Length) return ReadOnlySpan<byte>.Empty;

        return data.Slice(pos, len);
    }

    // ============================================================
    // State Tracking Helpers
    // ============================================================

    private void TrackPrincipalEtypes(string principal, List<int> etypes)
    {
        lock (_lock)
        {
            if (!_principalEtypes.TryGetValue(principal, out var set))
            {
                set = new HashSet<int>();
                _principalEtypes[principal] = set;
            }
            foreach (int e in etypes) set.Add(e);
        }
    }

    private void TrackHostEtypes(string srcIp, List<int> etypes)
    {
        if (string.IsNullOrEmpty(srcIp)) return;
        lock (_lock)
        {
            if (!_hostEtypeProfile.TryGetValue(srcIp, out var set))
            {
                set = new HashSet<int>();
                _hostEtypeProfile[srcIp] = set;
            }
            foreach (int e in etypes) set.Add(e);
        }
    }

    // ============================================================
    // Deduplication & Cleanup
    // ============================================================

    /// <summary>
    /// Check if a signature should be reported (not seen within DedupWindow).
    /// Thread-safe.
    /// </summary>
    private bool ShouldReport(string signature, DateTime now)
    {
        lock (_lock)
        {
            if (_seen.TryGetValue(signature, out var lastSeen) && now - lastSeen < DedupWindow)
                return false;
            _seen[signature] = now;
            return true;
        }
    }

    private void ReportEvent(KerberosEvent evt, bool dedup = false)
    {
        if (dedup)
        {
            string sig = $"{evt.EventType}|{evt.SourceIP}|{evt.Principal}|{evt.EncryptionType}";
            if (!ShouldReport(sig, evt.Timestamp)) return;
        }

        lock (_lock) { _events.Add(evt); }
        OnKerberosEvent?.Invoke(evt);
    }

    /// <summary>Prune stale entries from all tracking dictionaries.</summary>
    private void PruneState(DateTime now)
    {
        lock (_lock)
        {
            // Prune dedup signatures
            if (now - _lastSeenCleanup > DedupWindow)
            {
                var stale = _seen.Where(kv => now - kv.Value > DedupWindow).Select(kv => kv.Key).ToList();
                foreach (var key in stale) _seen.Remove(key);
                _lastSeenCleanup = now;
            }

            // Prune TGS-REQ burst tracker
            var staleBurst = _tgsReqBurst.Where(kv =>
                kv.Value.Count == 0 || now - kv.Value.Last().time > StateMaxAge)
                .Select(kv => kv.Key).ToList();
            foreach (var key in staleBurst) _tgsReqBurst.Remove(key);

            // Prune ticket source tracker — two passes to avoid modifying during enumeration
            var ticketKeysToRemove = new List<string>();
            var ticketKeysToUpdate = new List<(string key, Dictionary<string, DateTime> updated)>();
            foreach (var kv in _ticketSourceTracker)
            {
                var recent = kv.Value.Where(s => now - s.Value < StateMaxAge)
                                     .ToDictionary(s => s.Key, s => s.Value);
                if (recent.Count == 0)
                    ticketKeysToRemove.Add(kv.Key);
                else if (recent.Count < kv.Value.Count)
                    ticketKeysToUpdate.Add((kv.Key, recent));
            }
            foreach (var key in ticketKeysToRemove) _ticketSourceTracker.Remove(key);
            foreach (var (key, updated) in ticketKeysToUpdate) _ticketSourceTracker[key] = updated;

            // Cap total entries
            if (_hostEtypeProfile.Count > MaxTrackedEntries)
            {
                var oldest = _hostEtypeProfile.Keys.Take(_hostEtypeProfile.Count - MaxTrackedEntries / 2).ToList();
                foreach (var key in oldest) _hostEtypeProfile.Remove(key);
            }

            // Cap events list (keep most recent 50000)
            if (_events.Count > 50_000)
                _events.RemoveRange(0, _events.Count - 25_000);
        }
    }

    // ============================================================
    // Utility
    // ============================================================

    private static string EtypeName(int etype) => etype switch
    {
        EtypeDES_CBC_CRC       => "DES-CBC-CRC(1)",
        EtypeDES_CBC_MD4       => "DES-CBC-MD4(2)",
        EtypeDES_CBC_MD5       => "DES-CBC-MD5(3)",
        EtypeAES128_CTS_SHA1   => "AES128-CTS-SHA1(17)",
        EtypeAES256_CTS_SHA1   => "AES256-CTS-SHA1(18)",
        EtypeAES128_CTS_SHA256 => "AES128-CTS-SHA256(19)",
        EtypeAES256_CTS_SHA384 => "AES256-CTS-SHA384(20)",
        EtypeRC4_HMAC          => "RC4-HMAC(23)",
        EtypeRC4_HMAC_EXP      => "RC4-HMAC-EXP(24)",
        _ => $"etype({etype})"
    };

    private static string BytesToHex(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 2);
        foreach (byte b in data) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}

// ============================================================
// Data Models
// ============================================================

/// <summary>
/// A detected Kerberos security event.
/// </summary>
public class KerberosEvent
{
    public DateTime Timestamp { get; init; }
    public KerberosEventType EventType { get; init; }
    public string Category { get; init; } = "";
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string SourceIP { get; init; } = "";
    public string DestIP { get; init; } = "";
    public ushort Port { get; init; }
    public KerberosEventSeverity Severity { get; init; }
    public string Principal { get; init; } = "";
    public string Realm { get; init; } = "";
    public int EncryptionType { get; init; }

    /// <summary>Hashcat-compatible hash string, if applicable.</summary>
    public string? HashcatHash { get; init; }

    /// <summary>Hashcat mode number for cracking.</summary>
    public int HashcatMode { get; init; }

    public string ExploitPath { get; init; } = "";
    public string Mitigation { get; init; } = "";
    public long PacketId { get; init; }

    public string SeverityStr => Severity switch
    {
        KerberosEventSeverity.Critical => "CRITICAL",
        KerberosEventSeverity.High => "HIGH",
        KerberosEventSeverity.Medium => "MEDIUM",
        KerberosEventSeverity.Low => "LOW",
        KerberosEventSeverity.Info => "INFO",
        _ => "UNKNOWN"
    };

    public string EncryptionTypeName => EncryptionType switch
    {
        1 => "DES-CBC-CRC",
        2 => "DES-CBC-MD4",
        3 => "DES-CBC-MD5",
        17 => "AES128-CTS-SHA1",
        18 => "AES256-CTS-SHA1",
        19 => "AES128-CTS-SHA256",
        20 => "AES256-CTS-SHA384",
        23 => "RC4-HMAC",
        24 => "RC4-HMAC-EXP",
        _ => $"etype({EncryptionType})"
    };
}

public enum KerberosEventType
{
    // Informational
    AsReq,
    AsRep,
    TgsReq,
    TgsRep,

    // Credential extraction
    HashCaptured,        // PA-ENC-TIMESTAMP hash
    AsRepRoast,          // AS-REP Roasting hash
    KerberoastHash,      // TGS-REP Kerberoasting hash
    Kerberoast,          // TGS-REQ targeting SPN with RC4

    // Attack detection
    KerberoastBurst,     // Multiple SPNs queried rapidly
    OverpassTheHash,     // AS-REQ with only RC4 from AES host
    PassTheTicket,       // Same ticket from multiple IPs
    EncryptionDowngrade, // Only weak etypes requested

    // Weakness
    WeakTicketEncryption, // Ticket encrypted with RC4/DES

    // Authentication events
    PreauthFailed,       // Wrong password
    UserEnumeration      // Principal unknown (user enum via differential error)
}

public enum KerberosEventSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}
