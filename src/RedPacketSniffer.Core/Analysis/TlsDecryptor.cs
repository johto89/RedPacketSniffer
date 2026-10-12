using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// Decrypts captured TLS traffic using session keys from SSLKEYLOGFILE (NSS Key Log format).
///
/// Workflow:
///   1. Load/watch a key log file produced by the target (via SSLKEYLOGFILE env var)
///   2. ProtocolWeaknessDetector registers TLS sessions (client_random, server_random, cipher)
///      as they are parsed from handshake packets
///   3. When a TLS Application Data record arrives, call <see cref="TryDecryptRecord"/>
///   4. If matching key material exists, the record is decrypted and plaintext returned
///   5. Decrypted payload is fed back to HttpRequestLogger, CredentialExtractor, etc.
///
/// Supported cipher suites:
///   TLS 1.2: AES-128/256-GCM-SHA256/SHA384, AES-128/256-CBC-SHA/SHA256/SHA384,
///            ECDHE_RSA/ECDSA + ChaCha20-Poly1305
///   TLS 1.3: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
///            TLS_CHACHA20_POLY1305_SHA256
///
/// Key log labels handled:
///   CLIENT_RANDOM            — master secret for TLS ≤ 1.2
///   CLIENT_TRAFFIC_SECRET_0  — TLS 1.3 client application data key
///   SERVER_TRAFFIC_SECRET_0  — TLS 1.3 server application data key
///   CLIENT_HANDSHAKE_TRAFFIC_SECRET — TLS 1.3 client handshake key
///   SERVER_HANDSHAKE_TRAFFIC_SECRET — TLS 1.3 server handshake key
///
/// Threading: all mutable state guarded by <see cref="_lock"/>; safe for multi-thread capture.
/// Memory: hard cap <see cref="MaxSessions"/> on tracked sessions with time-based eviction.
/// Security: key material zeroed on <see cref="Dispose"/>; no key bytes in log/event output.
/// </summary>
public sealed class TlsDecryptor : IDisposable
{
    private readonly object _lock = new();
    private readonly Dictionary<string, byte[]> _masterSecrets = new();        // hex(client_random) -> master_secret
    private readonly Dictionary<string, byte[]> _clientTrafficSecrets = new(); // hex(client_random) -> secret
    private readonly Dictionary<string, byte[]> _serverTrafficSecrets = new(); // hex(client_random) -> secret
    private readonly Dictionary<string, byte[]> _clientHsSecrets = new();      // hex(client_random) -> handshake secret
    private readonly Dictionary<string, byte[]> _serverHsSecrets = new();      // hex(client_random) -> handshake secret
    private readonly Dictionary<string, SessionState> _sessions = new();       // connKey -> state

    private Timer? _watchTimer;
    private string? _keyLogPath;
    private long _keyLogPosition;
    private bool _disposed;

    // --- Capacity limits ---
    private const int MaxSessions = 2000;
    private const int MaxKeyLogEntries = 10000;
    private static readonly TimeSpan SessionIdleTimeout = TimeSpan.FromMinutes(30);
    private DateTime _lastSessionCleanup = DateTime.MinValue;

    /// <summary>
    /// Raised when a TLS record is successfully decrypted.
    /// Parameters: connection key, actual content type, plaintext bytes.
    /// No key material is included in event args.
    /// </summary>
    public event Action<string, byte, byte[]>? OnRecordDecrypted;

    // ========================================================================
    // Key Log File Management
    // ========================================================================

    /// <summary>
    /// Load all key entries from an SSLKEYLOGFILE. Can be called multiple times;
    /// new entries are merged without removing existing ones.
    /// </summary>
    public int LoadKeyLogFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Key log file path must not be empty.", nameof(path));

        lock (_lock)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(TlsDecryptor));
        }

        if (!File.Exists(path))
            return 0;

        int loaded = 0;
        long actualPosition;

        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        using (var reader = new StreamReader(fs))
        {
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                if (TryParseKeyLogLine(line))
                    loaded++;
            }

            reader.DiscardBufferedData();
            actualPosition = fs.Position;
        }

        lock (_lock)
        {
            _keyLogPath = path;
            _keyLogPosition = actualPosition;
        }

        return loaded;
    }

    /// <summary>
    /// Start watching the key log file for new entries appended by the target application.
    /// Polls every <paramref name="pollIntervalMs"/> milliseconds (default 2000).
    /// </summary>
    public void WatchKeyLogFile(string path, int pollIntervalMs = 2000)
    {
        LoadKeyLogFile(path);

        lock (_lock)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(TlsDecryptor));

            _watchTimer?.Dispose();
            _watchTimer = new Timer(PollKeyLogFile, null, pollIntervalMs, pollIntervalMs);
        }
    }

    /// <summary>Stop watching the key log file.</summary>
    public void StopWatching()
    {
        lock (_lock)
        {
            _watchTimer?.Dispose();
            _watchTimer = null;
        }
    }

    private void PollKeyLogFile(object? state)
    {
        string? path;
        long pos;

        lock (_lock)
        {
            path = _keyLogPath;
            pos = _keyLogPosition;
        }

        if (path == null || !File.Exists(path))
            return;

        var fi = new FileInfo(path);
        if (fi.Length <= pos)
            return; // No new data

        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            fs.Seek(pos, SeekOrigin.Begin);
            using var reader = new StreamReader(fs);

            string? line;
            while ((line = reader.ReadLine()) != null)
                TryParseKeyLogLine(line);

            // Use actual stream position after reading, not fi.Length captured before reading.
            // The file may have grown further while we were reading, and using fi.Length
            // would skip content appended between our FileInfo check and stream completion.
            // Conversely, a truncated/rotated file is handled by the fi.Length <= pos check above.
            reader.DiscardBufferedData(); // Flush StreamReader internal buffer to sync position
            long actualPosition = fs.Position;

            lock (_lock)
            {
                _keyLogPosition = actualPosition;
            }
        }
        catch (IOException)
        {
            // File locked by the target application; retry next poll
        }
    }

    /// <summary>
    /// Parse one line of NSS Key Log format.
    /// Format: LABEL SP hex(client_random) SP hex(secret)
    /// Lines starting with # are comments. Empty lines are ignored.
    /// </summary>
    private bool TryParseKeyLogLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line) || line[0] == '#')
            return false;

        // Split: LABEL <client_random_hex> <secret_hex>
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3)
            return false;

        string label = parts[0];
        string clientRandomHex = parts[1].ToUpperInvariant();
        byte[]? secret = HexToBytes(parts[2]);

        if (secret == null || clientRandomHex.Length != 64) // client_random is 32 bytes = 64 hex chars
            return false;

        lock (_lock)
        {
            // Enforce capacity
            int totalEntries = _masterSecrets.Count + _clientTrafficSecrets.Count
                + _serverTrafficSecrets.Count + _clientHsSecrets.Count + _serverHsSecrets.Count;
            if (totalEntries >= MaxKeyLogEntries)
                return false;

            Dictionary<string, byte[]> target;
            switch (label)
            {
                case "CLIENT_RANDOM":
                    target = _masterSecrets;
                    break;
                case "CLIENT_TRAFFIC_SECRET_0":
                    target = _clientTrafficSecrets;
                    break;
                case "SERVER_TRAFFIC_SECRET_0":
                    target = _serverTrafficSecrets;
                    break;
                case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
                    target = _clientHsSecrets;
                    break;
                case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
                    target = _serverHsSecrets;
                    break;
                default:
                    // EXPORTER_SECRET, EARLY_TRAFFIC_SECRET, etc. — not needed for decryption
                    return false;
            }

            // Zero old secret before overwriting to prevent key material lingering in memory
            if (target.TryGetValue(clientRandomHex, out byte[]? oldSecret))
                CryptographicOperations.ZeroMemory(oldSecret);

            target[clientRandomHex] = secret;
        }

        return true;
    }

    // ========================================================================
    // Session Registration
    // ========================================================================

    /// <summary>
    /// Register a TLS session after ClientHello + ServerHello have been parsed.
    /// Called by ProtocolWeaknessDetector when handshake parsing completes.
    /// </summary>
    /// <param name="connectionKey">
    /// Unique connection identifier, e.g. "192.168.1.100:54321-10.0.0.5:443"
    /// </param>
    /// <param name="clientRandom">32-byte client_random from ClientHello</param>
    /// <param name="serverRandom">32-byte server_random from ServerHello</param>
    /// <param name="cipherSuite">Negotiated cipher suite ID from ServerHello</param>
    /// <param name="tlsVersion">Negotiated TLS version (0x0303 = TLS 1.2, 0x0304 = TLS 1.3)</param>
    public void RegisterSession(
        string connectionKey,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        ushort cipherSuite,
        ushort tlsVersion)
    {
        if (clientRandom.Length != 32 || serverRandom.Length != 32)
            return;

        if (!CipherSuiteDb.TryGetValue(cipherSuite, out var csInfo))
            return; // Unsupported cipher suite

        string crHex = BytesToHex(clientRandom);

        lock (_lock)
        {
            if (_disposed) return;
            EvictIdleSessions();

            if (_sessions.Count >= MaxSessions)
                return; // At capacity

            bool isTls13 = tlsVersion >= 0x0304;

            SessionState session;
            if (isTls13)
            {
                // TLS 1.3: derive keys from traffic secrets
                if (!_clientTrafficSecrets.TryGetValue(crHex, out byte[]? clientSecret) ||
                    !_serverTrafficSecrets.TryGetValue(crHex, out byte[]? serverSecret))
                    return; // No key material yet

                session = DeriveTls13SessionKeys(clientSecret, serverSecret, csInfo);
            }
            else
            {
                // TLS 1.2: derive keys from master secret via PRF
                if (!_masterSecrets.TryGetValue(crHex, out byte[]? masterSecret))
                    return; // No key material

                session = DeriveTls12SessionKeys(
                    masterSecret, clientRandom, serverRandom, csInfo);
            }

            session.CipherInfo = csInfo;
            session.IsTls13 = isTls13;
            session.LastActivity = DateTime.UtcNow;

            // Zero old session keys before overwriting
            if (_sessions.TryGetValue(connectionKey, out SessionState? oldSession))
                oldSession.ZeroKeys();

            _sessions[connectionKey] = session;
        }
    }

    /// <summary>
    /// Check whether key material is available for a given client_random,
    /// without registering a session. Useful for early availability check.
    /// </summary>
    public bool HasKeyMaterial(ReadOnlySpan<byte> clientRandom, bool isTls13)
    {
        if (clientRandom.Length != 32) return false;
        string crHex = BytesToHex(clientRandom);

        lock (_lock)
        {
            if (_disposed) return false;
            if (isTls13)
                return _clientTrafficSecrets.ContainsKey(crHex)
                    && _serverTrafficSecrets.ContainsKey(crHex);
            else
                return _masterSecrets.ContainsKey(crHex);
        }
    }

    // ========================================================================
    // TLS Record Decryption
    // ========================================================================

    /// <summary>
    /// Attempt to decrypt a TLS record. Returns null if no session key is available,
    /// cipher is unsupported, or decryption fails (wrong key, corrupted, out of sync).
    /// </summary>
    /// <param name="connectionKey">Connection identifier matching RegisterSession</param>
    /// <param name="isClientToServer">Direction: true = client→server, false = server→client</param>
    /// <param name="record">
    /// Complete TLS record: content_type(1) + version(2) + length(2) + fragment(N).
    /// Minimum 5 bytes (header only, empty fragment).
    /// </param>
    /// <returns>Decryption result with plaintext and actual content type, or null.</returns>
    public DecryptionResult? TryDecryptRecord(
        string connectionKey, bool isClientToServer, ReadOnlySpan<byte> record)
    {
        if (record.Length < 6) // Header (5) + at least 1 byte fragment
            return null;

        byte contentType = record[0];
        // ushort version = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(1, 2));
        ushort fragmentLength = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(3, 2));

        if (record.Length < 5 + fragmentLength)
            return null; // Truncated record

        ReadOnlySpan<byte> fragment = record.Slice(5, fragmentLength);

        lock (_lock)
        {
            if (_disposed) return null;

            if (!_sessions.TryGetValue(connectionKey, out SessionState? session))
                return null;

            session.LastActivity = DateTime.UtcNow;

            ref ulong seqNum = ref (isClientToServer
                ? ref session.ClientSeqNum
                : ref session.ServerSeqNum);

            byte[] writeKey = isClientToServer ? session.ClientWriteKey : session.ServerWriteKey;
            byte[] writeIv = isClientToServer ? session.ClientWriteIv : session.ServerWriteIv;

            byte[]? plaintext;
            byte actualContentType = contentType;

            try
            {
                switch (session.CipherInfo.BulkCipher)
                {
                    case BulkCipherType.AesGcm:
                        plaintext = session.IsTls13
                            ? DecryptAesGcmTls13(writeKey, writeIv, seqNum, fragment, record.Slice(0, 5), out actualContentType)
                            : DecryptAesGcmTls12(writeKey, writeIv, seqNum, contentType, fragment);
                        break;

                    case BulkCipherType.AesCbc:
                        if (session.IsTls13)
                            return null; // TLS 1.3 does not use CBC
                        byte[] macKey = isClientToServer ? session.ClientMacKey! : session.ServerMacKey!;
                        plaintext = DecryptAesCbcTls12(
                            writeKey, macKey, seqNum, contentType, fragment,
                            session.CipherInfo.MacHash, session.CipherInfo.MacLength);
                        break;

                    case BulkCipherType.ChaCha20Poly1305:
                        plaintext = session.IsTls13
                            ? DecryptChaCha20Tls13(writeKey, writeIv, seqNum, fragment, record.Slice(0, 5), out actualContentType)
                            : DecryptChaCha20Tls12(writeKey, writeIv, seqNum, contentType, fragment);
                        break;

                    default:
                        return null;
                }
            }
            catch (CryptographicException)
            {
                // Decryption failed — wrong key, corrupted, or sequence desync
                seqNum++;
                return null;
            }
            catch (ArgumentException)
            {
                seqNum++;
                return null;
            }

            if (plaintext == null || plaintext.Length == 0)
            {
                seqNum++;
                return null;
            }

            seqNum++;

            var result = new DecryptionResult(actualContentType, plaintext);

            // Fire event outside lock would be safer, but we're returning the result
            // anyway — caller decides whether to raise events.
            return result;
        }
    }

    /// <summary>
    /// Convenience: decrypt and fire <see cref="OnRecordDecrypted"/> if successful.
    /// </summary>
    public byte[]? DecryptAndNotify(
        string connectionKey, bool isClientToServer, ReadOnlySpan<byte> record)
    {
        var result = TryDecryptRecord(connectionKey, isClientToServer, record);
        if (result == null)
            return null;

        OnRecordDecrypted?.Invoke(connectionKey, result.Value.ContentType, result.Value.Plaintext);
        return result.Value.Plaintext;
    }

    // ========================================================================
    // TLS 1.2 Key Derivation (PRF-SHA256 / PRF-SHA384)
    // ========================================================================

    /// <summary>
    /// Derive TLS 1.2 session keys from master secret using the PRF.
    /// key_block = PRF(master_secret, "key expansion", server_random + client_random)
    /// </summary>
    private static SessionState DeriveTls12SessionKeys(
        byte[] masterSecret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        CipherSuiteInfo csInfo)
    {
        // Seed = server_random + client_random (note: reversed order from master secret derivation)
        byte[] seed = new byte[64];
        serverRandom.CopyTo(seed);
        clientRandom.CopyTo(seed.AsSpan(32));

        HashAlgorithmName prfHash = csInfo.PrfHash == HashType.Sha384
            ? HashAlgorithmName.SHA384
            : HashAlgorithmName.SHA256;

        // Calculate key block size needed
        int macKeyLen = csInfo.BulkCipher == BulkCipherType.AesCbc ? csInfo.MacLength : 0;
        int keyBlockSize = (macKeyLen * 2) + (csInfo.KeyLength * 2) + (csInfo.FixedIvLength * 2);

        byte[] keyBlock = Tls12Prf(masterSecret, "key expansion", seed, keyBlockSize, prfHash);

        var session = new SessionState();
        int offset = 0;

        // CBC modes have MAC keys first
        if (csInfo.BulkCipher == BulkCipherType.AesCbc)
        {
            session.ClientMacKey = keyBlock[offset..(offset + macKeyLen)];
            offset += macKeyLen;
            session.ServerMacKey = keyBlock[offset..(offset + macKeyLen)];
            offset += macKeyLen;
        }

        session.ClientWriteKey = keyBlock[offset..(offset + csInfo.KeyLength)];
        offset += csInfo.KeyLength;
        session.ServerWriteKey = keyBlock[offset..(offset + csInfo.KeyLength)];
        offset += csInfo.KeyLength;

        session.ClientWriteIv = keyBlock[offset..(offset + csInfo.FixedIvLength)];
        offset += csInfo.FixedIvLength;
        session.ServerWriteIv = keyBlock[offset..(offset + csInfo.FixedIvLength)];

        CryptographicOperations.ZeroMemory(keyBlock);
        CryptographicOperations.ZeroMemory(seed);

        return session;
    }

    /// <summary>
    /// TLS 1.2 PRF: P_hash(secret, label + seed) truncated to <paramref name="length"/> bytes.
    /// P_hash(secret, seed) = HMAC_hash(secret, A(1)+seed) || HMAC_hash(secret, A(2)+seed) || ...
    /// A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
    /// </summary>
    private static byte[] Tls12Prf(
        byte[] secret, string label, byte[] seed, int length, HashAlgorithmName hashAlg)
    {
        byte[] labelBytes = Encoding.ASCII.GetBytes(label);
        byte[] labelAndSeed = new byte[labelBytes.Length + seed.Length];
        Array.Copy(labelBytes, 0, labelAndSeed, 0, labelBytes.Length);
        Array.Copy(seed, 0, labelAndSeed, labelBytes.Length, seed.Length);

        byte[] result = new byte[length];
        int offset = 0;

        // A(1) = HMAC(secret, label+seed)
        byte[] a = HmacHash(hashAlg, secret, labelAndSeed);
        int hashLen = a.Length;

        while (offset < length)
        {
            // P_hash = HMAC(secret, A(i) + label+seed)
            byte[] aAndSeed = new byte[hashLen + labelAndSeed.Length];
            Array.Copy(a, 0, aAndSeed, 0, hashLen);
            Array.Copy(labelAndSeed, 0, aAndSeed, hashLen, labelAndSeed.Length);

            byte[] pHash = HmacHash(hashAlg, secret, aAndSeed);
            int copyLen = Math.Min(pHash.Length, length - offset);
            Array.Copy(pHash, 0, result, offset, copyLen);
            offset += copyLen;

            CryptographicOperations.ZeroMemory(aAndSeed);
            CryptographicOperations.ZeroMemory(pHash);

            // A(i+1) = HMAC(secret, A(i))
            byte[] nextA = HmacHash(hashAlg, secret, a);
            CryptographicOperations.ZeroMemory(a);
            a = nextA;
        }

        CryptographicOperations.ZeroMemory(a);
        CryptographicOperations.ZeroMemory(labelAndSeed);

        return result;
    }

    private static byte[] HmacHash(HashAlgorithmName hashAlg, byte[] key, byte[] data)
    {
        using var hmac = hashAlg == HashAlgorithmName.SHA384
            ? (HMAC)new HMACSHA384(key)
            : new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    // ========================================================================
    // TLS 1.3 Key Derivation (HKDF)
    // ========================================================================

    /// <summary>
    /// Derive TLS 1.3 session keys from traffic secrets using HKDF-Expand-Label.
    /// key = HKDF-Expand-Label(secret, "key", "", key_length)
    /// iv  = HKDF-Expand-Label(secret, "iv",  "", 12)
    /// </summary>
    private static SessionState DeriveTls13SessionKeys(
        byte[] clientTrafficSecret, byte[] serverTrafficSecret, CipherSuiteInfo csInfo)
    {
        HashAlgorithmName hashAlg = csInfo.PrfHash == HashType.Sha384
            ? HashAlgorithmName.SHA384
            : HashAlgorithmName.SHA256;

        var session = new SessionState
        {
            ClientWriteKey = HkdfExpandLabel(hashAlg, clientTrafficSecret, "key", ReadOnlySpan<byte>.Empty, csInfo.KeyLength),
            ClientWriteIv = HkdfExpandLabel(hashAlg, clientTrafficSecret, "iv", ReadOnlySpan<byte>.Empty, 12),
            ServerWriteKey = HkdfExpandLabel(hashAlg, serverTrafficSecret, "key", ReadOnlySpan<byte>.Empty, csInfo.KeyLength),
            ServerWriteIv = HkdfExpandLabel(hashAlg, serverTrafficSecret, "iv", ReadOnlySpan<byte>.Empty, 12),
        };

        return session;
    }

    /// <summary>
    /// HKDF-Expand-Label as defined in TLS 1.3 (RFC 8446 §7.1).
    /// HkdfLabel = uint16(length) + opaque label[7..255] + opaque context[0..255]
    /// where label is "tls13 " + Label.
    /// </summary>
    private static byte[] HkdfExpandLabel(
        HashAlgorithmName hashAlg, byte[] secret, string label,
        ReadOnlySpan<byte> context, int length)
    {
        // Build info = HkdfLabel structure
        byte[] fullLabel = Encoding.ASCII.GetBytes("tls13 " + label);
        int infoLen = 2 + 1 + fullLabel.Length + 1 + context.Length;
        byte[] info = new byte[infoLen];

        info[0] = (byte)(length >> 8);
        info[1] = (byte)(length & 0xFF);
        info[2] = (byte)fullLabel.Length;
        Array.Copy(fullLabel, 0, info, 3, fullLabel.Length);
        info[3 + fullLabel.Length] = (byte)context.Length;
        if (context.Length > 0)
            context.CopyTo(info.AsSpan(4 + fullLabel.Length));

        byte[] result = HKDF.Expand(hashAlg, secret, length, info);

        CryptographicOperations.ZeroMemory(info);
        return result;
    }

    // ========================================================================
    // AES-GCM Decryption
    // ========================================================================

    /// <summary>
    /// Decrypt AES-GCM record for TLS 1.2.
    /// Fragment layout: explicit_nonce(8) + ciphertext(N) + auth_tag(16)
    /// Nonce = implicit_IV(4) || explicit_nonce(8)
    /// AAD = seq_num(8) || content_type(1) || version(2) || plaintext_length(2)
    /// </summary>
    private static byte[]? DecryptAesGcmTls12(
        byte[] writeKey, byte[] implicitIv, ulong seqNum, byte contentType,
        ReadOnlySpan<byte> fragment)
    {
        const int ExplicitNonceLen = 8;
        const int TagLen = 16;

        if (fragment.Length < ExplicitNonceLen + TagLen + 1)
            return null;

        ReadOnlySpan<byte> explicitNonce = fragment[..ExplicitNonceLen];
        int ciphertextLen = fragment.Length - ExplicitNonceLen - TagLen;
        ReadOnlySpan<byte> ciphertext = fragment.Slice(ExplicitNonceLen, ciphertextLen);
        ReadOnlySpan<byte> tag = fragment.Slice(fragment.Length - TagLen, TagLen);

        // Nonce = implicit_IV(4) || explicit_nonce(8)
        byte[] nonce = new byte[12];
        implicitIv.AsSpan(0, 4).CopyTo(nonce);
        explicitNonce.CopyTo(nonce.AsSpan(4));

        // AAD = seq_num(8) || content_type(1) || version(2) || plaintext_length(2)
        byte[] aad = new byte[13];
        BinaryPrimitives.WriteUInt64BigEndian(aad, seqNum);
        aad[8] = contentType;
        aad[9] = 0x03; aad[10] = 0x03; // TLS 1.2
        BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(11), (ushort)ciphertextLen);

        byte[] plaintext = new byte[ciphertextLen];

        using var aes = new AesGcm(writeKey, TagLen);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);

        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(aad);

        return plaintext;
    }

    /// <summary>
    /// Decrypt AES-GCM record for TLS 1.3.
    /// Fragment layout: ciphertext(N) + auth_tag(16)
    /// Nonce = XOR(write_iv(12), padded_seq_num(12))
    /// AAD = content_type(1=0x17) + legacy_version(2=0x0303) + record_length(2)
    /// After decryption: strip trailing zeros, last non-zero byte = actual content type.
    /// </summary>
    private static byte[]? DecryptAesGcmTls13(
        byte[] writeKey, byte[] writeIv, ulong seqNum,
        ReadOnlySpan<byte> fragment, ReadOnlySpan<byte> recordHeader,
        out byte actualContentType)
    {
        actualContentType = 0x17; // default: application data
        const int TagLen = 16;

        if (fragment.Length < TagLen + 1)
            return null;

        int ciphertextLen = fragment.Length - TagLen;
        ReadOnlySpan<byte> ciphertext = fragment[..ciphertextLen];
        ReadOnlySpan<byte> tag = fragment.Slice(ciphertextLen, TagLen);

        // Nonce = XOR(write_iv, padded seq_num)
        byte[] nonce = BuildTls13Nonce(writeIv, seqNum);

        // AAD = record header (content_type || legacy_version || length) = 5 bytes
        byte[] aad = recordHeader.ToArray();

        byte[] plaintext = new byte[ciphertextLen];

        using var aes = new AesGcm(writeKey, TagLen);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);

        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(aad);

        // TLS 1.3: strip padding and extract actual content type
        return StripTls13Padding(plaintext, out actualContentType);
    }

    // ========================================================================
    // AES-CBC Decryption (TLS 1.2 only)
    // ========================================================================

    /// <summary>
    /// Decrypt AES-CBC record for TLS 1.2 (with explicit IV per RFC 5246).
    /// Fragment layout: IV(16) + encrypted(N)
    /// Decrypted layout: content + MAC(macLength) + padding(padLen bytes) + padding_length(1 byte)
    ///
    /// Security: MAC is ALWAYS verified regardless of padding validity to prevent
    /// timing side-channels (Lucky13). All comparisons are constant-time.
    /// </summary>
    private static byte[]? DecryptAesCbcTls12(
        byte[] writeKey, byte[] macKey, ulong seqNum, byte contentType,
        ReadOnlySpan<byte> fragment, HashType macHash, int macLength)
    {
        const int IvLen = 16; // AES block size

        if (fragment.Length < IvLen + 16) // IV + at least 1 AES block
            return null;

        ReadOnlySpan<byte> iv = fragment[..IvLen];
        ReadOnlySpan<byte> ciphertext = fragment[IvLen..];

        // Ciphertext must be a multiple of block size
        if (ciphertext.Length % 16 != 0)
            return null;

        // CBC decrypt
        using var aes = Aes.Create();
        aes.Key = writeKey;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None; // We handle padding manually

        byte[] decrypted = new byte[ciphertext.Length];
        using (var decryptor = aes.CreateDecryptor(writeKey, iv.ToArray()))
        {
            decryptor.TransformBlock(ciphertext.ToArray(), 0, ciphertext.Length, decrypted, 0);
        }

        // RFC 5246 §6.2.3.2: last byte is padding_length.
        // padding consists of padding_length bytes each equal to padding_length,
        // followed by the padding_length byte itself. Total overhead = padding_length + 1.
        // padding_length can be 0..255 (0 means only the padding_length byte itself).
        int padLenField = decrypted[^1]; // The padding_length value
        int totalPadding = padLenField + 1; // padding bytes + padding_length byte

        // Validate padding in constant time: check all padding bytes equal padLenField.
        // Even if padding is invalid, we continue to MAC verification to avoid timing leak.
        int paddingGood = 1; // 1 = valid, 0 = invalid
        if (totalPadding > decrypted.Length)
        {
            paddingGood = 0;
            // Set totalPadding to a safe value so we can still compute MAC
            totalPadding = decrypted.Length;
        }
        else
        {
            // Check padding bytes: indices [Length - totalPadding .. Length - 2]
            // (the last byte is the padding_length field itself, already read)
            for (int i = decrypted.Length - totalPadding; i < decrypted.Length - 1; i++)
            {
                if (decrypted[i] != padLenField)
                    paddingGood = 0;
                // No early return — constant time
            }
        }

        int contentAndMacLen = decrypted.Length - totalPadding;

        // Must have at least macLength bytes for the MAC
        if (contentAndMacLen < macLength)
        {
            CryptographicOperations.ZeroMemory(decrypted);
            return null;
        }

        int plaintextLen = contentAndMacLen - macLength;
        byte[] recordMac = decrypted[plaintextLen..contentAndMacLen];

        // ALWAYS verify HMAC regardless of padding validity (anti-Lucky13).
        // MAC(mac_key, seq_num || content_type || version || length || plaintext)
        byte[] macInput = new byte[8 + 1 + 2 + 2 + plaintextLen];
        BinaryPrimitives.WriteUInt64BigEndian(macInput, seqNum);
        macInput[8] = contentType;
        macInput[9] = 0x03; macInput[10] = 0x03; // TLS 1.2
        BinaryPrimitives.WriteUInt16BigEndian(macInput.AsSpan(11), (ushort)plaintextLen);
        if (plaintextLen > 0)
            Array.Copy(decrypted, 0, macInput, 13, plaintextLen);

        byte[] expectedMac = ComputeMac(macHash, macKey, macInput);

        int macGood = CryptographicOperations.FixedTimeEquals(
            recordMac.AsSpan(0, macLength), expectedMac.AsSpan(0, macLength)) ? 1 : 0;

        // Both padding AND MAC must be valid
        if (paddingGood == 0 || macGood == 0)
        {
            CryptographicOperations.ZeroMemory(decrypted);
            CryptographicOperations.ZeroMemory(macInput);
            CryptographicOperations.ZeroMemory(expectedMac);
            return null;
        }

        byte[] plaintext = new byte[plaintextLen];
        Array.Copy(decrypted, 0, plaintext, 0, plaintextLen);

        CryptographicOperations.ZeroMemory(decrypted);
        CryptographicOperations.ZeroMemory(macInput);
        CryptographicOperations.ZeroMemory(expectedMac);

        return plaintext;
    }

    private static byte[] ComputeMac(HashType hashType, byte[] key, byte[] data)
    {
        using HMAC hmac = hashType switch
        {
            HashType.Sha1 => new HMACSHA1(key),
            HashType.Sha384 => new HMACSHA384(key),
            _ => new HMACSHA256(key), // SHA256 default
        };
        return hmac.ComputeHash(data);
    }

    // ========================================================================
    // ChaCha20-Poly1305 Decryption
    // ========================================================================

    /// <summary>
    /// Decrypt ChaCha20-Poly1305 record for TLS 1.2.
    /// Nonce construction same as AES-GCM TLS 1.3 (XOR with seq_num).
    /// RFC 7905: nonce = XOR(write_iv(12), padded_seq(12)), no explicit nonce in record.
    /// Fragment layout: ciphertext(N) + tag(16)
    /// </summary>
    private static byte[]? DecryptChaCha20Tls12(
        byte[] writeKey, byte[] writeIv, ulong seqNum, byte contentType,
        ReadOnlySpan<byte> fragment)
    {
        const int TagLen = 16;
        if (fragment.Length < TagLen + 1)
            return null;

        int ciphertextLen = fragment.Length - TagLen;
        ReadOnlySpan<byte> ciphertext = fragment[..ciphertextLen];
        ReadOnlySpan<byte> tag = fragment.Slice(ciphertextLen, TagLen);

        byte[] nonce = BuildTls13Nonce(writeIv, seqNum); // Same nonce construction

        // AAD = seq_num(8) || content_type(1) || version(2) || plaintext_length(2)
        byte[] aad = new byte[13];
        BinaryPrimitives.WriteUInt64BigEndian(aad, seqNum);
        aad[8] = contentType;
        aad[9] = 0x03; aad[10] = 0x03;
        BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(11), (ushort)ciphertextLen);

        byte[] plaintext = new byte[ciphertextLen];

        using var chacha = new ChaCha20Poly1305(writeKey);
        chacha.Decrypt(nonce, ciphertext, tag, plaintext, aad);

        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(aad);

        return plaintext;
    }

    /// <summary>
    /// Decrypt ChaCha20-Poly1305 record for TLS 1.3.
    /// Same as TLS 1.2 but with TLS 1.3 padding removal.
    /// </summary>
    private static byte[]? DecryptChaCha20Tls13(
        byte[] writeKey, byte[] writeIv, ulong seqNum,
        ReadOnlySpan<byte> fragment, ReadOnlySpan<byte> recordHeader,
        out byte actualContentType)
    {
        actualContentType = 0x17;
        const int TagLen = 16;

        if (fragment.Length < TagLen + 1)
            return null;

        int ciphertextLen = fragment.Length - TagLen;
        ReadOnlySpan<byte> ciphertext = fragment[..ciphertextLen];
        ReadOnlySpan<byte> tag = fragment.Slice(ciphertextLen, TagLen);

        byte[] nonce = BuildTls13Nonce(writeIv, seqNum);
        byte[] aad = recordHeader.ToArray();

        byte[] plaintext = new byte[ciphertextLen];

        using var chacha = new ChaCha20Poly1305(writeKey);
        chacha.Decrypt(nonce, ciphertext, tag, plaintext, aad);

        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(aad);

        return StripTls13Padding(plaintext, out actualContentType);
    }

    // ========================================================================
    // Shared Helpers
    // ========================================================================

    /// <summary>
    /// Build TLS 1.3 nonce: XOR(write_iv, zero-padded sequence number).
    /// Also used by ChaCha20-Poly1305 in TLS 1.2 (RFC 7905).
    /// </summary>
    private static byte[] BuildTls13Nonce(byte[] writeIv, ulong seqNum)
    {
        byte[] nonce = new byte[12];
        writeIv.AsSpan(0, 12).CopyTo(nonce);

        // XOR seq_num (big-endian, right-aligned) into nonce
        byte[] seqBytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(seqBytes, seqNum);
        for (int i = 0; i < 8; i++)
            nonce[4 + i] ^= seqBytes[i];

        CryptographicOperations.ZeroMemory(seqBytes);
        return nonce;
    }

    /// <summary>
    /// TLS 1.3 inner plaintext: strip trailing zero-padding, extract actual content type.
    /// The last non-zero byte is the real content type; everything after it (zeros) is padding.
    /// </summary>
    private static byte[]? StripTls13Padding(byte[] decrypted, out byte actualContentType)
    {
        actualContentType = 0;
        int end = decrypted.Length - 1;

        // Walk backward to find the last non-zero byte (the content type)
        while (end >= 0 && decrypted[end] == 0)
            end--;

        if (end < 0)
            return null; // All zeros — invalid

        actualContentType = decrypted[end];
        if (end == 0)
            return Array.Empty<byte>();

        byte[] result = new byte[end];
        Array.Copy(decrypted, 0, result, 0, end);

        CryptographicOperations.ZeroMemory(decrypted);
        return result;
    }

    // ========================================================================
    // Session Eviction
    // ========================================================================

    private void EvictIdleSessions()
    {
        DateTime now = DateTime.UtcNow;
        if (now - _lastSessionCleanup < TimeSpan.FromMinutes(5))
            return;

        _lastSessionCleanup = now;

        var expired = new List<string>();
        foreach (var kvp in _sessions)
        {
            if (now - kvp.Value.LastActivity > SessionIdleTimeout)
                expired.Add(kvp.Key);
        }

        foreach (string key in expired)
        {
            if (_sessions.TryGetValue(key, out SessionState? s))
            {
                s.ZeroKeys();
                _sessions.Remove(key);
            }
        }
    }

    // ========================================================================
    // Hex Conversion
    // ========================================================================

    private static byte[]? HexToBytes(string hex)
    {
        if (hex.Length % 2 != 0)
            return null;

        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            int hi = HexDigitValue(hex[i * 2]);
            int lo = HexDigitValue(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0)
                return null;
            bytes[i] = (byte)((hi << 4) | lo);
        }
        return bytes;
    }

    private static int HexDigitValue(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1,
    };

    private static string BytesToHex(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
            sb.Append(b.ToString("X2"));
        return sb.ToString();
    }

    // ========================================================================
    // Dispose — Zero all key material
    // ========================================================================

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            _watchTimer?.Dispose();
            _watchTimer = null;

            foreach (var kvp in _masterSecrets)
                CryptographicOperations.ZeroMemory(kvp.Value);
            _masterSecrets.Clear();

            foreach (var kvp in _clientTrafficSecrets)
                CryptographicOperations.ZeroMemory(kvp.Value);
            _clientTrafficSecrets.Clear();

            foreach (var kvp in _serverTrafficSecrets)
                CryptographicOperations.ZeroMemory(kvp.Value);
            _serverTrafficSecrets.Clear();

            foreach (var kvp in _clientHsSecrets)
                CryptographicOperations.ZeroMemory(kvp.Value);
            _clientHsSecrets.Clear();

            foreach (var kvp in _serverHsSecrets)
                CryptographicOperations.ZeroMemory(kvp.Value);
            _serverHsSecrets.Clear();

            foreach (var kvp in _sessions)
                kvp.Value.ZeroKeys();
            _sessions.Clear();
        }
    }

    // ========================================================================
    // Cipher Suite Database
    // ========================================================================

    private static readonly Dictionary<ushort, CipherSuiteInfo> CipherSuiteDb = new()
    {
        // ---- TLS 1.3 cipher suites ----
        [0x1301] = new CipherSuiteInfo(BulkCipherType.AesGcm, 16, 4, HashType.Sha256, 0, HashType.Sha256),   // TLS_AES_128_GCM_SHA256
        [0x1302] = new CipherSuiteInfo(BulkCipherType.AesGcm, 32, 4, HashType.Sha384, 0, HashType.Sha384),   // TLS_AES_256_GCM_SHA384
        [0x1303] = new CipherSuiteInfo(BulkCipherType.ChaCha20Poly1305, 32, 12, HashType.None, 0, HashType.Sha256), // TLS_CHACHA20_POLY1305_SHA256

        // ---- TLS 1.2 ECDHE_RSA with GCM ----
        [0xC02F] = new CipherSuiteInfo(BulkCipherType.AesGcm, 16, 4, HashType.None, 0, HashType.Sha256),     // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        [0xC030] = new CipherSuiteInfo(BulkCipherType.AesGcm, 32, 4, HashType.None, 0, HashType.Sha384),     // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

        // ---- TLS 1.2 ECDHE_ECDSA with GCM ----
        [0xC02B] = new CipherSuiteInfo(BulkCipherType.AesGcm, 16, 4, HashType.None, 0, HashType.Sha256),     // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        [0xC02C] = new CipherSuiteInfo(BulkCipherType.AesGcm, 32, 4, HashType.None, 0, HashType.Sha384),     // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

        // ---- TLS 1.2 RSA with GCM ----
        [0x009C] = new CipherSuiteInfo(BulkCipherType.AesGcm, 16, 4, HashType.None, 0, HashType.Sha256),     // TLS_RSA_WITH_AES_128_GCM_SHA256
        [0x009D] = new CipherSuiteInfo(BulkCipherType.AesGcm, 32, 4, HashType.None, 0, HashType.Sha384),     // TLS_RSA_WITH_AES_256_GCM_SHA384

        // ---- TLS 1.2 DHE_RSA with GCM ----
        [0x009E] = new CipherSuiteInfo(BulkCipherType.AesGcm, 16, 4, HashType.None, 0, HashType.Sha256),     // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        [0x009F] = new CipherSuiteInfo(BulkCipherType.AesGcm, 32, 4, HashType.None, 0, HashType.Sha384),     // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384

        // ---- TLS 1.2 ECDHE with ChaCha20 ----
        [0xCCA8] = new CipherSuiteInfo(BulkCipherType.ChaCha20Poly1305, 32, 12, HashType.None, 0, HashType.Sha256), // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        [0xCCA9] = new CipherSuiteInfo(BulkCipherType.ChaCha20Poly1305, 32, 12, HashType.None, 0, HashType.Sha256), // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        [0xCCAA] = new CipherSuiteInfo(BulkCipherType.ChaCha20Poly1305, 32, 12, HashType.None, 0, HashType.Sha256), // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256

        // ---- TLS 1.2 RSA with AES-CBC ----
        [0x002F] = new CipherSuiteInfo(BulkCipherType.AesCbc, 16, 16, HashType.Sha1, 20, HashType.Sha256),   // TLS_RSA_WITH_AES_128_CBC_SHA
        [0x0035] = new CipherSuiteInfo(BulkCipherType.AesCbc, 32, 16, HashType.Sha1, 20, HashType.Sha256),   // TLS_RSA_WITH_AES_256_CBC_SHA
        [0x003C] = new CipherSuiteInfo(BulkCipherType.AesCbc, 16, 16, HashType.Sha256, 32, HashType.Sha256), // TLS_RSA_WITH_AES_128_CBC_SHA256
        [0x003D] = new CipherSuiteInfo(BulkCipherType.AesCbc, 32, 16, HashType.Sha256, 32, HashType.Sha256), // TLS_RSA_WITH_AES_256_CBC_SHA256

        // ---- TLS 1.2 ECDHE_RSA with AES-CBC ----
        [0xC013] = new CipherSuiteInfo(BulkCipherType.AesCbc, 16, 16, HashType.Sha1, 20, HashType.Sha256),   // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        [0xC014] = new CipherSuiteInfo(BulkCipherType.AesCbc, 32, 16, HashType.Sha1, 20, HashType.Sha256),   // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        [0xC027] = new CipherSuiteInfo(BulkCipherType.AesCbc, 16, 16, HashType.Sha256, 32, HashType.Sha256), // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        [0xC028] = new CipherSuiteInfo(BulkCipherType.AesCbc, 32, 16, HashType.Sha384, 48, HashType.Sha384), // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384

        // ---- TLS 1.2 ECDHE_ECDSA with AES-CBC ----
        [0xC009] = new CipherSuiteInfo(BulkCipherType.AesCbc, 16, 16, HashType.Sha1, 20, HashType.Sha256),   // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        [0xC00A] = new CipherSuiteInfo(BulkCipherType.AesCbc, 32, 16, HashType.Sha1, 20, HashType.Sha256),   // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        [0xC023] = new CipherSuiteInfo(BulkCipherType.AesCbc, 16, 16, HashType.Sha256, 32, HashType.Sha256), // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        [0xC024] = new CipherSuiteInfo(BulkCipherType.AesCbc, 32, 16, HashType.Sha384, 48, HashType.Sha384), // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384

        // ---- TLS 1.2 DHE_RSA with AES-CBC ----
        [0x0033] = new CipherSuiteInfo(BulkCipherType.AesCbc, 16, 16, HashType.Sha1, 20, HashType.Sha256),   // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        [0x0039] = new CipherSuiteInfo(BulkCipherType.AesCbc, 32, 16, HashType.Sha1, 20, HashType.Sha256),   // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        [0x0067] = new CipherSuiteInfo(BulkCipherType.AesCbc, 16, 16, HashType.Sha256, 32, HashType.Sha256), // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        [0x006B] = new CipherSuiteInfo(BulkCipherType.AesCbc, 32, 16, HashType.Sha256, 32, HashType.Sha256), // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    };

    // ========================================================================
    // Supporting Types
    // ========================================================================

    /// <summary>Result of a successful TLS record decryption.</summary>
    public readonly struct DecryptionResult
    {
        /// <summary>Actual content type (may differ from outer record in TLS 1.3).</summary>
        public readonly byte ContentType;

        /// <summary>Decrypted plaintext bytes.</summary>
        public readonly byte[] Plaintext;

        public DecryptionResult(byte contentType, byte[] plaintext)
        {
            ContentType = contentType;
            Plaintext = plaintext;
        }

        /// <summary>True if this is application data (HTTP, SMTP, etc.).</summary>
        public bool IsApplicationData => ContentType == 0x17;

        /// <summary>True if this is a handshake message (certificate, etc.).</summary>
        public bool IsHandshake => ContentType == 0x16;
    }

    /// <summary>Per-connection decryption state including derived keys and sequence numbers.</summary>
    private sealed class SessionState
    {
        public byte[] ClientWriteKey = Array.Empty<byte>();
        public byte[] ServerWriteKey = Array.Empty<byte>();
        public byte[] ClientWriteIv = Array.Empty<byte>();
        public byte[] ServerWriteIv = Array.Empty<byte>();
        public byte[]? ClientMacKey;  // CBC only
        public byte[]? ServerMacKey;  // CBC only

        public ulong ClientSeqNum;
        public ulong ServerSeqNum;

        public CipherSuiteInfo CipherInfo;
        public bool IsTls13;
        public DateTime LastActivity;

        public void ZeroKeys()
        {
            CryptographicOperations.ZeroMemory(ClientWriteKey);
            CryptographicOperations.ZeroMemory(ServerWriteKey);
            CryptographicOperations.ZeroMemory(ClientWriteIv);
            CryptographicOperations.ZeroMemory(ServerWriteIv);
            if (ClientMacKey != null) CryptographicOperations.ZeroMemory(ClientMacKey);
            if (ServerMacKey != null) CryptographicOperations.ZeroMemory(ServerMacKey);
        }
    }

    /// <summary>Cipher suite metadata needed for key derivation and decryption.</summary>
    private readonly struct CipherSuiteInfo
    {
        public readonly BulkCipherType BulkCipher;
        public readonly int KeyLength;       // Encryption key length in bytes
        public readonly int FixedIvLength;   // GCM: 4 (implicit), CBC: 16, ChaCha20: 12
        public readonly HashType MacHash;    // For CBC HMAC verification (None for AEAD)
        public readonly int MacLength;       // MAC output length in bytes (0 for AEAD)
        public readonly HashType PrfHash;    // PRF hash for key derivation (SHA256 or SHA384)

        public CipherSuiteInfo(
            BulkCipherType bulkCipher, int keyLength, int fixedIvLength,
            HashType macHash, int macLength, HashType prfHash)
        {
            BulkCipher = bulkCipher;
            KeyLength = keyLength;
            FixedIvLength = fixedIvLength;
            MacHash = macHash;
            MacLength = macLength;
            PrfHash = prfHash;
        }
    }

    private enum BulkCipherType : byte
    {
        AesGcm,
        AesCbc,
        ChaCha20Poly1305,
    }

    private enum HashType : byte
    {
        None,
        Sha1,
        Sha256,
        Sha384,
    }
}
