using System.Text;
using System.Text.RegularExpressions;
using RedPacketSniffer.Core.Capture;

namespace RedPacketSniffer.Core.Analysis;

/// <summary>
/// HTTP Request/Response Logger — parse cleartext HTTP traffic
///
/// Trích xuất:
/// - Request: Method, URL, Host, User-Agent, Referer, Content-Type, Cookies, POST body
/// - Response: Status code, Server header, Set-Cookie, Content-Type, Content-Length
///
/// Hữu ích cho red team:
/// - Recon: xem target truy cập website/API nào, endpoints nào được gọi
/// - Session Hijacking: extract cookies/session tokens từ cleartext HTTP
/// - Data Exfiltration: detect sensitive data trong POST body, query params
/// - Identify internal applications: Host header reveals internal hostnames
/// - API Discovery: map API endpoints từ observed traffic
/// - Detect insecure configurations: cookies không HttpOnly/Secure, sensitive headers
/// </summary>
public sealed class HttpRequestLogger
{
    private readonly List<HttpLogEntry> _entries = new();
    private readonly object _lock = new();
    private readonly Dictionary<string, int> _hostCount = new(); // host -> request count
    private readonly Dictionary<string, HashSet<string>> _hostEndpoints = new(); // host -> unique URLs
    private long _analyzeCount;

    /// <summary>Maximum bytes of HTTP payload to convert to string. Headers + partial body.</summary>
    private const int MaxHttpPayloadBytes = 8192;

    /// <summary>Size caps to prevent unbounded RAM growth.</summary>
    private const int MaxEntries = 10_000;
    private const int MaxHosts = 5000;
    private const int MaxEndpointsPerHost = 500;

    /// <summary>When entries exceed cap, trim this many oldest entries at once to avoid trimming on every packet.</summary>
    private const int TrimBatchSize = 2000;

    public event Action<HttpLogEntry>? OnHttpEntry;

    /// <summary>
    /// Phân tích packet cho HTTP traffic
    /// </summary>
    public void Analyze(CapturedPacket packet)
    {
        if (packet.IpProtocol != 6) return; // TCP only
        if (packet.RawData.Length == 0) return;

        ReadOnlySpan<byte> payload = packet.GetPayload();
        if (payload.Length < 16) return;

        // Span-based quick check BEFORE allocating a string — reject non-HTTP at zero cost.
        bool isRequest = IsHttpRequestSpan(payload);
        bool isResponse = !isRequest && payload.StartsWith("HTTP/"u8);
        if (!isRequest && !isResponse) return;

        try
        {
            // Limit string conversion to MaxHttpPayloadBytes.
            int convertLen = Math.Min(payload.Length, MaxHttpPayloadBytes);
            string payloadStr = Encoding.ASCII.GetString(payload[..convertLen]);

            if (isRequest)
            {
                var entry = ParseHttpRequest(payloadStr, packet);
                if (entry != null) EmitEntry(entry);
            }
            else
            {
                var entry = ParseHttpResponse(payloadStr, packet);
                if (entry != null) EmitEntry(entry);
            }
        }
        catch
        {
            // Skip malformed HTTP
        }
    }

    /// <summary>
    /// Span-based HTTP request detection — zero allocation. Checks if payload starts
    /// with a known HTTP method followed by a space.
    /// </summary>
    private static bool IsHttpRequestSpan(ReadOnlySpan<byte> data)
    {
        return data.StartsWith("GET "u8) || data.StartsWith("POST "u8) ||
               data.StartsWith("PUT "u8) || data.StartsWith("DELETE "u8) ||
               data.StartsWith("PATCH "u8) || data.StartsWith("HEAD "u8) ||
               data.StartsWith("OPTIONS "u8) || data.StartsWith("CONNECT "u8);
    }

    private static bool IsHttpRequest(string data)
    {
        return data.StartsWith("GET ", StringComparison.Ordinal) ||
               data.StartsWith("POST ", StringComparison.Ordinal) ||
               data.StartsWith("PUT ", StringComparison.Ordinal) ||
               data.StartsWith("DELETE ", StringComparison.Ordinal) ||
               data.StartsWith("PATCH ", StringComparison.Ordinal) ||
               data.StartsWith("HEAD ", StringComparison.Ordinal) ||
               data.StartsWith("OPTIONS ", StringComparison.Ordinal) ||
               data.StartsWith("CONNECT ", StringComparison.Ordinal);
    }

    private HttpLogEntry? ParseHttpRequest(string data, CapturedPacket packet)
    {
        // Tách request line
        int firstNewline = data.IndexOf("\r\n", StringComparison.Ordinal);
        if (firstNewline < 0) return null;

        string requestLine = data[..firstNewline];
        string[] parts = requestLine.Split(' ', 3);
        if (parts.Length < 2) return null;

        string method = parts[0];
        string url = parts[1];
        string httpVersion = parts.Length > 2 ? parts[2] : "";

        // Parse headers
        int headerEnd = data.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        string headerBlock = headerEnd > 0 ? data[firstNewline..headerEnd] : data[firstNewline..];
        var headers = ParseHeaders(headerBlock);

        // Extract key fields
        string host = GetHeader(headers, "Host") ?? packet.DestIP ?? "";
        string userAgent = GetHeader(headers, "User-Agent") ?? "";
        string referer = GetHeader(headers, "Referer") ?? "";
        string contentType = GetHeader(headers, "Content-Type") ?? "";
        string cookie = GetHeader(headers, "Cookie") ?? "";
        string authorization = GetHeader(headers, "Authorization") ?? "";
        string accept = GetHeader(headers, "Accept") ?? "";

        // Extract POST body (nếu có)
        string body = "";
        if (headerEnd > 0 && headerEnd + 4 < data.Length)
        {
            body = data[(headerEnd + 4)..];
            if (body.Length > 2000) body = body[..2000] + "...";
        }

        // Extract cookies chi tiết
        var cookies = ParseCookies(cookie);

        // Anomaly detection
        var flags = new List<string>();
        DetectRequestAnomalies(method, url, host, headers, body, cookies, flags);

        var entry = new HttpLogEntry
        {
            Timestamp = packet.Timestamp,
            PacketId = packet.Id,
            IsRequest = true,
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            SourcePort = packet.SourcePort,
            DestPort = packet.DestPort,
            Method = method,
            Url = url,
            FullUrl = $"http://{host}{url}",
            Host = host,
            HttpVersion = httpVersion,
            UserAgent = userAgent,
            Referer = referer,
            ContentType = contentType,
            CookieHeader = cookie,
            Cookies = cookies,
            Authorization = authorization,
            Body = body,
            Headers = headers,
            AnomalyFlags = flags
        };

        return entry;
    }

    private HttpLogEntry? ParseHttpResponse(string data, CapturedPacket packet)
    {
        int firstNewline = data.IndexOf("\r\n", StringComparison.Ordinal);
        if (firstNewline < 0) return null;

        string statusLine = data[..firstNewline];
        // HTTP/1.1 200 OK
        var statusMatch = Regex.Match(statusLine, @"HTTP/[\d.]+\s+(\d{3})\s*(.*)");
        if (!statusMatch.Success) return null;

        int statusCode = int.Parse(statusMatch.Groups[1].Value);
        string statusText = statusMatch.Groups[2].Value;

        // Parse headers
        int headerEnd = data.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        string headerBlock = headerEnd > 0 ? data[firstNewline..headerEnd] : data[firstNewline..];
        var headers = ParseHeaders(headerBlock);

        string server = GetHeader(headers, "Server") ?? "";
        string contentType = GetHeader(headers, "Content-Type") ?? "";
        string contentLength = GetHeader(headers, "Content-Length") ?? "";
        string setCookie = GetHeader(headers, "Set-Cookie") ?? "";
        string location = GetHeader(headers, "Location") ?? "";
        string wwwAuth = GetHeader(headers, "WWW-Authenticate") ?? "";

        // Extract Set-Cookie chi tiết
        var setCookies = new List<SetCookieInfo>();
        foreach (var (key, val) in headers)
        {
            if (key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            {
                setCookies.Add(ParseSetCookie(val));
            }
        }

        // Anomaly detection
        var flags = new List<string>();
        DetectResponseAnomalies(statusCode, headers, setCookies, flags);

        var entry = new HttpLogEntry
        {
            Timestamp = packet.Timestamp,
            PacketId = packet.Id,
            IsRequest = false,
            SourceIP = packet.SourceIP ?? "",
            DestIP = packet.DestIP ?? "",
            SourcePort = packet.SourcePort,
            DestPort = packet.DestPort,
            StatusCode = statusCode,
            StatusText = statusText,
            ServerHeader = server,
            ContentType = contentType,
            ContentLength = contentLength,
            SetCookies = setCookies,
            Location = location,
            WwwAuthenticate = wwwAuth,
            Headers = headers,
            AnomalyFlags = flags
        };

        return entry;
    }

    private void DetectRequestAnomalies(string method, string url, string host,
        List<(string key, string val)> headers, string body, List<CookieInfo> cookies, List<string> flags)
    {
        // Sensitive data in URL query string
        string urlLower = url.ToLowerInvariant();
        if (urlLower.Contains("password=") || urlLower.Contains("passwd=") || urlLower.Contains("secret=") || urlLower.Contains("token="))
            flags.Add("SENSITIVE_URL: credentials/tokens in query string");

        if (urlLower.Contains("api_key=") || urlLower.Contains("apikey=") || urlLower.Contains("access_token="))
            flags.Add("API_KEY_LEAK: API key in URL");

        // Session cookies sent over HTTP (not HTTPS)
        if (cookies.Any(c => c.Name.Contains("session", StringComparison.OrdinalIgnoreCase) ||
                              c.Name.Contains("JSESSIONID", StringComparison.OrdinalIgnoreCase) ||
                              c.Name.Contains("PHPSESSID", StringComparison.OrdinalIgnoreCase) ||
                              c.Name.Contains("ASP.NET_SessionId", StringComparison.OrdinalIgnoreCase)))
        {
            flags.Add("SESSION_CLEARTEXT: session cookie sent over HTTP");
        }

        // Authorization header over cleartext
        if (!string.IsNullOrEmpty(GetHeader(headers, "Authorization")))
            flags.Add("AUTH_CLEARTEXT: Authorization header over HTTP");

        // Internal hostnames
        if (host.Contains(".local") || host.Contains(".internal") || host.Contains(".corp") ||
            host.Contains(".lan") || host.Contains("intranet"))
            flags.Add($"INTERNAL_HOST: {host}");

        // Sensitive POST data
        string bodyLower = body.ToLowerInvariant();
        if (method == "POST" && (bodyLower.Contains("password") || bodyLower.Contains("credit_card") ||
            bodyLower.Contains("ssn") || bodyLower.Contains("secret")))
            flags.Add("SENSITIVE_POST: potential sensitive data in POST body");

        // Suspicious paths
        if (urlLower.Contains("/admin") || urlLower.Contains("/wp-admin") || urlLower.Contains("/phpmyadmin") ||
            urlLower.Contains("/manager") || urlLower.Contains("/.env") || urlLower.Contains("/.git"))
            flags.Add("SUSPICIOUS_PATH: admin/config path accessed");
    }

    private void DetectResponseAnomalies(int statusCode, List<(string key, string val)> headers,
        List<SetCookieInfo> setCookies, List<string> flags)
    {
        // Missing security headers
        if (string.IsNullOrEmpty(GetHeader(headers, "X-Frame-Options")) &&
            string.IsNullOrEmpty(GetHeader(headers, "Content-Security-Policy")))
            flags.Add("MISSING_HEADERS: no X-Frame-Options or CSP");

        if (string.IsNullOrEmpty(GetHeader(headers, "Strict-Transport-Security")))
            flags.Add("NO_HSTS: missing Strict-Transport-Security header");

        // Insecure cookies
        foreach (var sc in setCookies)
        {
            if (!sc.HttpOnly && (sc.Name.Contains("session", StringComparison.OrdinalIgnoreCase) ||
                                  sc.Name.Contains("token", StringComparison.OrdinalIgnoreCase)))
                flags.Add($"COOKIE_NO_HTTPONLY: {sc.Name} missing HttpOnly flag");
            if (!sc.Secure)
                flags.Add($"COOKIE_NO_SECURE: {sc.Name} missing Secure flag");
        }

        // Server header information disclosure
        string server = GetHeader(headers, "Server") ?? "";
        if (Regex.IsMatch(server, @"\d+\.\d+", RegexOptions.None))
            flags.Add($"SERVER_VERSION: {server}");

        // X-Powered-By disclosure
        string poweredBy = GetHeader(headers, "X-Powered-By") ?? "";
        if (!string.IsNullOrEmpty(poweredBy))
            flags.Add($"POWERED_BY: {poweredBy}");

        // Authentication required
        if (statusCode == 401)
            flags.Add("AUTH_REQUIRED: 401 Unauthorized");
        if (statusCode == 403)
            flags.Add("FORBIDDEN: 403 Forbidden");
    }

    private static List<(string key, string val)> ParseHeaders(string headerBlock)
    {
        var headers = new List<(string, string)>();
        foreach (string line in headerBlock.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            int colonIdx = line.IndexOf(':');
            if (colonIdx > 0)
            {
                headers.Add((line[..colonIdx].Trim(), line[(colonIdx + 1)..].Trim()));
            }
        }
        return headers;
    }

    private static string? GetHeader(List<(string key, string val)> headers, string name)
    {
        return headers.FirstOrDefault(h => h.key.Equals(name, StringComparison.OrdinalIgnoreCase)).val;
    }

    private static List<CookieInfo> ParseCookies(string cookieHeader)
    {
        var cookies = new List<CookieInfo>();
        if (string.IsNullOrEmpty(cookieHeader)) return cookies;

        foreach (string part in cookieHeader.Split(';'))
        {
            string trimmed = part.Trim();
            int eqIdx = trimmed.IndexOf('=');
            if (eqIdx > 0)
            {
                cookies.Add(new CookieInfo
                {
                    Name = trimmed[..eqIdx].Trim(),
                    Value = trimmed[(eqIdx + 1)..].Trim()
                });
            }
        }
        return cookies;
    }

    private static SetCookieInfo ParseSetCookie(string setCookieValue)
    {
        var parts = setCookieValue.Split(';');
        string nameValue = parts[0].Trim();
        int eqIdx = nameValue.IndexOf('=');

        var info = new SetCookieInfo
        {
            Name = eqIdx > 0 ? nameValue[..eqIdx].Trim() : nameValue,
            Value = eqIdx > 0 ? nameValue[(eqIdx + 1)..].Trim() : "",
            Raw = setCookieValue
        };

        string lower = setCookieValue.ToLowerInvariant();
        info.HttpOnly = lower.Contains("httponly");
        info.Secure = lower.Contains("secure");
        info.SameSite = lower.Contains("samesite");

        var pathMatch = Regex.Match(setCookieValue, @"[Pp]ath=([^;]+)");
        if (pathMatch.Success) info.Path = pathMatch.Groups[1].Value.Trim();

        var domainMatch = Regex.Match(setCookieValue, @"[Dd]omain=([^;]+)");
        if (domainMatch.Success) info.Domain = domainMatch.Groups[1].Value.Trim();

        return info;
    }

    private void EmitEntry(HttpLogEntry entry)
    {
        lock (_lock)
        {
            // Trim oldest entries in batch when cap exceeded — avoids trimming on every packet.
            if (_entries.Count >= MaxEntries)
                _entries.RemoveRange(0, TrimBatchSize);

            _entries.Add(entry);

            // Track host statistics
            if (entry.IsRequest && !string.IsNullOrEmpty(entry.Host))
            {
                string hostKey = entry.Host.ToLowerInvariant();

                // Cap host tracking to prevent DoS from scanning traffic with thousands of unique hosts
                if (_hostCount.Count < MaxHosts || _hostCount.ContainsKey(hostKey))
                {
                    _hostCount[hostKey] = _hostCount.GetValueOrDefault(hostKey) + 1;

                    if (!_hostEndpoints.TryGetValue(hostKey, out var endpoints))
                    {
                        endpoints = new HashSet<string>();
                        _hostEndpoints[hostKey] = endpoints;
                    }

                    // Cap endpoints per host to prevent memory bloat from API fuzzing traffic
                    if (endpoints.Count < MaxEndpointsPerHost)
                    {
                        string endpoint = entry.Url.Split('?')[0];
                        endpoints.Add($"{entry.Method} {endpoint}");
                    }
                }
            }
        }

        OnHttpEntry?.Invoke(entry);
    }

    public List<HttpLogEntry> GetAllEntries()
    {
        lock (_lock) { return new List<HttpLogEntry>(_entries); }
    }

    public Dictionary<string, int> GetTopHosts(int count = 20)
    {
        lock (_lock)
        {
            return _hostCount
                .OrderByDescending(kv => kv.Value)
                .Take(count)
                .ToDictionary(kv => kv.Key, kv => kv.Value);
        }
    }

    public Dictionary<string, List<string>> GetHostEndpoints()
    {
        lock (_lock)
        {
            return _hostEndpoints.ToDictionary(kv => kv.Key, kv => kv.Value.ToList());
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
            _hostCount.Clear();
            _hostEndpoints.Clear();
        }
    }
}

public class HttpLogEntry
{
    public DateTime Timestamp { get; init; }
    public long PacketId { get; init; }
    public bool IsRequest { get; init; }
    public string SourceIP { get; init; } = "";
    public string DestIP { get; init; } = "";
    public ushort SourcePort { get; init; }
    public ushort DestPort { get; init; }

    // Request fields
    public string Method { get; init; } = "";
    public string Url { get; init; } = "";
    public string FullUrl { get; init; } = "";
    public string Host { get; init; } = "";
    public string HttpVersion { get; init; } = "";
    public string UserAgent { get; init; } = "";
    public string Referer { get; init; } = "";
    public string ContentType { get; init; } = "";
    public string CookieHeader { get; init; } = "";
    public List<CookieInfo> Cookies { get; init; } = new();
    public string Authorization { get; init; } = "";
    public string Body { get; init; } = "";

    // Response fields
    public int StatusCode { get; init; }
    public string StatusText { get; init; } = "";
    public string ServerHeader { get; init; } = "";
    public string ContentLength { get; init; } = "";
    public List<SetCookieInfo> SetCookies { get; init; } = new();
    public string Location { get; init; } = "";
    public string WwwAuthenticate { get; init; } = "";

    // Common
    public List<(string key, string val)> Headers { get; init; } = new();
    public List<string> AnomalyFlags { get; init; } = new();
}

public class CookieInfo
{
    public string Name { get; init; } = "";
    public string Value { get; init; } = "";
}

public class SetCookieInfo
{
    public string Name { get; init; } = "";
    public string Value { get; init; } = "";
    public string Raw { get; init; } = "";
    public bool HttpOnly { get; set; }
    public bool Secure { get; set; }
    public bool SameSite { get; set; }
    public string Path { get; set; } = "";
    public string Domain { get; set; } = "";
}
