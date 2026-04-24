package com.lauriewired;

import com.sun.net.httpserver.HttpExchange;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Helpers HTTP/JSON shared between GhidraMCPPlugin (CodeBrowser) and
 * GhidraMCPDebuggerPlugin (Debugger tool). Extracted so both plugins emit
 * identical wire formats (text/plain, newline-delimited) without duplicating
 * parse/serialize logic.
 */
public final class Util {
    /** Max pagination limit the server will honor before clamping. */
    public static final int MAX_LIMIT = 10000;
    /** Default wait for async debugger ops. */
    public static final int ASYNC_TIMEOUT_SEC = 30;

    private Util() {}

    public static Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        if (query != null) {
            for (String p : query.split("&")) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(Util.class, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    public static String readBody(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    public static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        String bodyStr = readBody(exchange);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(Util.class, "Error decoding form parameter", e);
                }
            }
        }
        return params;
    }

    public static String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end = Math.min(items.size(), offset + limit);
        if (start >= items.size()) return "";
        return String.join("\n", items.subList(start, end));
    }

    public static int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /** Clamps the parsed limit into [0, MAX_LIMIT] so a client can't request an unbounded slice. */
    public static int parseLimitOrDefault(String val, int defaultValue) {
        int v = parseIntOrDefault(val, defaultValue);
        if (v < 0) return 0;
        return Math.min(v, MAX_LIMIT);
    }

    /**
     * Drop the "/ * WARNING: ... * /" header comments that Ghidra's decompiler
     * prepends for injections, analysis hints and guesses. They pollute the
     * output and an LLM agent cannot act on them anyway. Matches any line
     * whose trimmed content opens with the warning marker.
     */
    public static String stripDecompileWarnings(String input) {
        if (input == null || input.isEmpty()) return input;
        StringBuilder out = new StringBuilder(input.length());
        for (String line : input.split("\n", -1)) {
            String trimmed = line.trim();
            if (trimmed.startsWith("/* WARNING:")) continue;
            if (out.length() > 0) out.append('\n');
            out.append(line);
        }
        return out.toString();
    }

    public static String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    /** Epoch millis at which this Util class (and therefore the plugin JVM)
     *  was loaded. Used by /health and /stats to report uptime. */
    public static final long STARTUP_MS = System.currentTimeMillis();

    /** Seconds since the plugin loaded. */
    public static long uptimeSeconds() {
        return (System.currentTimeMillis() - STARTUP_MS) / 1000;
    }

    /** Plugin semantic version, surfaced by /health and /version. */
    public static final String PLUGIN_VERSION = "1.0-SNAPSHOT";

    // Lightweight request counting. ConcurrentHashMap for read-mostly access
    // from many worker threads; AtomicLong per endpoint to avoid a map-level
    // lock on every increment. Not exposed as a public collection so callers
    // can't mutate it — snapshots are taken via buildStatsSnapshot().
    private static final Map<String, AtomicLong> REQUESTS_BY_PATH = new ConcurrentHashMap<>();
    private static final AtomicLong TOTAL_REQUESTS = new AtomicLong();
    private static final AtomicLong TOTAL_RESPONSE_BYTES = new AtomicLong();

    private static void recordRequest(HttpExchange exchange, int bodyBytes) {
        try {
            String path = exchange.getRequestURI().getPath();
            REQUESTS_BY_PATH.computeIfAbsent(path, k -> new AtomicLong()).incrementAndGet();
            TOTAL_REQUESTS.incrementAndGet();
            TOTAL_RESPONSE_BYTES.addAndGet(bodyBytes);
        } catch (Exception ignore) { /* never let metrics break the response */ }
    }

    /** Snapshot of request counters for /stats. */
    public static Map<String, Object> buildStatsSnapshot() {
        Map<String, Object> out = new LinkedHashMap<>();
        long up = Math.max(1, uptimeSeconds());
        out.put("uptime_sec", uptimeSeconds());
        long total = TOTAL_REQUESTS.get();
        out.put("total_requests", total);
        out.put("requests_per_sec", String.format("%.3f", (double) total / up));
        out.put("total_response_bytes", TOTAL_RESPONSE_BYTES.get());
        Map<String, Long> byPath = new TreeMap<>();
        for (Map.Entry<String, AtomicLong> e : REQUESTS_BY_PATH.entrySet()) {
            byPath.put(e.getKey(), e.getValue().get());
        }
        out.put("by_endpoint", byPath);
        return out;
    }

    /** Safety cap on any single HTTP response body sent by the plugin. 256 KB
     *  is large enough for decompiled functions and sizeable listings, and
     *  small enough to avoid blowing up the MCP client's context window when
     *  a query accidentally matches too much. Override via Tool Options is a
     *  future enhancement; for now it's a compile-time constant. */
    public static final int MAX_RESPONSE_BYTES = 256 * 1024;

    public static void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = (response == null ? "" : response).getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_RESPONSE_BYTES) {
            int kept = MAX_RESPONSE_BYTES;
            long dropped = (long) bytes.length - kept;
            byte[] truncated = new byte[kept];
            System.arraycopy(bytes, 0, truncated, 0, kept);
            String suffix = "\n... [truncated, " + dropped + " more bytes — narrow your query or pass offset/limit]";
            byte[] suffixBytes = suffix.getBytes(StandardCharsets.UTF_8);
            // Make room for the suffix inside the cap so the total wire size
            // stays under MAX_RESPONSE_BYTES even after appending it.
            int newLen = Math.max(0, kept - suffixBytes.length);
            byte[] out = new byte[newLen + suffixBytes.length];
            System.arraycopy(truncated, 0, out, 0, newLen);
            System.arraycopy(suffixBytes, 0, out, newLen, suffixBytes.length);
            bytes = out;
        }
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
        recordRequest(exchange, bytes.length);
    }

    /**
     * Serialize a Java value to a compact JSON string. Symmetric counterpart
     * to MiniJson.parse — handles null / Boolean / Number / CharSequence /
     * Map / Iterable. Anything else is toString()'d and emitted as a JSON
     * string. Cycles are not detected; don't pass recursive graphs.
     */
    public static String toJson(Object value) {
        StringBuilder sb = new StringBuilder();
        appendJson(sb, value);
        return sb.toString();
    }

    private static void appendJson(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof Boolean) { sb.append(((Boolean) v).booleanValue() ? "true" : "false"); return; }
        if (v instanceof Number) { sb.append(v.toString()); return; }
        if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) sb.append(',');
                appendJsonString(sb, String.valueOf(e.getKey()));
                sb.append(':');
                appendJson(sb, e.getValue());
                first = false;
            }
            sb.append('}');
            return;
        }
        if (v instanceof Iterable) {
            sb.append('[');
            boolean first = true;
            for (Object it : (Iterable<?>) v) {
                if (!first) sb.append(',');
                appendJson(sb, it);
                first = false;
            }
            sb.append(']');
            return;
        }
        appendJsonString(sb, v.toString());
    }

    private static void appendJsonString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    /**
     * Emit a JSON error document with an explicit HTTP status code.
     * Body shape: {"error": "...", "code": N}. Callers pick the code:
     *   400 for malformed input (missing/invalid query param)
     *   404 when the resource (function, instruction, launcher) isn't there
     *   503 when the plugin is alive but the feature depends on state that
     *       isn't current (no program loaded, no debug session)
     *   500 for unhandled exceptions
     * Picked only 4xx/5xx codes an agent can special-case meaningfully.
     */
    public static void sendError(HttpExchange exchange, int status, String message) throws IOException {
        String safe = message == null ? "" : message.replace("\\", "\\\\").replace("\"", "\\\"")
                                                    .replace("\n", " ").replace("\r", "");
        String body = "{\"error\":\"" + safe + "\",\"code\":" + status + "}";
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
        recordRequest(exchange, bytes.length);
    }

    /** Inspect a JSON body built by a handler and route to sendError with a
     *  status guessed from its text, or sendJson with 200 if no error field.
     *  Heuristic — keeps the refactor bounded without migrating every handler
     *  to a code-carrying return type. */
    public static void sendJsonAuto(HttpExchange exchange, String jsonBody) throws IOException {
        if (jsonBody != null && jsonBody.startsWith("{\"error\":")) {
            int code = 400;
            String lc = jsonBody.toLowerCase();
            if (lc.contains("no program loaded") || lc.contains("no active debug session")) code = 503;
            else if (lc.contains("not found") || lc.contains("no function") || lc.contains("no instruction")
                 || lc.contains("launcher not found")) code = 404;
            // Strip the already-embedded {"error":"..."} wrapper so we don't
            // double-nest the message; extract the raw text.
            String msg = jsonBody;
            int s = jsonBody.indexOf("\"error\":\"");
            if (s >= 0) {
                int start = s + "\"error\":\"".length();
                int end = jsonBody.indexOf("\"", start);
                while (end > 0 && jsonBody.charAt(end - 1) == '\\') {
                    end = jsonBody.indexOf("\"", end + 1);
                }
                if (end > start) msg = jsonBody.substring(start, end);
            }
            sendError(exchange, code, msg);
            return;
        }
        sendJson(exchange, jsonBody);
    }

    /**
     * Send a JSON response with application/json Content-Type and the size
     * cap from sendResponse. The body argument is written verbatim — build
     * it with toJson().
     */
    public static void sendJson(HttpExchange exchange, String jsonBody) throws IOException {
        byte[] bytes = (jsonBody == null ? "{}" : jsonBody).getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_RESPONSE_BYTES) {
            // For JSON we can't splice a suffix in the middle without breaking
            // the structure. Instead replace with a single error document.
            String err = "{\"error\":\"response exceeded " + MAX_RESPONSE_BYTES
                + " bytes (" + bytes.length + "); narrow your query\"}";
            bytes = err.getBytes(StandardCharsets.UTF_8);
        }
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
        recordRequest(exchange, bytes.length);
    }

    /**
     * Block on a CompletableFuture with the default async timeout. Used by
     * debugger endpoints where the underlying API is async (GDB/dbgeng comms).
     */
    public static <T> T waitFor(CompletableFuture<T> cf) throws Exception {
        return cf.get(ASYNC_TIMEOUT_SEC, TimeUnit.SECONDS);
    }

    public static <T> T waitFor(CompletableFuture<T> cf, int timeoutSec) throws Exception {
        return cf.get(timeoutSec, TimeUnit.SECONDS);
    }

    /**
     * Minimal recursive-descent JSON parser. Returns null / Boolean / Long / Double /
     * String / List&lt;Object&gt; / LinkedHashMap&lt;String,Object&gt;. Scoped deliberately small —
     * no streaming, no reviver, no custom numbers. Throws RuntimeException on bad input.
     */
    public static final class MiniJson {
        private final String s;
        private int i;

        private MiniJson(String s) { this.s = s; this.i = 0; }

        public static Object parse(String text) {
            if (text == null) throw new RuntimeException("Empty body");
            MiniJson p = new MiniJson(text);
            p.skipWs();
            Object v = p.parseValue();
            p.skipWs();
            if (p.i < p.s.length()) {
                throw new RuntimeException("Unexpected trailing content at pos " + p.i);
            }
            return v;
        }

        private void skipWs() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }

        private Object parseValue() {
            skipWs();
            if (i >= s.length()) throw new RuntimeException("Unexpected end of input");
            char c = s.charAt(i);
            if (c == '"') return parseString();
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
            if (s.startsWith("null", i))  { i += 4; return null; }
            if (s.startsWith("true", i))  { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            throw new RuntimeException("Unexpected char '" + c + "' at pos " + i);
        }

        private String parseString() {
            if (s.charAt(i) != '"') throw new RuntimeException("Expected '\"' at pos " + i);
            i++;
            StringBuilder out = new StringBuilder();
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') return out.toString();
                if (c == '\\') {
                    if (i >= s.length()) throw new RuntimeException("Bad escape at EOF");
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"': out.append('"'); break;
                        case '\\': out.append('\\'); break;
                        case '/': out.append('/'); break;
                        case 'b': out.append('\b'); break;
                        case 'f': out.append('\f'); break;
                        case 'n': out.append('\n'); break;
                        case 'r': out.append('\r'); break;
                        case 't': out.append('\t'); break;
                        case 'u':
                            if (i + 4 > s.length()) throw new RuntimeException("Bad unicode escape");
                            out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                            break;
                        default: throw new RuntimeException("Bad escape \\" + e);
                    }
                } else {
                    out.append(c);
                }
            }
            throw new RuntimeException("Unterminated string");
        }

        private Number parseNumber() {
            int start = i;
            if (s.charAt(i) == '-') i++;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            boolean fp = false;
            if (i < s.length() && s.charAt(i) == '.') {
                fp = true; i++;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                fp = true; i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            }
            String t = s.substring(start, i);
            return fp ? (Number) Double.parseDouble(t) : (Number) Long.parseLong(t);
        }

        private List<Object> parseArray() {
            if (s.charAt(i) != '[') throw new RuntimeException("Expected '['");
            i++;
            skipWs();
            List<Object> out = new ArrayList<>();
            if (i < s.length() && s.charAt(i) == ']') { i++; return out; }
            while (true) {
                out.add(parseValue());
                skipWs();
                if (i >= s.length()) throw new RuntimeException("Unterminated array");
                char c = s.charAt(i);
                if (c == ',') { i++; skipWs(); continue; }
                if (c == ']') { i++; return out; }
                throw new RuntimeException("Expected ',' or ']' at pos " + i);
            }
        }

        private Map<String, Object> parseObject() {
            if (s.charAt(i) != '{') throw new RuntimeException("Expected '{'");
            i++;
            skipWs();
            Map<String, Object> out = new LinkedHashMap<>();
            if (i < s.length() && s.charAt(i) == '}') { i++; return out; }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                if (i >= s.length() || s.charAt(i) != ':') throw new RuntimeException("Expected ':' at pos " + i);
                i++;
                Object v = parseValue();
                out.put(key, v);
                skipWs();
                if (i >= s.length()) throw new RuntimeException("Unterminated object");
                char c = s.charAt(i);
                if (c == ',') { i++; continue; }
                if (c == '}') { i++; return out; }
                throw new RuntimeException("Expected ',' or '}' at pos " + i);
            }
        }
    }
}
