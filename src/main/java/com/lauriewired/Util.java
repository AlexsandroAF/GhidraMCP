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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

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

    public static void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
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
