// language: Java 21, file: docker/app/VulnApp.java
// Minimal HTTP server that decodes Base64 from multiple surfaces.
// Intentionally vulnerable to CVE-2026-114938 (Java4Shell).
//
// Surfaces exposed:
//   GET  /            — basic landing page
//   GET  /health      — healthcheck endpoint
//   GET  /api/data    — Base64 query param decode
//   POST /api/decode  — JSON body {"data":"<base64>"}
//   POST /saml/SSO    — form field SAMLRequest=<base64>
//   GET  /auth/...    — HTTP Basic Auth header decode
//
// Build & run (JDK 21, x86_64 AVX-512 host):
//   javac VulnApp.java
//   java -server -Xms256m -Xmx512m -XX:+UseG1GC VulnApp

import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.*;

public class VulnApp {

    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 128);
        ExecutorService pool = Executors.newFixedThreadPool(32);

        server.createContext("/",         new RootHandler());
        server.createContext("/health",   new HealthHandler());
        server.createContext("/api/",     new ApiHandler());
        server.createContext("/saml/",    new SamlHandler());
        server.createContext("/auth/",    new AuthHandler());
        server.createContext("/login",    new LoginHandler());
        server.createContext("/upload",   new UploadHandler());

        server.setExecutor(pool);
        server.start();

        System.out.println("[VulnApp] Listening on :" + PORT);
        System.out.println("[VulnApp] JVM: " + System.getProperty("java.version"));
        System.out.println("[VulnApp] Surfaces: /api/decode, /saml/SSO, /auth/, /login, /upload");
    }

    // ── Shared decode helper — hits the vulnerable intrinsic path ──────────────

    static String safeDecode(String b64Input) {
        try {
            // java.util.Base64.Decoder.decode() — the vulnerable method on JDK 17/21
            byte[] decoded = Base64.getDecoder().decode(b64Input.trim());
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Malformed input — log and return error (crash signal comes from JVM, not here)
            return "[decode error: " + e.getMessage() + "]";
        }
    }

    static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("Server", "VulnApp/1.0 (Java/" + System.getProperty("java.version") + ")");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    static String readBody(HttpExchange ex) throws IOException {
        try (InputStream is = ex.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // ── Handlers ───────────────────────────────────────────────────────────────

    static class RootHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String body = "{\"app\":\"Java4Shell Test Server\",\"cve\":\"CVE-2026-114938\","
                + "\"java\":\"" + System.getProperty("java.version") + "\","
                + "\"surfaces\":[\"/api/decode\",\"/saml/SSO\",\"/auth/\",\"/login\",\"/upload\"]}";
            respond(ex, 200, body);
        }
    }

    static class HealthHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            respond(ex, 200, "{\"status\":\"UP\"}");
        }
    }

    static class ApiHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String path = ex.getRequestURI().getPath();
            String query = ex.getRequestURI().getQuery();

            if (path.equals("/api/data") && query != null) {
                // GET /api/data?data=<base64>&format=base64
                String param = Arrays.stream(query.split("&"))
                    .filter(p -> p.startsWith("data="))
                    .map(p -> URLDecoder.decode(p.substring(5), StandardCharsets.UTF_8))
                    .findFirst().orElse("");
                String decoded = safeDecode(param);
                respond(ex, 200, "{\"input\":\"" + param.substring(0, Math.min(40, param.length())) + "\",\"decoded\":\"" + decoded.substring(0, Math.min(200, decoded.length())) + "\"}");
            } else if (path.equals("/api/decode")) {
                // POST /api/decode {"data":"<base64>"}
                String reqBody = readBody(ex);
                String data = "";
                // Naive JSON extract
                int idx = reqBody.indexOf("\"data\"");
                if (idx >= 0) {
                    int q1 = reqBody.indexOf('"', idx + 7);
                    int q2 = q1 >= 0 ? reqBody.indexOf('"', q1 + 1) : -1;
                    if (q1 >= 0 && q2 > q1) data = reqBody.substring(q1 + 1, q2);
                }
                String decoded = safeDecode(data);
                respond(ex, 200, "{\"result\":\"" + decoded.substring(0, Math.min(200, decoded.length())) + "\"}");
            } else {
                respond(ex, 404, "{\"error\":\"not found\"}");
            }
        }
    }

    static class SamlHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            // POST /saml/SSO  SAMLRequest=<base64>
            String reqBody = readBody(ex);
            String samlReq = "";
            for (String part : reqBody.split("&")) {
                if (part.startsWith("SAMLRequest=")) {
                    samlReq = URLDecoder.decode(part.substring(12), StandardCharsets.UTF_8);
                }
            }
            String decoded = samlReq.isEmpty() ? "" : safeDecode(samlReq);
            respond(ex, 200, "{\"saml_decoded_len\":" + decoded.length() + "}");
        }
    }

    static class AuthHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            // GET /auth/... — HTTP Basic Auth header
            String authHeader = ex.getRequestHeaders().getFirst("Authorization");
            if (authHeader != null && authHeader.startsWith("Basic ")) {
                String b64 = authHeader.substring(6).trim();
                String decoded = safeDecode(b64);
                // Simulate auth check (always fails — just decodes)
                respond(ex, 401, "{\"error\":\"Unauthorized\",\"decoded_len\":" + decoded.length() + "}");
            } else {
                ex.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"VulnApp\"");
                respond(ex, 401, "{\"error\":\"Authentication required\"}");
            }
        }
    }

    static class LoginHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            // POST /login  username=<base64>&password=x
            String reqBody = readBody(ex);
            String username = "";
            for (String part : reqBody.split("&")) {
                if (part.startsWith("username=")) {
                    username = URLDecoder.decode(part.substring(9), StandardCharsets.UTF_8);
                }
            }
            // The username goes through Base64 decode on some SSO integrations
            String decoded = username.isEmpty() ? "" : safeDecode(username);
            respond(ex, 401, "{\"error\":\"Invalid credentials\",\"user_len\":" + decoded.length() + "}");
        }
    }

    static class UploadHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            // POST /upload  multipart — read body and look for base64 content
            String reqBody = readBody(ex);
            // Naive: find any base64-looking block and decode it
            String decoded = "";
            for (String line : reqBody.split("\r?\n")) {
                line = line.trim();
                if (line.length() > 20 && line.matches("[A-Za-z0-9+/=]+")) {
                    decoded = safeDecode(line);
                    break;
                }
            }
            respond(ex, 200, "{\"upload\":\"ok\",\"decoded_len\":" + decoded.length() + "}");
        }
    }
}
