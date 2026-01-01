import com.sun.net.httpserver.*;
import java.net.InetSocketAddress;
import java.io.*;
import java.util.concurrent.Executors;
import java.sql.*;

public class Server {
    private static final String DB_URL = "jdbc:sqlite:../database/encrypted_data.db";
    private HybridEncryptor encryptor;

    public Server() throws Exception {
        encryptor = new HybridEncryptor();
    }

    private void handleEncrypt(HttpExchange exchange, String mode) throws Exception {
        InputStreamReader isr = new InputStreamReader(exchange.getRequestBody());
        BufferedReader br = new BufferedReader(isr);
        String plaintext = br.readLine();
        String userId = exchange.getRequestHeaders().getFirst("User-Id");  // Mock header

        String[] result = encryptor.encrypt(plaintext, mode);
        String plaintextHash = Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(plaintext.getBytes()));

        // Store to DB
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            String sql = "INSERT INTO encrypted_blobs (user_id, plaintext_hash, encrypted_data, merkle_root, key_encap) VALUES (?, ?, ?, ?, ?)";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, userId != null ? userId : "anonymous");
            pstmt.setString(2, plaintextHash);
            pstmt.setBytes(3, Base64.getDecoder().decode(result[0]));
            pstmt.setString(4, result[2]);
            pstmt.setBytes(5, Base64.getDecoder().decode(result[1]));
            pstmt.executeUpdate();
        }

        String response = "{\"ciphertext\":\"" + result[0] + "\", \"encapKey\":\"" + result[1] + "\", \"merkleRoot\":\"" + result[2] + "\", \"id\":1}";
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    private void handleDecrypt(HttpExchange exchange) throws Exception {
        // Parse JSON body for ciphertext, encapKey, merkleRoot, mode, originalHash
        // For brevity, assume body is "ciphertext|encapKey|merkleRoot|mode|originalHash"
        InputStreamReader isr = new InputStreamReader(exchange.getRequestBody());
        BufferedReader br = new BufferedReader(isr);
        String[] parts = br.readLine().split("\\|");
        String decrypted = encryptor.decrypt(parts[0], parts[1], parts[2], parts[3], parts[4]);

        String response = "{\"plaintext\":\"" + decrypted + "\"}";
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    public static void main(String[] args) throws Exception {
        Server server = new Server();
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(8080), 0);
        httpServer.createContext("/encrypt/pq", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                server.handleEncrypt(exchange, "PQ");
            }
        });
        httpServer.createContext("/encrypt/rsa", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                server.handleEncrypt(exchange, "RSA");
            }
        });
        httpServer.createContext("/decrypt", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                server.handleDecrypt(exchange);
            }
        });
        httpServer.setExecutor(Executors.newSingleThreadExecutor());
        httpServer.start();
        System.out.println("Server started on port 8080");
    }
}