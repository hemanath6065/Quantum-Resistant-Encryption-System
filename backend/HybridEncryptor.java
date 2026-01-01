import java.util.List;
import java.util.Base64;

public class HybridEncryptor {
    private CryptoService cryptoService;

    public HybridEncryptor() throws Exception {
        this.cryptoService = new CryptoService();
    }

    // Encrypt with Merkle integrity (split data into blocks if large)
    public String[] encrypt(String plaintext, String mode) throws Exception {  // mode: "PQ" or "RSA"
        // Split into blocks for Merkle (simple: one block for demo)
        List<String> blocks = List.of(plaintext);
        MerkleTree tree = new MerkleTree(blocks);
        String merkleRoot = tree.getRoot();

        String[] encrypted;
        String encapKey;
        if ("PQ".equals(mode)) {
            encrypted = cryptoService.hybridEncryptPQ(plaintext);
            encapKey = encrypted[1];  // PQ encap
        } else {
            KeyPair pair = cryptoService.rsaKeyGen.generateKeyPair();  // Generate per session
            encrypted = cryptoService.hybridEncryptRSA(plaintext, pair);
            encapKey = encrypted[1];  // RSA encrypted key
            // Store private key temporarily (in prod, secure storage)
        }

        return new String[]{encrypted[0], encapKey, merkleRoot};
    }

    public String decrypt(String encryptedData, String encapKey, String merkleRoot, String mode, String originalHash) throws Exception {
        // Verify Merkle (using original hash as proxy for block)
        if (!new MerkleTree(List.of(originalHash)).getRoot().equals(merkleRoot)) {
            throw new Exception("Integrity check failed: Tampering detected!");
        }

        if ("PQ".equals(mode)) {
            return cryptoService.hybridDecryptPQ(encryptedData, encapKey);
        } else {
            // Assume private key retrieval (placeholder)
            KeyPair pair = cryptoService.rsaKeyGen.generateKeyPair();  // Mock
            return cryptoService.hybridDecryptRSA(encryptedData, encapKey, pair.getPrivate());
        }
    }
}