import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

// Simplified Lattice KEM (LWE-based; educational only, not secure for prod)
class LatticeKEM {
    private static final int N = 256;  // Polynomial degree
    private static final int Q = 3329; // Modulus
    private SecureRandom random = new SecureRandom();

    public byte[] encapsulate() {
        // Simplified: Generate random shared secret (in prod, use Kyber impl)
        byte[] shared = new byte[32];
        random.nextBytes(shared);
        return shared;
    }

    public byte[] decapsulate(byte[] encap) {
        // Mock decapsulate
        return Arrays.copyOf(encap, 32);
    }
}

public class CryptoService {
    private static final String AES_ALGO = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private KeyGenerator aesKeyGen;
    private KeyPairGenerator rsaKeyGen;
    private Cipher rsaCipher;
    private Cipher aesCipher;
    private LatticeKEM latticeKem;

    public CryptoService() throws Exception {
        aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(AES_KEY_SIZE);
        rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(2048);
        rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        aesCipher = Cipher.getInstance(AES_ALGO);
        latticeKem = new LatticeKEM();
    }

    // Hybrid: PQ KEM + AES
    public String[] hybridEncryptPQ(String plaintext) throws Exception {
        byte[] sharedSecret = latticeKem.encapsulate();
        SecretKey aesKey = new SecretKeySpec(sharedSecret, "AES");

        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] ciphertext = aesCipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] fullCipher = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, fullCipher, 0, iv.length);
        System.arraycopy(ciphertext, 0, fullCipher, iv.length, ciphertext.length);

        return new String[]{
            Base64.getEncoder().encodeToString(fullCipher),
            Base64.getEncoder().encodeToString(sharedSecret)  // Encapsulated key
        };
    }

    public String hybridDecryptPQ(String encrypted, String encapKey) throws Exception {
        byte[] fullCipher = Base64.getDecoder().decode(encrypted);
        byte[] iv = Arrays.copyOf(fullCipher, GCM_IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(fullCipher, GCM_IV_LENGTH, fullCipher.length);

        byte[] sharedSecret = latticeKem.decapsulate(Base64.getDecoder().decode(encapKey));
        SecretKey aesKey = new SecretKeySpec(sharedSecret, "AES");

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        byte[] plaintext = aesCipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    // RSA for compatibility
    public String[] hybridEncryptRSA(String plaintext, KeyPair keyPair) throws Exception {
        rsaCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encryptedKey = rsaCipher.doFinal(generateAesKey().getEncoded());

        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        SecretKey aesKey = new SecretKeySpec(encryptedKey, "AES");  // Mock derive
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] ciphertext = aesCipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] fullCipher = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, fullCipher, 0, iv.length);
        System.arraycopy(ciphertext, 0, fullCipher, iv.length, ciphertext.length);

        return new String[]{
            Base64.getEncoder().encodeToString(fullCipher),
            Base64.getEncoder().encodeToString(encryptedKey)
        };
    }

    public String hybridDecryptRSA(String encrypted, String encryptedKeyStr, PrivateKey privateKey) throws Exception {
        byte[] fullCipher = Base64.getDecoder().decode(encrypted);
        byte[] iv = Arrays.copyOf(fullCipher, GCM_IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(fullCipher, GCM_IV_LENGTH, fullCipher.length);

        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedKeyStr));
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        byte[] plaintext = aesCipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private SecretKey generateAesKey() throws Exception {
        return aesKeyGen.generateKey();
    }
}