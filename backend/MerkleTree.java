import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class MerkleTree {
    private List<String> leaves;
    private List<String> nodes;
    private String root;

    public MerkleTree(List<String> dataBlocks) {
        this.leaves = new ArrayList<>();
        for (String block : dataBlocks) {
            leaves.add(hash(block));
        }
        buildTree();
    }

    private String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void buildTree() {
        nodes = new ArrayList<>(leaves);
        int numLeaves = leaves.size();
        while (numLeaves > 1) {
            List<String> newLevel = new ArrayList<>();
            for (int i = 0; i < numLeaves; i += 2) {
                String left = nodes.get(i);
                String right = (i + 1 < numLeaves) ? nodes.get(i + 1) : left;  // Duplicate if odd
                newLevel.add(hash(left + right));
            }
            nodes.addAll(newLevel);
            numLeaves = newLevel.size();
        }
        root = nodes.get(nodes.size() - 1);
    }

    public String getRoot() {
        return root;
    }

    public boolean verifyIntegrity(List<String> currentBlocks, String providedRoot) {
        MerkleTree tempTree = new MerkleTree(currentBlocks);
        return tempTree.getRoot().equals(providedRoot);
    }

    // Simple proof generation (path to leaf)
    public List<String> getProof(int leafIndex) {
        // Implementation omitted for brevity; in full, compute sibling path
        return new ArrayList<>();  // Placeholder
    }
}