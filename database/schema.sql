-- Schema for Encrypted Data Storage
-- Uses SQLite for simplicity

CREATE TABLE IF NOT EXISTS encrypted_blobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,  -- Placeholder for user
    plaintext_hash TEXT NOT NULL,  -- SHA-256 of original plaintext
    encrypted_data BLOB NOT NULL,  -- AES-encrypted ciphertext
    merkle_root TEXT NOT NULL,     -- Base64-encoded Merkle root hash
    key_encap BLOB NOT NULL,       -- Encapsulated key (PQ or RSA)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast lookups
CREATE INDEX IF NOT EXISTS idx_user_hash ON encrypted_blobs(user_id, plaintext_hash);

-- Sample insert (for testing)
-- INSERT INTO encrypted_blobs (user_id, plaintext_hash, encrypted_data, merkle_root, key_encap)
-- VALUES ('test', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 
--         X'encrypted_hex_here', 'root_hash_base64', X'key_encap_hex');