document.addEventListener('DOMContentLoaded', () => {
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const plaintextInput = document.getElementById('plaintext');
    const modeSelect = document.getElementById('mode');
    const resultDiv = document.getElementById('result');
    const statusDiv = document.getElementById('status');

    // Simple SHA-256 hash (for Merkle verification proxy)
    function sha256(str) {
        // Placeholder: Use crypto.subtle in prod
        return btoa(unescape(encodeURIComponent(str)));  // Mock hash
    }

    encryptBtn.addEventListener('click', async () => {
        const plaintext = plaintextInput.value;
        if (!plaintext) return;

        const mode = modeSelect.value;
        const url = mode === 'PQ' ? 'http://localhost:8080/encrypt/pq' : 'http://localhost:8080/encrypt/rsa';

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'text/plain', 'User-Id': 'demo' },
                body: plaintext
            });
            const data = await response.json();
            resultDiv.innerHTML = `
                <h3>Encryption Result:</h3>
                <p><strong>Ciphertext:</strong> ${data.ciphertext}</p>
                <p><strong>Encap Key:</strong> ${data.encapKey}</p>
                <p><strong>Merkle Root:</strong> ${data.merkleRoot}</p>
            `;
            statusDiv.textContent = 'Encrypted and stored successfully!';
        } catch (err) {
            statusDiv.textContent = 'Error: ' + err.message;
        }
    });

    decryptBtn.addEventListener('click', async () => {
        // For demo, reuse result from encrypt (in prod, input fields)
        const ciphertext = prompt('Enter Ciphertext:');
        const encapKey = prompt('Enter Encap Key:');
        const merkleRoot = prompt('Enter Merkle Root:');
        const mode = modeSelect.value;
        const originalHash = sha256(plaintextInput.value);

        if (!ciphertext || !encapKey || !merkleRoot) return;

        const body = `${ciphertext}|${encapKey}|${merkleRoot}|${mode}|${originalHash}`;

        try {
            const response = await fetch('http://localhost:8080/decrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'text/plain' },
                body: body
            });
            const data = await response.json();
            resultDiv.innerHTML = `<h3>Decryption Result:</h3><p><strong>Plaintext:</strong> ${data.plaintext}</p>`;
            statusDiv.textContent = 'Decrypted and verified successfully!';
        } catch (err) {
            statusDiv.textContent = 'Error: ' + err.message;
        }
    });
});