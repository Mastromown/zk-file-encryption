// Header format identifier: "ZKFD" (4 bytes)
const HEADER_MAGIC = new Uint8Array([0x5A, 0x4B, 0x46, 0x44]);
const PBKDF2_ITERATIONS = 200000;
const SALT_BYTE_LENGTH = 16;
const IV_BYTE_LENGTH = 12;

const fileInput = document.getElementById('fileInput');
const fileNameDisplay = document.getElementById('fileName');
const passwordInput = document.getElementById('passwordInput');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const statusDiv = document.getElementById('status');

fileInput.addEventListener('change', () => {
if (fileInput.files.length > 0) {
fileNameDisplay.textContent = fileInput.files[0].name;
} else {
fileNameDisplay.textContent = 'Drag & drop or click to browse';
}
});

function showStatus(message, type = 'info') {
statusDiv.textContent = message;
statusDiv.className = `status-msg ${type}`;
}

function clearStatus() {
statusDiv.className = 'status-msg hidden';
statusDiv.textContent = '';
}

async function deriveKey(password, salt) {
const enc = new TextEncoder();
const passwordKey = await window.crypto.subtle.importKey(
'raw',
enc.encode(password),
'PBKDF2',
false,
['deriveKey']
);

return window.crypto.subtle.deriveKey(
{
name: 'PBKDF2',
salt: salt,
iterations: PBKDF2_ITERATIONS,
hash: 'SHA-256'
},
passwordKey,
{ name: 'AES-GCM', length: 256 },
false,
['encrypt', 'decrypt']
);
}

// Encrypt File
encryptBtn.addEventListener('click', async () => {
const file = fileInput.files[0];
const password = passwordInput.value;

if (!file) return showStatus('Please select a file to encrypt.', 'error');
if (!password) return showStatus('Please enter a passphrase.', 'error');

try {
showStatus('Encrypting file... Please wait.', 'info');
setLoading(true);

const salt = window.crypto.getRandomValues(new Uint8Array(SALT_BYTE_LENGTH));
const iv = window.crypto.getRandomValues(new Uint8Array(IV_BYTE_LENGTH));
const key = await deriveKey(password, salt);

const fileBuffer = await file.arrayBuffer();

// Preserve original filename inside ciphertext payload as JSON
const payload = JSON.stringify({
filename: file.name,
data: Array.from(new Uint8Array(fileBuffer))
});

const encPayload = new TextEncoder().encode(payload);
const encryptedData = await window.crypto.subtle.encrypt(
{ name: 'AES-GCM', iv: iv },
key,
encPayload
);

// Combine: [MAGIC (4b)] [SALT (16b)] [IV (12b)] [CIPHERTEXT]
const finalBuffer = new Uint8Array(
HEADER_MAGIC.length + salt.length + iv.length + encryptedData.byteLength
);

finalBuffer.set(HEADER_MAGIC, 0);
finalBuffer.set(salt, HEADER_MAGIC.length);
finalBuffer.set(iv, HEADER_MAGIC.length + salt.length);
finalBuffer.set(new Uint8Array(encryptedData), HEADER_MAGIC.length + salt.length + iv.length);

const blob = new Blob([finalBuffer], { type: 'application/octet-stream' });
downloadBlob(blob, `${file.name}.enc`);

showStatus('Encryption successful! Downloading encrypted file.', 'success');
} catch (err) {
console.error(err);
showStatus('Encryption failed. See console for details.', 'error');
} finally {
setLoading(false);
}
});

// Decrypt File
decryptBtn.addEventListener('click', async () => {
const file = fileInput.files[0];
const password = passwordInput.value;

if (!file) return showStatus('Please select an encrypted (.enc) file.', 'error');
if (!password) return showStatus('Please enter the passphrase.', 'error');

try {
showStatus('Decrypting file... Please wait.', 'info');
setLoading(true);

const buffer = new Uint8Array(await file.arrayBuffer());

const minLength = HEADER_MAGIC.length + SALT_BYTE_LENGTH + IV_BYTE_LENGTH;
if (buffer.length < minLength) {
throw new Error('File is too short to be a valid encrypted payload.');
}

// Verify magic header
for (let i = 0; i < HEADER_MAGIC.length; i++) {
if (buffer[i] !== HEADER_MAGIC[i]) {
throw new Error('Invalid file format or header.');
}
}

const salt = buffer.subarray(HEADER_MAGIC.length, HEADER_MAGIC.length + SALT_BYTE_LENGTH);
const iv = buffer.subarray(
HEADER_MAGIC.length + SALT_BYTE_LENGTH,
HEADER_MAGIC.length + SALT_BYTE_LENGTH + IV_BYTE_LENGTH
);
const ciphertext = buffer.subarray(HEADER_MAGIC.length + SALT_BYTE_LENGTH + IV_BYTE_LENGTH);

const key = await deriveKey(password, salt);

const decryptedData = await window.crypto.subtle.decrypt(
{ name: 'AES-GCM', iv: iv },
key,
ciphertext
);

const decodedPayload = JSON.parse(new TextDecoder().decode(decryptedData));
const restoredBytes = new Uint8Array(decodedPayload.data);

const blob = new Blob([restoredBytes]);
downloadBlob(blob, decodedPayload.filename || 'decrypted_file');

showStatus('Decryption successful! Restored file downloaded.', 'success');
} catch (err) {
console.error(err);
showStatus('Decryption failed. Incorrect password or corrupted file.', 'error');
} finally {
setLoading(false);
}
});

function downloadBlob(blob, filename) {
const url = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = filename;
document.body.appendChild(a);
a.click();
document.body.removeChild(a);
URL.revokeObjectURL(url);
}

function setLoading(isLoading) {
encryptBtn.disabled = isLoading;
decryptBtn.disabled = isLoading;
}
