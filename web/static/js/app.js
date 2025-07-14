// --- DOM Elements ---
const authSection = document.getElementById('authSection');
const usernameInput = document.getElementById('usernameInput');
const bioInput = document.getElementById('bioInput');
const registerButton = document.getElementById('registerButton');
const loginButton = document.getElementById('loginButton');
const authMessage = document.getElementById('authMessage');

const userInfo = document.getElementById('userInfo');
const currentUsernameSpan = document.getElementById('currentUsername');
const logoutButton = document.getElementById('logoutButton');

const userListSection = document.getElementById('userListSection');
const userList = document.getElementById('userList');

const chatArea = document.getElementById('chatArea');
const chatPartnerName = document.getElementById('chatPartnerName');
const messagesDisplay = document.getElementById('messagesDisplay');
const messageInput = document.getElementById('messageInput');
const sendMessageButton = document.getElementById('sendMessageButton');
const attachFileButton = document.getElementById('attachFileButton');
const fileInput = document.getElementById('fileInput');

const modal = document.getElementById('modal');
const modalMessage = document.getElementById('modalMessage');
const modalOkButton = document.getElementById('modalOkButton');
const closeButton = document.querySelector('.modal .close-button');


// --- Global State Variables ---
let currentUserId = null;
let currentUsername = null;
let currentUserPrivateKey = null; // Stored as CryptoKey object
let currentUserPublicKey = null;  // Stored as CryptoKey object (exported as JWK for server)

let chatPartnerId = null;
let chatPartnerUsername = null;
let chatPartnerPublicKey = null; // Stored as CryptoKey object

let allUsers = []; // Cache of all registered users and their public keys

// --- WebSocket Variables ---
let websocket = null;
let reconnectAttempts = 0;
let maxReconnectAttempts = 5;
let reconnectDelay = 1000; // Start with 1 second
let typingTimer = null;
let isTyping = false;

// --- Utility Functions ---

/**
 * Displays a message in the auth section for a short duration.
 * @param {string} message - The message to display.
 * @param {string} type - 'success' or 'error' for styling.
 */
function showAuthMessage(message, type) {
    authMessage.textContent = message;
    authMessage.className = `message-box ${type}`;
    setTimeout(() => {
        authMessage.className = 'message-box'; // Hide after a delay
        authMessage.textContent = '';
    }, 3000);
}

/**
 * Displays a modal message to the user.
 * @param {string} message - The message to display in the modal.
 */
function showModal(message) {
    modalMessage.textContent = message;
    modal.style.display = 'flex'; // Show the modal
}

/**
 * Hides the modal.
 */
function hideModal() {
    modal.style.display = 'none';
}

/**
 * Converts a Base64 string to an ArrayBuffer.
 * @param {string} base64 - The Base64 string.
 * @returns {ArrayBuffer}
 */
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Converts an ArrayBuffer to a Base64 string.
 * @param {ArrayBuffer} buffer - The ArrayBuffer.
 * @returns {string}
 */
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// --- WebCrypto API Functions for Encryption ---

/**
 * Generates a new ECDH P-384 key pair using WebCrypto API.
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
async function generateECDHKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-384",
        },
        true, // extractable
        ["deriveKey", "deriveBits"]
    );
}

/**
 * Derives a shared secret key using the local private key and remote public key.
 * The derived key is suitable for AES-GCM.
 * @param {CryptoKey} privateKey - The local ECDH private key.
 * @param {CryptoKey} remotePublicKey - The remote ECDH public key.
 * @returns {Promise<CryptoKey>} - The derived symmetric key for AES-GCM.
 */
async function deriveSharedSecret(privateKey, remotePublicKey) {
    const sharedSecret = await window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: remotePublicKey,
        },
        privateKey,
        {
            name: "AES-GCM",
            length: 256, // AES-256
        },
        true, // extractable
        ["encrypt", "decrypt"]
    );
    return sharedSecret;
}

/**
 * Encrypts data using AES-GCM.
 * @param {CryptoKey} key - The AES-GCM key.
 * @param {ArrayBuffer} plaintext - The data to encrypt.
 * @returns {Promise<{ciphertext: ArrayBuffer, iv: ArrayBuffer}>}
 */
async function encryptAESGCM(key, plaintext) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12-byte IV for AES-GCM
    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        plaintext
    );
    return { ciphertext: ciphertext, iv: iv.buffer };
}

/**
 * Decrypts data using AES-GCM.
 * @param {CryptoKey} key - The AES-GCM key.
 * @param {ArrayBuffer} ciphertext - The encrypted data.
 * @param {ArrayBuffer} iv - The Initialization Vector.
 * @returns {Promise<ArrayBuffer>} - The decrypted plaintext.
 */
async function decryptAESGCM(key, ciphertext, iv) {
    try {
        const plaintext = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: new Uint8Array(iv),
            },
            key,
            ciphertext
        );
        return plaintext;
    } catch (e) {
        console.error("Decryption failed:", e);
        showModal("Decryption failed. This message might be corrupted or encrypted with a different key.");
        return null;
    }
}

// --- WebSocket Functions ---

/**
 * Connects to the websocket server
 */
function connectWebSocket() {
    if (!currentUserId || !currentUsername) {
        console.log('Cannot connect websocket: user not logged in');
        return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws?userId=${currentUserId}&username=${encodeURIComponent(currentUsername)}`;
    
    websocket = new WebSocket(wsUrl);

    websocket.onopen = function(event) {
        console.log('WebSocket connected');
        reconnectAttempts = 0;
        reconnectDelay = 1000;
        
        // Send heartbeat every 30 seconds
        setInterval(() => {
            if (websocket && websocket.readyState === WebSocket.OPEN) {
                sendWebSocketMessage('heartbeat', { timestamp: new Date().toISOString() });
            }
        }, 30000);
    };

    websocket.onmessage = function(event) {
        try {
            const message = JSON.parse(event.data);
            handleWebSocketMessage(message);
        } catch (error) {
            console.error('Error parsing websocket message:', error);
        }
    };

    websocket.onclose = function(event) {
        console.log('WebSocket disconnected:', event.code, event.reason);
        websocket = null;
        
        // Attempt to reconnect if not a normal closure
        if (event.code !== 1000 && reconnectAttempts < maxReconnectAttempts) {
            setTimeout(() => {
                reconnectAttempts++;
                reconnectDelay *= 2; // Exponential backoff
                console.log(`Attempting to reconnect (${reconnectAttempts}/${maxReconnectAttempts})...`);
                connectWebSocket();
            }, reconnectDelay);
        }
    };

    websocket.onerror = function(error) {
        console.error('WebSocket error:', error);
    };
}

/**
 * Disconnects from the websocket server
 */
function disconnectWebSocket() {
    if (websocket) {
        websocket.close(1000, 'User logout');
        websocket = null;
    }
}

/**
 * Sends a message through the websocket
 */
function sendWebSocketMessage(type, data) {
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        const message = {
            type: type,
            data: data,
            timestamp: new Date().toISOString()
        };
        websocket.send(JSON.stringify(message));
    }
}

/**
 * Handles incoming websocket messages
 */
async function handleWebSocketMessage(message) {
    switch (message.type) {
        case 'chat':
            await handleIncomingChatMessage(message.data);
            break;
        case 'typing_start':
            handleTypingStart(message.data);
            break;
        case 'typing_stop':
            handleTypingStop(message.data);
            break;
        case 'user_online':
            handleUserOnline(message.data);
            break;
        case 'user_offline':
            handleUserOffline(message.data);
            break;
        case 'file_upload':
            handleFileUploadNotification(message.data);
            break;
        case 'heartbeat':
            // Heartbeat response - no action needed
            break;
        case 'error':
            console.error('WebSocket error:', message.data.message);
            showModal(`WebSocket error: ${message.data.message}`);
            break;
        default:
            console.log('Unknown websocket message type:', message.type);
    }
}

/**
 * Handles incoming chat messages via websocket
 */
async function handleIncomingChatMessage(chatData) {
    // Only process if we're currently chatting with this user
    if (chatData.senderId === chatPartnerId || chatData.receiverId === currentUserId) {
        await fetchAndDisplayMessages();
    }
}

/**
 * Handles typing start indicator
 */
function handleTypingStart(typingData) {
    if (typingData.userId === chatPartnerId) {
        showTypingIndicator(typingData.username);
    }
}

/**
 * Handles typing stop indicator
 */
function handleTypingStop(typingData) {
    if (typingData.userId === chatPartnerId) {
        hideTypingIndicator();
    }
}

/**
 * Handles user coming online
 */
function handleUserOnline(presenceData) {
    updateUserPresenceInList(presenceData.userId, true);
}

/**
 * Handles user going offline
 */
function handleUserOffline(presenceData) {
    updateUserPresenceInList(presenceData.userId, false);
}

/**
 * Handles file upload notifications
 */
function handleFileUploadNotification(fileData) {
    if (fileData.receiverId === currentUserId) {
        // Refresh messages to show the new file
        if (chatPartnerId === fileData.senderId) {
            fetchAndDisplayMessages();
        }
    }
}

/**
 * Shows typing indicator in the chat
 */
function showTypingIndicator(username) {
    hideTypingIndicator(); // Remove any existing indicator
    
    const typingDiv = document.createElement('div');
    typingDiv.id = 'typing-indicator';
    typingDiv.className = 'typing-indicator';
    typingDiv.innerHTML = `<span>${username} is typing...</span>`;
    
    messagesDisplay.appendChild(typingDiv);
    messagesDisplay.scrollTop = messagesDisplay.scrollHeight;
}

/**
 * Hides typing indicator
 */
function hideTypingIndicator() {
    const existingIndicator = document.getElementById('typing-indicator');
    if (existingIndicator) {
        existingIndicator.remove();
    }
}

/**
 * Updates user presence status in the user list
 */
function updateUserPresenceInList(userId, isOnline) {
    const userItem = userList.querySelector(`[data-user-id="${userId}"]`);
    if (userItem) {
        if (isOnline) {
            userItem.classList.add('online');
            userItem.classList.remove('offline');
        } else {
            userItem.classList.add('offline');
            userItem.classList.remove('online');
        }
    }
}

/**
 * Sends typing start notification
 */
function sendTypingStart() {
    if (chatPartnerId && !isTyping) {
        isTyping = true;
        sendWebSocketMessage('typing_start', {
            chatPartnerId: chatPartnerId
        });
    }
}

/**
 * Sends typing stop notification
 */
function sendTypingStop() {
    if (chatPartnerId && isTyping) {
        isTyping = false;
        sendWebSocketMessage('typing_stop', {
            chatPartnerId: chatPartnerId
        });
    }
}

// --- Authentication and User Management ---

/**
 * Handles user registration.
 */
async function handleRegister() {
    const username = usernameInput.value.trim();
    const bio = bioInput.value.trim();

    if (!username) {
        showAuthMessage("Username cannot be empty.", "error");
        return;
    }

    // Generate ECDH key pair for the new user
    const keyPair = await generateECDHKeyPair();
    currentUserPrivateKey = keyPair.privateKey;
    currentUserPublicKey = keyPair.publicKey;

    // Export public key to JWK format to send to server
    const exportedPublicKey = await window.crypto.subtle.exportKey(
        "jwk",
        currentUserPublicKey
    );

    // Convert JWK to a compact byte array for server storage (only 'x' and 'y' for P-384)
    // This is a simplification. A more robust solution would handle full JWK or specific curve point encoding.
    // For P-384, the public key is typically 96 bytes (48 for x, 48 for y).
    // The server-side Go `ecdh.P384().PublicKey()` expects a byte slice directly from `Export()` method.
    // Here, we'll send the raw 'x' and 'y' coordinates as concatenated bytes.
    // This requires careful handling on the Go side to re-import.
    // A simpler approach for interoperability might be to base64 encode the full JWK and decode on Go side.
    // For this example, let's assume the Go server expects the raw bytes from `publicKey.Bytes()`.
    // Since WebCrypto doesn't directly give raw bytes for P384, we export JWK and extract 'x' and 'y'.
    // Then we convert the base64url encoded 'x' and 'y' to ArrayBuffer and concatenate.
    const xBytes = base64ToArrayBuffer(exportedPublicKey.x.replace(/-/g, '+').replace(/_/g, '/'));
    const yBytes = base64ToArrayBuffer(exportedPublicKey.y.replace(/-/g, '+').replace(/_/g, '/'));
    const publicKeyBytes = new Uint8Array(xBytes.byteLength + yBytes.byteLength);
    publicKeyBytes.set(new Uint8Array(xBytes), 0);
    publicKeyBytes.set(new Uint8Array(yBytes), xBytes.byteLength);


    try {
        const response = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username,
                bio: bio,
                publicKey: Array.from(publicKeyBytes) // Convert Uint8Array to regular array for JSON
            })
        });

        const data = await response.json();
        if (response.ok) {
            showAuthMessage(data.message, "success");
            // Store user info in localStorage
            localStorage.setItem('currentUserId', data.userId);
            localStorage.setItem('currentUsername', data.username);
            // Store private key (JWK format) securely in localStorage
            const exportedPrivateKey = await window.crypto.subtle.exportKey("jwk", currentUserPrivateKey);
            localStorage.setItem('currentUserPrivateKey', JSON.stringify(exportedPrivateKey));
            localStorage.setItem('currentUserPublicKey', JSON.stringify(exportedPublicKey)); // Store exported public key too

            currentUserId = data.userId;
            currentUsername = data.username;
            updateUIForLoggedInUser();
            await fetchAndDisplayUsers();
            
            // Connect to websocket after successful registration
            connectWebSocket();
        } else {
            showAuthMessage(data.message || "Registration failed.", "error");
        }
    } catch (error) {
        console.error('Registration error:', error);
        showAuthMessage("Network error or server unavailable.", "error");
    }
}

/**
 * Handles user login.
 */
async function handleLogin() {
    const username = usernameInput.value.trim();
    if (!username) {
        showAuthMessage("Username cannot be empty.", "error");
        return;
    }

    // Try to load private key from localStorage
    const storedPrivateKeyJWK = localStorage.getItem('currentUserPrivateKey');
    const storedPublicKeyJWK = localStorage.getItem('currentUserPublicKey');

    if (!storedPrivateKeyJWK || !storedPublicKeyJWK) {
        showAuthMessage("No local key found. Please register first.", "error");
        return;
    }

    try {
        currentUserPrivateKey = await window.crypto.subtle.importKey(
            "jwk",
            JSON.parse(storedPrivateKeyJWK),
            { name: "ECDH", namedCurve: "P-384" },
            true, // extractable
            ["deriveKey", "deriveBits"]
        );
        currentUserPublicKey = await window.crypto.subtle.importKey(
            "jwk",
            JSON.parse(storedPublicKeyJWK),
            { name: "ECDH", namedCurve: "P-384" },
            true, // extractable
            [] // Public key only used for export/import, not deriveKey
        );

        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username })
        });

        const data = await response.json();
        if (response.ok) {
            // Verify that the public key returned by the server matches the one we have locally.
            // This is a crucial step to prevent key substitution attacks.
            const serverPublicKeyBase64 = data.publicKey;
            const localPublicKeyJWK = JSON.parse(storedPublicKeyJWK);
            const localPublicKeyBase64 = arrayBufferToBase64(base64ToArrayBuffer(localPublicKeyJWK.x.replace(/-/g, '+').replace(/_/g, '/'))).slice(0, 48) + arrayBufferToBase64(base64ToArrayBuffer(localPublicKeyJWK.y.replace(/-/g, '+').replace(/_/g, '/'))).slice(0, 48); // Simplified check, need to be precise

            // A more robust check: export both to JWK and compare stringified versions
            const exportedLocalPublicKeyJWK = await window.crypto.subtle.exportKey("jwk", currentUserPublicKey);
            const serverPublicKeyBytes = base64ToArrayBuffer(serverPublicKeyBase64);

            // Re-import server's public key from raw bytes into CryptoKey object
            // This requires the Go server to provide the public key in a format importable by WebCrypto.
            // Assuming the Go server sends the raw concatenated x and y bytes:
            const serverXBytes = serverPublicKeyBytes.slice(0, serverPublicKeyBytes.byteLength / 2);
            const serverYBytes = serverPublicKeyBytes.slice(serverPublicKeyBytes.byteLength / 2);

            const importedServerPublicKey = await window.crypto.subtle.importKey(
                "jwk",
                {
                    kty: "EC",
                    crv: "P-384",
                    x: arrayBufferToBase64(serverXBytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''), // Base64url encode
                    y: arrayBufferToBase64(serverYBytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''), // Base64url encode
                    ext: true,
                    key_ops: [],
                },
                { name: "ECDH", namedCurve: "P-384" },
                true, // extractable
                []
            );

            const exportedImportedServerPublicKeyJWK = await window.crypto.subtle.exportKey("jwk", importedServerPublicKey);

            // Compare the 'x' and 'y' components of the JWKs
            if (exportedLocalPublicKeyJWK.x !== exportedImportedServerPublicKeyJWK.x ||
                exportedLocalPublicKeyJWK.y !== exportedImportedServerPublicKeyJWK.y) {
                showModal("Security Alert: Public key mismatch! Your local key does not match the one stored on the server for this username. This could indicate a security issue. Please re-register or check your username.");
                console.error("Public key mismatch! Local:", exportedLocalPublicKeyJWK, "Server:", exportedImportedServerPublicKeyJWK);
                // Clear local keys to prevent further use with mismatched identity
                localStorage.removeItem('currentUserPrivateKey');
                localStorage.removeItem('currentUserPublicKey');
                currentUserId = null;
                currentUsername = null;
                currentUserPrivateKey = null;
                currentUserPublicKey = null;
                updateUIForLoggedOutUser();
                return;
            }


            showAuthMessage(data.message, "success");
            localStorage.setItem('currentUserId', data.userId);
            localStorage.setItem('currentUsername', data.username);
            currentUserId = data.userId;
            currentUsername = data.username;
            updateUIForLoggedInUser();
            await fetchAndDisplayUsers();
            
            // Connect to websocket after successful login
            connectWebSocket();
        } else {
            showAuthMessage(data.message || "Login failed.", "error");
        }
    } catch (error) {
        console.error('Login error:', error);
        showAuthMessage("Network error or invalid local key. Please try registering.", "error");
    }
}

/**
 * Handles user logout.
 */
function handleLogout() {
    // Disconnect websocket before clearing user data
    disconnectWebSocket();
    
    localStorage.removeItem('currentUserId');
    localStorage.removeItem('currentUsername');
    localStorage.removeItem('currentUserPrivateKey');
    localStorage.removeItem('currentUserPublicKey');
    currentUserId = null;
    currentUsername = null;
    currentUserPrivateKey = null;
    currentUserPublicKey = null;
    chatPartnerId = null;
    chatPartnerUsername = null;
    chatPartnerPublicKey = null;
    messagesDisplay.innerHTML = ''; // Clear messages
    chatPartnerName.textContent = 'Select a user to chat with';
    updateUIForLoggedOutUser();
    userList.innerHTML = ''; // Clear user list
    showModal("You have been logged out.");
}

/**
 * Updates the UI to reflect a logged-in user.
 */
function updateUIForLoggedInUser() {
    authSection.style.display = 'none';
    userInfo.style.display = 'block';
    userListSection.style.display = 'block';
    chatArea.style.display = 'flex';
    currentUsernameSpan.textContent = currentUsername;
}

/**
 * Updates the UI to reflect a logged-out user.
 */
function updateUIForLoggedOutUser() {
    authSection.style.display = 'block';
    userInfo.style.display = 'none';
    userListSection.style.display = 'none';
    chatArea.style.display = 'none';
}

/**
 * Fetches all registered users from the server and displays them.
 */
async function fetchAndDisplayUsers() {
    try {
        const response = await fetch('/api/users');
        const users = await response.json();
        allUsers = users; // Cache all users

        userList.innerHTML = ''; // Clear existing list
        users.forEach(user => {
            if (user.id === currentUserId) return; // Don't list self

            const listItem = document.createElement('li');
            listItem.className = 'user-list-item';
            listItem.textContent = user.username;
            listItem.dataset.userId = user.id;
            listItem.dataset.username = user.username;
            listItem.dataset.publicKey = user.publicKey; // Base64 encoded public key

            listItem.addEventListener('click', async () => {
                // Remove active class from previous partner
                const currentActive = userList.querySelector('.user-list-item.active');
                if (currentActive) {
                    currentActive.classList.remove('active');
                }
                // Add active class to clicked partner
                listItem.classList.add('active');

                chatPartnerId = user.id;
                chatPartnerUsername = user.username;
                chatPartnerName.textContent = `Chatting with ${chatPartnerUsername}`;

                // Import chat partner's public key
                const serverPublicKeyBytes = base64ToArrayBuffer(user.publicKey);
                const serverXBytes = serverPublicKeyBytes.slice(0, serverPublicKeyBytes.byteLength / 2);
                const serverYBytes = serverPublicKeyBytes.slice(serverPublicKeyBytes.byteLength / 2);

                chatPartnerPublicKey = await window.crypto.subtle.importKey(
                    "jwk",
                    {
                        kty: "EC",
                        crv: "P-384",
                        x: arrayBufferToBase64(serverXBytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
                        y: arrayBufferToBase64(serverYBytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
                        ext: true,
                        key_ops: [],
                    },
                    { name: "ECDH", namedCurve: "P-384" },
                    true, // extractable
                    []
                );

                await fetchAndDisplayMessages();
            });
            userList.appendChild(listItem);
        });
    } catch (error) {
        console.error('Failed to fetch users:', error);
        showModal("Failed to load user list. Please try again later.");
    }
}

// --- Chat and File Sharing ---

/**
 * Fetches and displays messages between the current user and the chat partner.
 */
async function fetchAndDisplayMessages() {
    if (!currentUserId || !chatPartnerId || !currentUserPrivateKey || !chatPartnerPublicKey) {
        messagesDisplay.innerHTML = '<p class="message-info">Select a user to start chatting.</p>';
        return;
    }

    messagesDisplay.innerHTML = '<p class="message-info">Loading messages...</p>';

    try {
        const response = await fetch(`/api/messages?senderId=${currentUserId}&receiverId=${chatPartnerId}`);

        // Check if the response was successful before parsing JSON
        if (!response.ok) {
            const errorText = await response.text(); // Get raw error text
            console.error(`Server error fetching messages: ${response.status} - ${errorText}`);
            showModal("Failed to load messages due to server error.");
            return;
        }

        const messages = await response.json();

        // Explicitly check if messages is an array to prevent TypeError
        if (!Array.isArray(messages)) {
            console.error("Received non-array response for messages:", messages);
            showModal("Invalid message data received from server.");
            return;
        }

        messagesDisplay.innerHTML = ''; // Clear loading message

        // Derive shared secret for decryption
        const sharedSecretKey = await deriveSharedSecret(currentUserPrivateKey, chatPartnerPublicKey);

        for (const msg of messages) {
            const encryptedContent = base64ToArrayBuffer(msg.encryptedContent);
            const iv = base64ToArrayBuffer(msg.iv);

            const decryptedContentBuffer = await decryptAESGCM(sharedSecretKey, encryptedContent, iv);
            let decryptedContent = '';
            if (decryptedContentBuffer) {
                decryptedContent = new TextDecoder().decode(decryptedContentBuffer);
            } else {
                decryptedContent = '[Decryption Failed]';
            }


            const isSent = msg.senderId === currentUserId;
            const senderUsername = isSent ? currentUsername : chatPartnerUsername;

            const messageBubble = document.createElement('div');
            messageBubble.className = `message-bubble ${isSent ? 'sent' : 'received'}`;

            const senderNameSpan = document.createElement('span');
            senderNameSpan.className = 'sender-name';
            senderNameSpan.textContent = senderUsername;
            messageBubble.appendChild(senderNameSpan);

            const contentP = document.createElement('p');
            // Check if it's a file link
            if (decryptedContent.startsWith('FILE_ID:')) {
                const fileId = decryptedContent.split(':')[1];
                const originalFilename = decryptedContent.split(':')[2]; // Assuming format FILE_ID:ID:FILENAME
                const fileLink = document.createElement('a');
                fileLink.href = '#'; // Prevent actual navigation
                fileLink.textContent = `📎 ${originalFilename}`;
                fileLink.className = 'file-link';
                fileLink.onclick = (e) => {
                    e.preventDefault(); // Prevent default link behavior
                    downloadFile(fileId, originalFilename);
                };
                contentP.appendChild(fileLink);
            } else {
                contentP.textContent = decryptedContent;
            }
            messageBubble.appendChild(contentP);

            const timestampSpan = document.createElement('span');
            timestampSpan.className = 'timestamp';
            timestampSpan.textContent = new Date(msg.timestamp).toLocaleString();
            messageBubble.appendChild(timestampSpan);

            messagesDisplay.appendChild(messageBubble);
        }
        messagesDisplay.scrollTop = messagesDisplay.scrollHeight; // Scroll to bottom
    } catch (error) {
        console.error('Failed to fetch or decrypt messages:', error);
        showModal("Failed to load messages. Ensure both users have valid keys.");
    }
}

/**
 * Sends an encrypted message.
 */
async function sendMessage() {
    const messageText = messageInput.value.trim();
    if (!messageText || !currentUserId || !chatPartnerId || !currentUserPrivateKey || !chatPartnerPublicKey) {
        showModal("Please select a user and type a message.");
        return;
    }

    try {
        // Derive shared secret
        const sharedSecretKey = await deriveSharedSecret(currentUserPrivateKey, chatPartnerPublicKey);
        const plaintextBuffer = new TextEncoder().encode(messageText);

        // Encrypt message
        const { ciphertext, iv } = await encryptAESGCM(sharedSecretKey, plaintextBuffer);

        const response = await fetch('/api/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                senderId: currentUserId,
                receiverId: chatPartnerId,
                encryptedContent: Array.from(new Uint8Array(ciphertext)), // Convert ArrayBuffer to Array for JSON
                iv: Array.from(new Uint8Array(iv)) // Convert ArrayBuffer to Array for JSON
            })
        });

        if (response.ok) {
            messageInput.value = ''; // Clear input
            await fetchAndDisplayMessages(); // Refresh messages
        } else {
            const errorData = await response.json();
            showModal(`Failed to send message: ${errorData.message || response.statusText}`);
        }
    } catch (error) {
        console.error('Error sending message:', error);
        showModal("Failed to send message due to encryption or network error.");
    }
}

/**
 * Uploads an encrypted file.
 * @param {File} file - The file to upload.
 */
async function uploadFile(file) {
    if (!file || !currentUserId || !chatPartnerId || !currentUserPrivateKey || !chatPartnerPublicKey) {
        showModal("Please select a user and a file to upload.");
        return;
    }

    try {
        // Derive shared secret
        const sharedSecretKey = await deriveSharedSecret(currentUserPrivateKey, chatPartnerPublicKey);

        // Read file content as ArrayBuffer
        const fileReader = new FileReader();
        fileReader.readAsArrayBuffer(file);

        fileReader.onload = async () => {
            const fileBuffer = fileReader.result; // ArrayBuffer of file content

            // Encrypt file content
            const { ciphertext, iv } = await encryptAESGCM(sharedSecretKey, fileBuffer);

            const formData = new FormData();
            formData.append('senderId', currentUserId);
            formData.append('receiverId', chatPartnerId);
            formData.append('originalFilename', file.name);
            formData.append('iv', arrayBufferToBase64(iv)); // Send IV as base64 string
            formData.append('encryptedFile', new Blob([ciphertext]), file.name); // Send encrypted blob

            const response = await fetch('/api/file/upload', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                const data = await response.json();
                showModal(`File "${data.filename}" uploaded successfully!`);
                // Send a chat message indicating the file upload
                const fileLinkMessage = `FILE_ID:${data.fileId}:${data.filename}`;
                messageInput.value = fileLinkMessage; // Set the message input to the file link
                await sendMessage(); // Send this "special" message
                fileInput.value = ''; // Clear file input
            } else {
                const errorData = await response.json();
                showModal(`Failed to upload file: ${errorData.message || response.statusText}`);
            }
        };

        fileReader.onerror = (error) => {
            console.error('Error reading file:', error);
            showModal("Failed to read file for upload.");
        };

    } catch (error) {
        console.error('Error uploading file:', error);
        showModal("Failed to upload file due to encryption or network error.");
    }
}

/**
 * Downloads and decrypts a file.
 * @param {number} fileId - The ID of the file to download.
 * @param {string} originalFilename - The original filename for saving.
 */
async function downloadFile(fileId, originalFilename) {
    if (!currentUserId || !chatPartnerId || !currentUserPrivateKey || !chatPartnerPublicKey) {
        showModal("You must be logged in and have a chat partner selected to download files.");
        return;
    }

    try {
        const response = await fetch(`/api/file/download?fileId=${fileId}`);
        const data = await response.json();

        if (!response.ok) {
            showModal(`Failed to download file: ${data.message || response.statusText}`);
            return;
        }

        const encryptedFileContent = base64ToArrayBuffer(data.encryptedFileContent);
        const iv = base64ToArrayBuffer(data.iv);

        // Derive shared secret
        const sharedSecretKey = await deriveSharedSecret(currentUserPrivateKey, chatPartnerPublicKey);

        // Decrypt file content
        const decryptedContentBuffer = await decryptAESGCM(sharedSecretKey, encryptedFileContent, iv);

        if (decryptedContentBuffer) {
            // Create a Blob from the decrypted content
            const blob = new Blob([decryptedContentBuffer], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);

            // Create a temporary link and click it to trigger download
            const a = document.createElement('a');
            a.href = url;
            a.download = originalFilename; // Use the original filename
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url); // Clean up the object URL

            showModal(`File "${originalFilename}" downloaded and decrypted successfully!`);
        } else {
            showModal("Failed to decrypt file content.");
        }

    } catch (error) {
        console.error('Error downloading file:', error);
        showModal("Failed to download file due to encryption or network error.");
    }
}


// --- Event Listeners ---
registerButton.addEventListener('click', handleRegister);
loginButton.addEventListener('click', handleLogin);
logoutButton.addEventListener('click', handleLogout);
sendMessageButton.addEventListener('click', sendMessage);

// Add typing indicators
messageInput.addEventListener('input', () => {
    if (messageInput.value.trim()) {
        sendTypingStart();
        
        // Clear existing timer and set new one
        clearTimeout(typingTimer);
        typingTimer = setTimeout(() => {
            sendTypingStop();
        }, 2000); // Stop typing indicator after 2 seconds of no input
    } else {
        sendTypingStop();
    }
});

messageInput.addEventListener('keypress', (event) => {
    if (event.key === 'Enter') {
        event.preventDefault();
        sendMessage();
        sendTypingStop(); // Stop typing when message is sent
    }
});

attachFileButton.addEventListener('click', () => fileInput.click()); // Trigger file input click
fileInput.addEventListener('change', (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
        showModal(`Uploading "${selectedFile.name}"...`);
        uploadFile(selectedFile);
    }
});

modalOkButton.addEventListener('click', hideModal);
closeButton.addEventListener('click', hideModal);
window.addEventListener('click', (event) => {
    if (event.target === modal) {
        hideModal();
    }
});


// --- Initialization ---
document.addEventListener('DOMContentLoaded', async () => {
    // Check if user is already logged in (based on localStorage)
    currentUserId = parseInt(localStorage.getItem('currentUserId'));
    currentUsername = localStorage.getItem('currentUsername');
    const storedPrivateKeyJWK = localStorage.getItem('currentUserPrivateKey');
    const storedPublicKeyJWK = localStorage.getItem('currentUserPublicKey');

    if (currentUserId && currentUsername && storedPrivateKeyJWK && storedPublicKeyJWK) {
        try {
            currentUserPrivateKey = await window.crypto.subtle.importKey(
                "jwk",
                JSON.parse(storedPrivateKeyJWK),
                { name: "ECDH", namedCurve: "P-384" },
                true, // extractable
                ["deriveKey", "deriveBits"]
            );
            currentUserPublicKey = await window.crypto.subtle.importKey(
                "jwk",
                JSON.parse(storedPublicKeyJWK),
                { name: "ECDH", namedCurve: "P-384" },
                true, // extractable
                []
            );
            updateUIForLoggedInUser();
            await fetchAndDisplayUsers();
            
            // Connect to websocket if user is already logged in
            connectWebSocket();
        } catch (error) {
            console.error("Failed to load local keys:", error);
            showModal("Failed to load local encryption keys. Please login or register again.");
            handleLogout(); // Force logout if keys are corrupted
        }
    } else {
        updateUIForLoggedOutUser();
    }
});

// WebSocket-based real-time messaging has replaced polling
// Messages are now updated in real-time via websocket events
