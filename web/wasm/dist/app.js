// Secure Application - Loaded from WASM embedded assets
'use strict';

(function () {
    // Get auth config from parent loader (use window to avoid redeclaration)
    const authConfig = window.__AUTH_CONFIG__ || null;
    const securityToken = window.__SECURITY_TOKEN__ || null;

    let appInitialized = false;

    function initApp() {
        if (appInitialized) return;
        appInitialized = true;

        // Update user info
        const userIdEl = document.getElementById('userId');
        if (userIdEl && authConfig) {
            userIdEl.textContent = authConfig.userID || authConfig.deviceID || 'Authenticated';
        }

        // Setup button click handler
        const fetchBtn = document.getElementById('fetchBtn');
        if (fetchBtn) {
            fetchBtn.addEventListener('click', testSecureFetch);
        }

        // Setup user info button
        const userInfoBtn = document.getElementById('userInfoBtn');
        if (userInfoBtn) {
            userInfoBtn.addEventListener('click', testUserInfo);
        }

        // Setup upload button
        const uploadBtn = document.getElementById('uploadBtn');
        if (uploadBtn) {
            uploadBtn.addEventListener('click', testFileUpload);
        }

        // Setup list files button
        const listFilesBtn = document.getElementById('listFilesBtn');
        if (listFilesBtn) {
            listFilesBtn.addEventListener('click', testListFiles);
        }

        console.log('✅ App initialized with auth config:', authConfig ? 'present' : 'missing');
    }

    // Update user info on load
    document.addEventListener('DOMContentLoaded', function () {
        initApp();
    });

    // Also run immediately in case DOM is already ready
    if (document.readyState !== 'loading') {
        initApp();
    }

    async function testSecureFetch() {
        const output = document.getElementById('output');
        const fetchBtn = document.getElementById('fetchBtn');

        if (!output) return;

        output.textContent = '🔄 Initializing secure client...';
        if (fetchBtn) fetchBtn.disabled = true;

        try {
            if (!authConfig) {
                throw new Error('Auth config not available. Please log in again.');
            }

            console.log('Auth config:', authConfig);

            // Check if secureFetchInit is available (from WASM)
            if (typeof secureFetchInit !== 'function') {
                throw new Error('secureFetchInit not available. WASM may not be loaded correctly.');
            }

            output.textContent = '🔐 Setting up encrypted channel...';

            const baseURL = authConfig.baseURL && authConfig.baseURL !== ''
                ? authConfig.baseURL
                : window.location.origin;

            const initConfig = {
                baseURL: baseURL,
                deviceID: authConfig.deviceID,
                deviceSecret: authConfig.deviceSecret,
                gateSecrets: authConfig.gateSecrets,
                userToken: authConfig.userToken,
                capabilityToken: authConfig.capabilityToken,
                accessToken: authConfig.accessToken,
                refreshToken: authConfig.refreshToken,
                handshakePath: authConfig.handshakePath || '/handshake',
                autoHandshake: true
            };

            console.log('SecureFetch init config:', initConfig);

            // Initialize secure fetch with auth config
            await secureFetchInit(initConfig);

            output.textContent = '📡 Making secure API request...';

            // Make a secure fetch request
            const response = await secureFetch({
                endpoint: '/api/protected',
                method: 'GET',
                responseType: 'json'
            });

            output.textContent = '✅ Response received:\n\n' + JSON.stringify(response, null, 2);
            console.log('✅ Secure fetch successful:', response);

        } catch (error) {
            console.error('❌ Secure fetch error:', error);
            output.textContent = '❌ Error: ' + error.message;

            if (error.stack) {
                output.textContent += '\n\n📋 Stack:\n' + error.stack;
            }
        } finally {
            if (fetchBtn) fetchBtn.disabled = false;
        }
    }

    async function testUserInfo() {
        const output = document.getElementById('userOutput');
        const userInfoBtn = document.getElementById('userInfoBtn');
        const userName = document.getElementById('userName').value;

        if (!output) return;

        output.textContent = '🔄 Calling user info...';
        if (userInfoBtn) userInfoBtn.disabled = true;

        try {
            if (!authConfig) {
                throw new Error('Auth config not available.');
            }

            if (typeof secureFetchInit !== 'function') {
                throw new Error('secureFetchInit not available.');
            }

            const baseURL = authConfig.baseURL && authConfig.baseURL !== ''
                ? authConfig.baseURL
                : window.location.origin;

            await secureFetchInit({
                baseURL: baseURL,
                deviceID: authConfig.deviceID,
                deviceSecret: authConfig.deviceSecret,
                gateSecrets: authConfig.gateSecrets,
                userToken: authConfig.userToken,
                capabilityToken: authConfig.capabilityToken,
                accessToken: authConfig.accessToken,
                refreshToken: authConfig.refreshToken,
                handshakePath: authConfig.handshakePath || '/handshake',
                autoHandshake: true
            });

            const response = await secureFetch({
                endpoint: '/api/user/info',
                method: 'POST',
                body: { name: userName || 'Test User' },
                responseType: 'json'
            });

            output.textContent = '✅ Response:\n\n' + JSON.stringify(response, null, 2);
        } catch (error) {
            output.textContent = '❌ Error: ' + error.message;
        } finally {
            if (userInfoBtn) userInfoBtn.disabled = false;
        }
    }

    async function testFileUpload() {
        const output = document.getElementById('uploadOutput');
        const uploadBtn = document.getElementById('uploadBtn');
        const fileInput = document.getElementById('fileInput');

        if (!output || !fileInput) return;

        const file = fileInput.files[0];
        if (!file) {
            output.textContent = '❌ Please select a file first';
            return;
        }

        output.textContent = '🔄 Uploading file...';
        if (uploadBtn) uploadBtn.disabled = true;

        try {
            if (!authConfig) {
                throw new Error('Auth config not available.');
            }

            if (typeof secureFetchInit !== 'function') {
                throw new Error('secureFetchInit not available.');
            }

            const baseURL = authConfig.baseURL && authConfig.baseURL !== ''
                ? authConfig.baseURL
                : window.location.origin;

            await secureFetchInit({
                baseURL: baseURL,
                deviceID: authConfig.deviceID,
                deviceSecret: authConfig.deviceSecret,
                gateSecrets: authConfig.gateSecrets,
                userToken: authConfig.userToken,
                capabilityToken: authConfig.capabilityToken,
                accessToken: authConfig.accessToken,
                refreshToken: authConfig.refreshToken,
                handshakePath: authConfig.handshakePath || '/handshake',
                autoHandshake: true
            });

            const response = await secureFetch({
                endpoint: '/api/upload',
                method: 'POST',
                body: file,
                isFileUpload: true,
                filename: file.name,
                fieldName: 'file',
                contentType: file.type || 'application/octet-stream',
                responseType: 'json'
            });

            output.textContent = '✅ Upload successful:\n\n' + JSON.stringify(response, null, 2);
        } catch (error) {
            output.textContent = '❌ Error: ' + error.message;
        } finally {
            if (uploadBtn) uploadBtn.disabled = false;
        }
    }

    async function testListFiles() {
        const output = document.getElementById('filesOutput');
        const listFilesBtn = document.getElementById('listFilesBtn');

        if (!output) return;

        output.textContent = '🔄 Loading files...';
        if (listFilesBtn) listFilesBtn.disabled = true;

        try {
            if (!authConfig) {
                throw new Error('Auth config not available.');
            }

            if (typeof secureFetchInit !== 'function') {
                throw new Error('secureFetchInit not available.');
            }

            const baseURL = authConfig.baseURL && authConfig.baseURL !== ''
                ? authConfig.baseURL
                : window.location.origin;

            await secureFetchInit({
                baseURL: baseURL,
                deviceID: authConfig.deviceID,
                deviceSecret: authConfig.deviceSecret,
                gateSecrets: authConfig.gateSecrets,
                userToken: authConfig.userToken,
                capabilityToken: authConfig.capabilityToken,
                accessToken: authConfig.accessToken,
                refreshToken: authConfig.refreshToken,
                handshakePath: authConfig.handshakePath || '/handshake',
                autoHandshake: true
            });

            const response = await secureFetch({
                endpoint: '/api/files',
                method: 'GET',
                responseType: 'json'
            });

            output.textContent = '✅ Files:\n\n' + JSON.stringify(response, null, 2);
        } catch (error) {
            output.textContent = '❌ Error: ' + error.message;
        } finally {
            if (listFilesBtn) listFilesBtn.disabled = false;
        }
    }

    // Logout function
    function logout() {
        sessionStorage.removeItem('auth_config');
        window.location.href = './login.html';
    }

    // Make logout available globally
    window.logout = logout;

    console.log('🚀 Secure Application JS loaded');
})();
