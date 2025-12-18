function getCurrentSeconds() {
  return Math.round(new Date().getTime() / 1000.0);
}

function truncateTo(str, digits) {
  if (str.length <= digits) {
    return str;
  }
  return str.slice(-digits);
}

function parseURLSearch(search) {
  const queryParams = search.substr(1).split('&').reduce(function (q, query) {
    const chunks = query.split('=');
    const key = chunks[0];
    let value = decodeURIComponent(chunks[1]);
    value = isNaN(Number(value)) ? value : Number(value);
    return (q[key] = value, q);
  }, {});

  return queryParams;
}

// ============================================
// Funciones de encriptación/desencriptación
// ============================================

// Deriva una clave criptográfica desde una contraseña
async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encripta datos usando AES-GCM
async function encryptData(data, password) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(JSON.stringify(data));
  
  // Generar salt e IV aleatorios
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  // Derivar la clave desde la contraseña
  const key = await deriveKey(password, salt);
  
  // Encriptar los datos
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    dataBuffer
  );
  
  // Combinar salt + iv + datos encriptados
  const encryptedData = new Uint8Array(salt.length + iv.length + encryptedBuffer.byteLength);
  encryptedData.set(salt, 0);
  encryptedData.set(iv, salt.length);
  encryptedData.set(new Uint8Array(encryptedBuffer), salt.length + iv.length);
  
  // Convertir a base64 para almacenamiento
  return btoa(String.fromCharCode(...encryptedData));
}

// Desencripta datos usando AES-GCM
async function decryptData(encryptedBase64, password) {
  try {
    // Convertir desde base64
    const encryptedData = new Uint8Array(
      atob(encryptedBase64).split('').map(c => c.charCodeAt(0))
    );
    
    // Extraer salt, iv y datos encriptados
    const salt = encryptedData.slice(0, 16);
    const iv = encryptedData.slice(16, 28);
    const data = encryptedData.slice(28);
    
    // Derivar la clave desde la contraseña
    const key = await deriveKey(password, salt);
    
    // Desencriptar
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      data
    );
    
    // Decodificar y parsear JSON
    const decoder = new TextDecoder();
    const decryptedText = decoder.decode(decryptedBuffer);
    return JSON.parse(decryptedText);
  } catch (error) {
    throw new Error('Incorrect password or corrupted data');
  }
}

// ============================================
// Funciones de guardado/carga con encriptación
// ============================================

let masterPasswordGlobal = "";

function setMasterPassword(password) {
  masterPasswordGlobal = password;
}

function getMasterPassword() {
  return masterPasswordGlobal;
}

// Guarda el array completo de claves (encriptado o en texto plano)
async function saveKeys(keys) {
  const password = getMasterPassword();
  if (password === null || password === undefined) {
    throw new Error('Master password has not been set');
  }
  
  if (password === '') {
    // Empty password: save without encryption
    localStorage.setItem('savedKeys', JSON.stringify(keys));
  } else {
    // Non-empty password: encrypt
    const encryptedData = await encryptData(keys, password);
    localStorage.setItem('savedKeys', encryptedData);
  }
}

// Loads and decrypts all keys (or loads in plain text)
async function loadKeys() {
  const password = getMasterPassword();
  
  if (password === null || password === undefined) {
    return [];
  }
  
  const storedData = localStorage.getItem('savedKeys');
  
  if (!storedData) {
    return [];
  }
  
  if (password === '') {
    // Contraseña vacía: intentar cargar sin encriptar
    try {
      const data = JSON.parse(storedData);
      // Verificar que es un array válido
      if (Array.isArray(data)) {
        return data;
      }
      // If not an array, data is encrypted
      throw new Error('Data encrypted with empty password');
    } catch (error) {
      // If parsing fails, data is encrypted
      throw new Error('Incorrect password or corrupted data');
    }
  } else {
    // Non-empty password: decrypt
    try {
      return await decryptData(storedData, password);
    } catch (error) {
      throw error;
    }
  }
}

// Verifica si hay datos guardados
function hasStoredData() {
  return localStorage.getItem('savedKeys') !== null;
}

const app = Vue.createApp({
  data() {
    return {
      secret_key: '',
      digits: 6,
      period: 30,
      algorithm: 'SHA1',
      updatingIn: 30,
      token: null,
      clipboardButton: null,
      savedKeys: [],
      showPasswordModal: true,
      masterPassword: '',
      passwordError: '',
      showChangePasswordModal: false,
      currentPassword: '',
      newPassword: '',
      confirmNewPassword: '',
      changePasswordError: '',
      qrFileName: '',
      showCameraModal: false,
      cameraError: '',
      cameraStream: null,
      scanningInterval: null,
      // Alert modal data
      alertModal: {
        show: false,
        title: 'Alert',
        message: '',
        icon: 'fa-info-circle'
      },
      // Confirm modal data
      confirmModal: {
        show: false,
        title: 'Confirm',
        message: '',
        acceptText: 'Accept',
        cancelText: 'Cancel',
        onAccept: null,
        onCancel: null
      }
    };
  },

  mounted: function () {
    this.intervalHandle = setInterval(this.updateToken, 1000);
    this.clipboardButton = new ClipboardJS('#clipboard-button');
    
    // No cargar claves hasta que se desbloquee la aplicación
    if (!hasStoredData()) {
      this.showPasswordModal = false;
    }
    this.updateToken();
  },

  destroyed: function () {
    clearInterval(this.intervalHandle);
    this.closeCameraModal(); // Ensure camera is stopped when component is destroyed
  },

  computed: {
    totp: function () {
      if (!this.secret_key || this.secret_key.trim() === '') {
        return null;
      }
      try {
        return new OTPAuth.TOTP({
          algorithm: this.algorithm,
          digits: this.digits,
          period: this.period,
          secret: OTPAuth.Secret.fromBase32(this.secret_key.replace(/\s/g, '')),
        });
      } catch (error) {
        return null;
      }
    }
  },

  methods: {
    // ============================================
    // Modal Alert and Confirm methods
    // ============================================
    showAlert: function(message, title = 'Alert', icon = 'fa-info-circle') {
      this.alertModal = {
        show: true,
        title: title,
        message: message,
        icon: icon
      };
    },

    closeAlertModal: function() {
      this.alertModal.show = false;
    },

    showConfirm: function(message, onAccept, onCancel = null, title = 'Confirm', acceptText = 'Accept', cancelText = 'Cancel') {
      this.confirmModal = {
        show: true,
        title: title,
        message: message,
        acceptText: acceptText,
        cancelText: cancelText,
        onAccept: onAccept,
        onCancel: onCancel
      };
    },

    acceptConfirmModal: function() {
      this.confirmModal.show = false;
      if (this.confirmModal.onAccept) {
        this.confirmModal.onAccept();
      }
    },

    cancelConfirmModal: function() {
      this.confirmModal.show = false;
      if (this.confirmModal.onCancel) {
        this.confirmModal.onCancel();
      }
    },

    // ============================================
    // App methods
    // ============================================
    unlockApp: async function () {
      // Allow empty passwords
      // Set the master password (can be empty)
      setMasterPassword(this.masterPassword);

      // If there is stored data, try to decrypt it
      if (hasStoredData()) {
        try {
          await this.loadKeys();
          // If decryption was successful, close the modal
          this.showPasswordModal = false;
          this.passwordError = '';
          // Load the first key if it exists
          this.loadFirstKey();
        } catch (error) {
          // If the password is incorrect, show an error
          this.passwordError = 'Incorrect password. Please try again.';
          this.masterPassword = '';
          setMasterPassword(""); // Clear the master password
        }
      } else {
        // No stored data, accept any password
        this.showPasswordModal = false;
        this.passwordError = '';
      }
    },

    loadFirstKey: function () {
      if (this.savedKeys.length > 0) {
        const firstKey = this.savedKeys[0];
        this.loadKey(firstKey);
      } else {
        // Si no hay claves guardadas, dejar el secret vacío
        this.secret_key = '';
      }
    },

    clearAllConfiguration: async function () {
      this.showConfirm(
        'Are you sure you want to clear all configuration and saved keys? This action cannot be undone.',
        () => {
          localStorage.removeItem('savedKeys');
          this.secret_key = '';
          this.digits = 6;
          this.period = 30;
          this.algorithm = 'SHA1';
          this.updatingIn = 30;
          this.key_name = '';
          this.token = null;
          this.savedKeys = [];
          this.showPasswordModal = false;
          this.masterPassword = '';
          this.passwordError = '';
          setMasterPassword("");
        },
        null,
        'Clear All Configuration',
        'Yes, clear all',
        'Cancel'
      );
    },

    showChangePasswordDialog: function () {
      this.showChangePasswordModal = true;
      this.currentPassword = '';
      this.newPassword = '';
      this.confirmNewPassword = '';
      this.changePasswordError = '';
    },

    closeChangePasswordDialog: function () {
      this.showChangePasswordModal = false;
      this.currentPassword = '';
      this.newPassword = '';
      this.confirmNewPassword = '';
      this.changePasswordError = '';
    },

    changePassword: async function () {
      // Verify that the current password matches
      const currentMasterPassword = getMasterPassword();
      if (this.currentPassword !== currentMasterPassword) {
        this.changePasswordError = 'Current password is incorrect';
        return;
      }

      // Verify that the new passwords match
      if (this.newPassword !== this.confirmNewPassword) {
        this.changePasswordError = 'New passwords do not match';
        return;
      }

      try {
        // Load the data with the current password
        const keys = await loadKeys();

        // Set the new password
        setMasterPassword(this.newPassword);

        // Save the data with the new password
        await saveKeys(keys);

        // Show success message
        this.showAlert('Password changed successfully', 'Success', 'fa-check-circle');
        this.closeChangePasswordDialog();
      } catch (error) {
        this.changePasswordError = 'Error changing password: ' + error.message;
        // Restore the previous password
        setMasterPassword(currentMasterPassword);
      }
    },

    saveKeys: async function (savedKeys) {
      try {
        await saveKeys(savedKeys);
        await this.loadKeys();

        const password = getMasterPassword();
        if (password === '') {
          this.showConfirm(
            'You are saving keys without a master password. This means your keys will be stored unencrypted in the browser storage. Do you want to set a master password now?',
            () => {
              this.showChangePasswordDialog();
            },
            null,
            'Security Warning',
            'Set Password',
            'Continue Without Password'
          );
          return;
        }
      } catch (error) {
        this.showAlert('Error saving keys: ' + error.message, 'Error', 'fa-exclamation-circle');
      }
    },

    saveCurrentKey: async function () {
      const key = {
        name: this.key_name || `Unnamed Key ${this.secret_key.slice(-4)}`,
        secret: this.secret_key,
        digits: this.digits,
        period: this.period,
        algorithm: this.algorithm,
      };

      try {
        // Check if the key already exists with the same name
        const savedKeys = await loadKeys();
        const exists = savedKeys.some(savedKey =>
          savedKey.name === key.name
        );

        if (exists) {
          if (!this.showConfirm(
            `A key with the name "${key.name}" already exists. Do you want to overwrite it?`,
            async () => {
              // Overwrite the existing key
              const index = savedKeys.findIndex(savedKey => savedKey.name === key.name);
              savedKeys[index] = key;
              await this.saveKeys(savedKeys);
            },
            null,
            'Duplicate Key Name',
            'Overwrite',
            'Cancel'
          ))
          return;
        }

        savedKeys.push(key);
        await this.saveKeys(savedKeys);

      } catch (error) {
        this.showAlert('Error saving the key: ' + error.message, 'Error', 'fa-exclamation-circle');
        console.error('Error saving key:', error);
      }
    },

    loadKey: function (key) {
      this.key_name = key.name;
      this.secret_key = key.secret;
      this.digits = key.digits;
      this.period = key.period;
      this.algorithm = key.algorithm;
      this.updateToken();
    },

    deleteKey: async function (index) {
      try {
        const savedKeys = await loadKeys();
        savedKeys.splice(index, 1);
        await saveKeys(savedKeys);
        await this.loadKeys();
      } catch (error) {
        this.showAlert('Error deleting the key: ' + error.message, 'Error', 'fa-exclamation-circle');
      }
    },

    loadKeys: async function () {
      try {
        this.savedKeys = await loadKeys();
      } catch (error) {
        throw error;
      }
    },

    updateToken: function () {
      this.updatingIn = this.period - (getCurrentSeconds() % this.period);
      if (this.totp) {
        try {
          this.token = truncateTo(this.totp.generate(), this.digits);
        } catch (error) {
          this.token = '------';
        }
      } else {
        this.token = '------';
      }
    },

    handleQRImageUpload: function (event) {
      const file = event.target.files[0];
      if (!file) {
        return;
      }

      this.qrFileName = file.name;

      const reader = new FileReader();
      reader.onload = (e) => {
        this.processQRImage(e.target.result);
      };
      reader.readAsDataURL(file);
    },

    processQRImage: function (imageData) {
      const image = new Image();
      image.onload = () => {
        // Create a canvas to read the image data
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        canvas.width = image.width;
        canvas.height = image.height;
        context.drawImage(image, 0, 0);

        // Get image data
        const imageDataObj = context.getImageData(0, 0, canvas.width, canvas.height);

        // Decode QR code
        const code = jsQR(imageDataObj.data, imageDataObj.width, imageDataObj.height);

        if (code) {
          this.parseOTPAuthURL(code.data);
        } else {
          this.showAlert('No QR code found in the image. Please try with a different image.', 'QR Code Error', 'fa-exclamation-triangle');
          this.qrFileName = '';
          this.$refs.qrFileInput.value = '';
        }
      };
      image.src = imageData;
    },

    parseOTPAuthURL: function (url) {
      try {
        // Check if it's an otpauth URL
        if (!url.startsWith('otpauth://')) {
          this.showAlert('The QR code does not contain a valid OTP authentication URL.', 'Invalid QR Code', 'fa-exclamation-triangle');
          return;
        }

        // Parse the URL
        const urlObj = new URL(url);
        
        // Check if it's a TOTP URL
        if (urlObj.protocol !== 'otpauth:' || urlObj.hostname !== 'totp') {
          this.showAlert('Only TOTP (Time-based OTP) URLs are supported.', 'Unsupported Type', 'fa-exclamation-triangle');
          return;
        }

        // Extract the account name from the path
        const path = decodeURIComponent(urlObj.pathname.substring(1));
        
        // Extract parameters
        const params = new URLSearchParams(urlObj.search);
        const secret = params.get('secret');
        const issuer = params.get('issuer');
        const digits = params.get('digits') || '6';
        const period = params.get('period') || '30';
        const algorithm = (params.get('algorithm') || 'SHA1').toUpperCase();

        if (!secret) {
          this.showAlert('No secret key found in the QR code.', 'Invalid QR Code', 'fa-exclamation-triangle');
          return;
        }

        // Set the values in the form
        this.secret_key = secret;
        this.digits = parseInt(digits);
        this.period = parseInt(period);
        this.algorithm = algorithm;
        
        // Set a default name if possible
        if (issuer && path) {
          this.key_name = `${issuer}: ${path}`;
        } else if (path) {
          this.key_name = path;
        } else if (issuer) {
          this.key_name = issuer;
        }

        // Update the token
        this.updateToken();

        // Clear the file input
        this.qrFileName = '';
        this.$refs.qrFileInput.value = '';
      } catch (error) {
        this.showAlert('Error parsing the QR code: ' + error.message, 'Error', 'fa-exclamation-circle');
        this.qrFileName = '';
        this.$refs.qrFileInput.value = '';
      }
    },

    openCamera: async function () {
      this.showCameraModal = true;
      this.cameraError = "";
      try {
        // Request camera access
        this.cameraStream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment' } // Use back camera on mobile
        });

        // Set the video source
        const video = this.$refs.cameraVideo;
        video.srcObject = this.cameraStream;
        
        // Wait for video to be ready
        await new Promise((resolve) => {
          video.onloadedmetadata = resolve;
        });

        // Start scanning for QR codes
        this.startQRScanning();
      } catch (error) {
        console.error('Camera error:', error);
        if (error.name === 'NotAllowedError' || error.name === 'PermissionDeniedError') {
          this.cameraError = 'Camera permission denied. Please allow camera access and try again.';
        } else if (error.name === 'NotFoundError' || error.name === 'DevicesNotFoundError') {
          this.cameraError = 'No camera found on this device.';
        } else {
          this.cameraError = 'Error accessing camera: ' + error.message;
        }
      }
    },

    startQRScanning: function () {
      const video = this.$refs.cameraVideo;
      const canvas = this.$refs.cameraCanvas;
      const context = canvas.getContext('2d');

      // Scan every 300ms
      this.scanningInterval = setInterval(() => {
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          context.drawImage(video, 0, 0, canvas.width, canvas.height);

          const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);

          if (code) {
            // QR code found!
            this.parseOTPAuthURL(code.data);
            this.closeCameraModal();
          }
        }
      }, 300);
    },

    closeCameraModal: function () {
      // Stop scanning
      if (this.scanningInterval) {
        clearInterval(this.scanningInterval);
        this.scanningInterval = null;
      }

      // Stop camera stream
      if (this.cameraStream) {
        this.cameraStream.getTracks().forEach(track => track.stop());
        this.cameraStream = null;
      }

      // Clear video source
      if (this.$refs.cameraVideo) {
        this.$refs.cameraVideo.srcObject = null;
      }

      this.showCameraModal = false;
      this.cameraError = '';
    }
  }
});

app.mount('#app');
