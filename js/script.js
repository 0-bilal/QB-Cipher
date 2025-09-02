// QB-Cipher Chat – Enhanced Security Chat Application
(() => {
  // ====== CONFIGURATION ======
  const GAS_URL = "https://script.google.com/macros/s/AKfycbxXf-hoYEk1UR5mX6tqv7kGqlvrYgLp_MLQNhsyWJzcggtMoKXtPKWOOlJ6PF4XxoPFaQ/exec";

  // ====== DOM ELEMENTS ======
  const $ = (sel) => document.querySelector(sel);
  const chatList = $("#chatList");
  const messageInput = $("#messageInput");
  const sendBtn = $("#sendBtn");
  const statusDot = $("#statusDot");
  const roomInput = $("#roomId");
  const userInput = $("#userId");
  const roomLabel = $("#roomLabel");
  const userLabel = $("#userLabel");
  const saveSettingsBtn = $("#saveSettings");
  const clearMessagesBtn = $("#clearMessages");
  const reconnectBtn = $("#reconnect");

  const aesKeyInput = $("#aesKey");
  const genAESBtn = $("#genAES");
  const pasteAESBtn = $("#pasteAES");
  const copyAESBtn = $("#copyAES");
  const clearAESBtn = $("#clearAES");

  const hmacKeyInput = $("#hmacKey");
  const genHMACBtn = $("#genHMAC");
  const pasteHMACBtn = $("#pasteHMAC");
  const copyHMACBtn = $("#copyHMAC");
  const clearHMACBtn = $("#clearHMAC");

  // ====== APPLICATION STATE ======
  let pollingTimer = null;
  let lastMessageId = null;
  const seenIds = new Set(); // منع التكرار
  let settings = { 
    roomId: "", 
    userId: "", 
    aesKeyB64: "", 
    hmacKeyB64: "" 
  };
  let isConnected = false;
  let retryCount = 0;
  const MAX_RETRIES = 3;

  // ====== UTILITY FUNCTIONS ======
  const textEnc = new TextEncoder();
  const textDec = new TextDecoder();
  const randomBytes = (n) => { 
    const u = new Uint8Array(n); 
    crypto.getRandomValues(u); 
    return u; 
  };
  const bytesToBase64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const base64ToBytes = (b64) => new Uint8Array(atob(b64).split('').map(c => c.charCodeAt(0)));
  const formatTime = (ts) => new Date(ts).toLocaleString('ar-SA', { 
    hour12: false,
    hour: '2-digit',
    minute: '2-digit'
  });
  const safeBase64 = (s) => /^[A-Za-z0-9+/=]+$/.test(s || "");

  // ====== UI FUNCTIONS ======
  function showMessage(text, type = "success") {
    const cont = document.getElementById("messageContainer");
    const el = document.createElement("div");
    el.className = `message ${type}`;
    const icon = type === "success" ? "✅" : "❌";
    el.innerHTML = `<span class="icon">${icon}</span>${text}`;
    cont.appendChild(el);
    
    setTimeout(() => el.classList.add("show"), 10);
    setTimeout(() => { 
      el.classList.remove("show"); 
      setTimeout(() => el.remove(), 300); 
    }, 3000);
  }

  function setOnline(status) {
    statusDot.classList.remove("ok", "err");
    if (status) {
      statusDot.classList.add("ok");
      isConnected = true;
      retryCount = 0;
    } else {
      statusDot.classList.add("err");
      isConnected = false;
    }
  }

  function addBubble({ text, from, ts, verified, isOwn }) {
    const wrap = document.createElement("article");
    wrap.className = `msg ${isOwn ? "other" : "me"}`;
    const name = from || "مجهول";
    const timeStr = formatTime(ts || Date.now());
    
    wrap.innerHTML = `
      <div class="from">${name}</div>
      <div class="text"></div>
      <div class="meta">
        ${verified ? 
          '<span class="badge">محقق</span>' : 
          '<span class="badge" style="background:rgba(239,68,68,.18);color:#FCA5A5">غير محقق</span>'
        }
        <span class="time">${timeStr}</span>
      </div>
    `;
    
    wrap.querySelector(".text").textContent = text;
    chatList.appendChild(wrap);
    chatList.scrollTop = chatList.scrollHeight;
    
    // Add entrance animation
    requestAnimationFrame(() => {
      wrap.style.opacity = '0';
      wrap.style.transform = 'translateY(20px)';
      requestAnimationFrame(() => {
        wrap.style.transition = 'all 0.3s ease-out';
        wrap.style.opacity = '1';
        wrap.style.transform = 'translateY(0)';
      });
    });
  }

  function refreshHeader() {
    roomLabel.textContent = settings.roomId || "—";
    userLabel.textContent = settings.userId ? `أنت: ${settings.userId}` : "—";
  }

  // ====== CRYPTOGRAPHY FUNCTIONS ======
  const AES_IV_BYTES = 12;

  async function importAESKeyFromBase64(b64) {
    if (!safeBase64(b64)) throw new Error("مفتاح AES ليس Base64 صالح.");
    const raw = base64ToBytes(b64);
    if (raw.length !== 32) throw new Error("مفتاح AES يجب أن يكون 32 بايت.");
    return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  }

  async function importHmacKeyFromBase64(b64) {
    if (!safeBase64(b64)) throw new Error("مفتاح HMAC ليس Base64 صالح.");
    const raw = base64ToBytes(b64);
    if (raw.length !== 32) throw new Error("مفتاح HMAC مفضل أن يكون 32 بايت.");
    return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  }

  async function encryptAESGCM(plainText, aesKeyB64) {
    const key = await importAESKeyFromBase64(aesKeyB64);
    const iv = randomBytes(AES_IV_BYTES);
    const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textEnc.encode(plainText));
    return { 
      ivB64: bytesToBase64(iv), 
      ctB64: bytesToBase64(new Uint8Array(ctBuf)) 
    };
  }

  async function decryptAESGCM(ctB64, ivB64, aesKeyB64) {
    const key = await importAESKeyFromBase64(aesKeyB64);
    const iv = base64ToBytes(ivB64);
    const ct = base64ToBytes(ctB64);
    const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return textDec.decode(ptBuf);
  }

  async function hmacSha256Base64(messageBytes, hmacKeyB64) {
    const key = await importHmacKeyFromBase64(hmacKeyB64);
    const sig = await crypto.subtle.sign("HMAC", key, messageBytes);
    return bytesToBase64(new Uint8Array(sig));
  }

  async function hmacVerifyBase64(messageBytes, hmacKeyB64, signatureB64) {
    const key = await importHmacKeyFromBase64(hmacKeyB64);
    const sig = base64ToBytes(signatureB64);
    return crypto.subtle.verify("HMAC", key, sig, messageBytes);
  }

  // ====== SETTINGS MANAGEMENT ======
  function loadSettings() {
    try {
      const raw = localStorage.getItem("qbcipher:settings");
      if (raw) {
        const obj = JSON.parse(raw);
        delete obj.gasUrl; // تجاهل أي قيمة قديمة
        settings = { ...settings, ...obj };
      }
    } catch (e) {
      console.warn("Failed to load settings:", e);
    }
    
    roomInput.value = settings.roomId || "";
    userInput.value = settings.userId || "";
    aesKeyInput.value = settings.aesKeyB64 || "";
    hmacKeyInput.value = settings.hmacKeyB64 || "";
    
    // استرجاع آخر معرف لهذه الغرفة
    if (settings.roomId) {
      lastMessageId = localStorage.getItem(`qbcipher:lastId:${settings.roomId}`) || null;
    }
    
    refreshHeader();
  }

  function saveSettings() {
    settings.roomId = roomInput.value.trim();
    settings.userId = userInput.value.trim();
    settings.aesKeyB64 = aesKeyInput.value.trim();
    settings.hmacKeyB64 = hmacKeyInput.value.trim();
    
    try {
      localStorage.setItem("qbcipher:settings", JSON.stringify(settings));
      refreshHeader();
      
      if (settings.roomId) { 
        startPolling(true); 
      }
      
      showMessage("تم حفظ الإعدادات بنجاح ✅");
    } catch (e) {
      showMessage("فشل في حفظ الإعدادات", "error");
    }
  }

  // ====== NETWORK FUNCTIONS ======
  // JSONP GET for reading messages
  let cbSeq = 0;
  function jsonp(url, params) {
    return new Promise((resolve, reject) => {
      const cbName = "__qbjsonp_" + (++cbSeq);
      const cleanup = (script) => { 
        delete window[cbName]; 
        if (script && script.parentNode) script.parentNode.removeChild(script); 
      };
      
      const q = new URL(url);
      Object.entries(params || {}).forEach(([k, v]) => q.searchParams.set(k, v));
      q.searchParams.set("callback", cbName);
      q.searchParams.set("_t", Date.now().toString()); // cache-buster
      
      const script = document.createElement("script");
      window[cbName] = (data) => { cleanup(script); resolve(data); };
      script.onerror = () => { cleanup(script); reject(new Error("JSONP failed")); };
      script.src = q.toString();
      document.body.appendChild(script);
      
      setTimeout(() => { 
        cleanup(script); 
        reject(new Error("JSONP timeout")); 
      }, 15000);
    });
  }

  // Hidden-iframe POST for sending messages
  function postViaIframe(url, payloadObj) {
    return new Promise((resolve) => {
      const iframe = document.createElement("iframe");
      iframe.name = "__qb_iframe_" + Math.random().toString(36).slice(2);
      iframe.style.display = "none";
      document.body.appendChild(iframe);

      const form = document.createElement("form");
      form.method = "POST";
      form.target = iframe.name;
      form.action = url;
      
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "payload";
      input.value = JSON.stringify(payloadObj);
      form.appendChild(input);
      document.body.appendChild(form);

      form.submit();
      
      setTimeout(() => { 
        form.remove(); 
        iframe.remove(); 
        resolve(true); 
      }, 800);
    });
  }

  async function apiSendToken(token) {
    if (!GAS_URL || GAS_URL.indexOf("/exec") === -1) {
      throw new Error("ضبط رابط GAS_URL (يجب أن يكون /exec).");
    }
    
    const payload = { 
      action: "send", 
      roomId: settings.roomId, 
      senderId: settings.userId || "anon", 
      token 
    };
    
    await postViaIframe(GAS_URL, payload);
    return { ok: true };
  }

  async function apiListSince(sinceId) {
    if (!GAS_URL || GAS_URL.indexOf("/exec") === -1) {
      throw new Error("ضبط رابط GAS_URL (يجب أن يكون /exec).");
    }
    
    const params = { 
      action: "list", 
      roomId: settings.roomId 
    };
    
    if (sinceId) params.sinceId = sinceId;
    
    return jsonp(GAS_URL, params);
  }

  // ====== MESSAGE HANDLING ======
  async function handleSend() {
    const msg = messageInput.value.trim();
    if (!msg) return;
    
    if (!settings.roomId) {
      return showMessage("أدخل معرف الغرفة Room ID", "error");
    }
    
    if (!settings.aesKeyB64) {
      return showMessage("أدخل/ولّد مفتاح AES-GCM", "error");
    }
    
    if (!settings.hmacKeyB64) {
      return showMessage("أدخل/ولّد مفتاح HMAC", "error");
    }

    // Show loading state
    sendBtn.classList.add("loading");
    sendBtn.disabled = true;

    try {
      const { ivB64, ctB64 } = await encryptAESGCM(msg, settings.aesKeyB64);
      const sealed = `${ivB64}.${ctB64}`;
      const macB64 = await hmacSha256Base64(textEnc.encode(sealed), settings.hmacKeyB64);
      const token = `gcm:${sealed}.${macB64}`;

      // Add message to UI immediately
      addBubble({ 
        text: msg, 
        from: settings.userId || "أنا", 
        ts: Date.now(), 
        verified: true, 
        isOwn: true 
      });

      await apiSendToken(token);
      messageInput.value = "";
      messageInput.style.height = "auto";
      
      showMessage("تم إرسال الرسالة بنجاح 🚀");
      
    } catch (e) {
      console.error(e);
      showMessage(e.message || "خطأ أثناء الإرسال", "error");
    } finally {
      // Remove loading state
      sendBtn.classList.remove("loading");
      sendBtn.disabled = false;
    }
  }

  async function pollOnce() {
    if (!settings.roomId || !GAS_URL) { 
      setOnline(false); 
      return; 
    }
    
    try {
      const data = await apiListSince(lastMessageId);
      
      if (!data || !Array.isArray(data.messages)) { 
        setOnline(true); 
        return; 
      }
      
      for (const m of data.messages) {
        if (seenIds.has(m.id)) continue; // تجاهل المكرر

        let plain = null, verified = false;
        
        try {
          if (!m.token || !m.token.startsWith("gcm:")) {
            throw new Error("bad token");
          }
          
          const parts = m.token.slice(4).split(".");
          if (parts.length !== 3) {
            throw new Error("bad format");
          }
          
          const [ivB64, ctB64, macB64] = parts;
          const sealed = `${ivB64}.${ctB64}`;
          const ok = await hmacVerifyBase64(textEnc.encode(sealed), settings.hmacKeyB64, macB64);
          verified = !!ok;
          plain = await decryptAESGCM(ctB64, ivB64, settings.aesKeyB64);
          
        } catch (e) {
          plain = "🔒 رسالة غير قابلة للفك بالمفاتيح الحالية";
          verified = false;
        }

        const isOwn = (m.senderId || "") === (settings.userId || "");
        
        // Don't show own messages again
        if (!isOwn) {
          addBubble({ 
            text: plain, 
            from: m.senderId || "—", 
            ts: m.ts || Date.now(), 
            verified, 
            isOwn 
          });
        }

        seenIds.add(m.id);
        lastMessageId = m.id;
      }
      
      if (settings.roomId && lastMessageId) {
        localStorage.setItem(`qbcipher:lastId:${settings.roomId}`, lastMessageId);
      }
      
      setOnline(true);
      
    } catch (e) {
      console.warn("Polling error:", e);
      setOnline(false);
      
      // Implement exponential backoff
      if (retryCount < MAX_RETRIES) {
        retryCount++;
        setTimeout(() => pollOnce(), Math.pow(2, retryCount) * 1000);
      }
    }
  }

  function startPolling(reset = false) {
    if (reset) {
      lastMessageId = localStorage.getItem(`qbcipher:lastId:${settings.roomId}`) || null;
      
      // Keep welcome message, remove others
      const welcomeMsg = chatList.querySelector('.msg');
      chatList.innerHTML = '';
      if (welcomeMsg && welcomeMsg.textContent.includes('QB-Cipher')) {
        chatList.appendChild(welcomeMsg);
      }
      
      seenIds.clear();
      retryCount = 0;
    }
    
    if (pollingTimer) clearInterval(pollingTimer);
    pollingTimer = setInterval(pollOnce, 2500);
    pollOnce();
  }

  // ====== KEY MANAGEMENT ======
  function generateAESKey() {
    aesKeyInput.value = bytesToBase64(randomBytes(32));
    showMessage("تم توليد مفتاح AES-GCM جديد 🔑");
  }

  function generateHMACKey() {
    hmacKeyInput.value = bytesToBase64(randomBytes(32));
    showMessage("تم توليد مفتاح HMAC جديد 🛡️");
  }

  async function copyToClipboard(text, keyType) {
    if (!text) return;
    
    try {
      await navigator.clipboard.writeText(text);
      showMessage(`تم نسخ مفتاح ${keyType} 📋`);
    } catch (e) {
      // Fallback for older browsers
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      showMessage(`تم نسخ مفتاح ${keyType} 📋`);
    }
  }

  async function pasteFromClipboard(inputEl, keyType) {
    try {
      const text = await navigator.clipboard.readText();
      if (!text) {
        return showMessage("الحافظة فارغة.", "error");
      }
      inputEl.value = text.trim();
      showMessage(`تم لصق مفتاح ${keyType} 📥`);
    } catch (e) {
      showMessage("تعذر الوصول للحافظة.", "error");
    }
  }

  function clearInput(inputEl, keyType) {
    inputEl.value = "";
    showMessage(`تم مسح مفتاح ${keyType} 🗑️`);
  }

  // ====== MOBILE FUNCTIONS ======
  window.toggleSettings = function() {
    const panel = document.getElementById('settingsPanel');
    panel.classList.toggle('open');
  };

  function setupMobileHandlers() {
    // Close settings when clicking outside on mobile
    document.addEventListener('click', (e) => {
      const panel = document.getElementById('settingsPanel');
      const toggle = document.querySelector('.mobile-toggle');
      
      if (window.innerWidth <= 980 && 
          !panel.contains(e.target) && 
          !toggle.contains(e.target) && 
          panel.classList.contains('open')) {
        panel.classList.remove('open');
      }
    });

    // Auto-resize textarea
    messageInput.addEventListener('input', function() {
      this.style.height = 'auto';
      this.style.height = Math.min(this.scrollHeight, 200) + 'px';
    });
  }

  // ====== EVENT LISTENERS ======
  function setupEventListeners() {
    // Send message
    sendBtn.addEventListener("click", handleSend);
    messageInput.addEventListener("keydown", (e) => {
      if (e.ctrlKey && e.key === "Enter") {
        e.preventDefault();
        handleSend();
      }
    });

    // Settings
    saveSettingsBtn.addEventListener("click", saveSettings);
    reconnectBtn.addEventListener("click", () => startPolling(true));
    clearMessagesBtn.addEventListener("click", () => {
      const welcomeMsg = chatList.querySelector('.msg');
      chatList.innerHTML = '';
      if (welcomeMsg && welcomeMsg.textContent.includes('QB-Cipher')) {
        chatList.appendChild(welcomeMsg);
      }
      showMessage("تم مسح المحادثة 🧹");
    });

    // AES Key Management
    genAESBtn.addEventListener("click", generateAESKey);
    copyAESBtn.addEventListener("click", () => copyToClipboard(aesKeyInput.value, "AES"));
    pasteAESBtn.addEventListener("click", () => pasteFromClipboard(aesKeyInput, "AES"));
    clearAESBtn.addEventListener("click", () => clearInput(aesKeyInput, "AES"));

    // HMAC Key Management
    genHMACBtn.addEventListener("click", generateHMACKey);
    copyHMACBtn.addEventListener("click", () => copyToClipboard(hmacKeyInput.value, "HMAC"));
    pasteHMACBtn.addEventListener("click", () => pasteFromClipboard(hmacKeyInput, "HMAC"));
    clearHMACBtn.addEventListener("click", () => clearInput(hmacKeyInput, "HMAC"));

    // Enter key to save settings
    [roomInput, userInput, aesKeyInput, hmacKeyInput].forEach((el) => {
      el.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          saveSettings();
        }
      });
    });

    // Auto-save settings on input change (debounced)
    let saveTimeout;
    [roomInput, userInput].forEach((el) => {
      el.addEventListener("input", () => {
        clearTimeout(saveTimeout);
        saveTimeout = setTimeout(() => {
          settings.roomId = roomInput.value.trim();
          settings.userId = userInput.value.trim();
          refreshHeader();
        }, 500);
      });
    });
  }

  // ====== INITIALIZATION ======
  function init() {
    loadSettings();
    setupEventListeners();
    setupMobileHandlers();
    
    // Set placeholders if empty
    if (!aesKeyInput.value) {
      aesKeyInput.placeholder = "ألصق مفتاح AES (Base64) بطول 32 بايت…";
    }
    
    if (!hmacKeyInput.value) {
      hmacKeyInput.placeholder = "ألصق مفتاح HMAC (Base64) بطول 32 بايت…";
    }

    // Initial connection status
    setTimeout(() => {
      if (settings.roomId) {
        startPolling();
      } else {
        setOnline(false);
      }
    }, 1000);

    // Show welcome message
    setTimeout(() => {
      showMessage("مرحباً بك في QB-Cipher! 🔐", "success");
    }, 500);

    console.log("QB-Cipher initialized successfully! 🚀");
  }

  // ====== CLEANUP ======
  window.addEventListener('beforeunload', () => {
    if (pollingTimer) {
      clearInterval(pollingTimer);
    }
  });

  // Start the application
  window.addEventListener("load", init);

})();