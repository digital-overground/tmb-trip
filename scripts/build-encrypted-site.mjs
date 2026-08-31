import { webcrypto } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";

const ITERATIONS = 600_000;
const encoder = new TextEncoder();
const passphrase = process.env.SITE_PASSPHRASE;
const sourcePath = process.env.SOURCE_HTML_PATH;

if (!passphrase) {
  throw new Error("SITE_PASSPHRASE is required");
}

if (!sourcePath) {
  throw new Error("SOURCE_HTML_PATH is required");
}

const source = await readFile(sourcePath);

const salt = webcrypto.getRandomValues(new Uint8Array(16));
const iv = webcrypto.getRandomValues(new Uint8Array(12));
const keyMaterial = await webcrypto.subtle.importKey(
  "raw",
  encoder.encode(passphrase),
  "PBKDF2",
  false,
  ["deriveKey"],
);
const key = await webcrypto.subtle.deriveKey(
  { name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERATIONS },
  keyMaterial,
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"],
);
const encrypted = new Uint8Array(
  await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, source),
);

const decrypted = new Uint8Array(
  await webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted),
);
if (!Buffer.from(decrypted).equals(source)) {
  throw new Error("Encryption round-trip verification failed");
}

const base64 = (value) => Buffer.from(value).toString("base64");
const payload = {
  version: 1,
  algorithm: "AES-256-GCM",
  kdf: "PBKDF2-SHA256",
  iterations: ITERATIONS,
  salt: base64(salt),
  iv: base64(iv),
  ciphertext: base64(encrypted),
};

const unlockPage = renderUnlockPage(payload);
await mkdir("dist", { recursive: true });
await writeFile("dist/index.html", unlockPage, "utf8");
console.log("Encrypted site built and round-trip verified.");

function renderUnlockPage(encryptedPayload) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <meta name="theme-color" content="#062946">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
  <title>Unlock itinerary</title>
  <style>
    :root{color-scheme:light;--navy:#062946;--green:#08784c;--ink:#102033;--muted:#6c7885;--line:#dce3e6;--bg:#f4f6f7}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:24px}
    main{width:min(100%,430px);background:#fff;border:1px solid var(--line);border-radius:22px;padding:28px;box-shadow:0 12px 40px rgba(15,33,51,.12)}
    .mark{width:48px;height:48px;display:grid;place-items:center;border-radius:15px;background:var(--navy);color:#fff;font-size:24px;margin-bottom:20px}
    h1{font-size:26px;line-height:1.1;margin:0 0 10px;color:var(--green)}p{margin:0 0 22px;color:var(--muted);line-height:1.5}
    label{display:block;font-size:13px;font-weight:800;margin-bottom:7px}input,button{width:100%;min-height:52px;border-radius:14px;font:inherit}
    input{border:1px solid #cbd6da;padding:0 14px;color:var(--ink);background:#fff}input:focus{outline:3px solid rgba(8,120,76,.18);border-color:var(--green)}
    @keyframes autofill-start{from{opacity:.99}to{opacity:1}}input:-webkit-autofill{animation-name:autofill-start;animation-duration:.01s}
    button{border:0;margin-top:12px;background:var(--green);color:#fff;font-weight:800;cursor:pointer}button:disabled{opacity:.6;cursor:wait}
    #status{min-height:21px;margin:13px 0 0;color:#a23d3d;font-size:13px}small{display:block;color:var(--muted);line-height:1.45;margin-top:18px}
  </style>
</head>
<body>
  <main>
    <div class="mark" aria-hidden="true">🔒</div>
    <h1>Geneva + Tour du Mont Blanc</h1>
    <p>This itinerary is encrypted. Enter the passphrase to unlock it locally on this device.</p>
    <form id="unlock-form">
      <label for="passphrase">Passphrase</label>
      <input id="passphrase" name="passphrase" type="password" autocomplete="current-password" maxlength="256" required autofocus>
      <button id="unlock-button" type="submit">Unlock itinerary</button>
      <p id="status" role="alert" aria-live="polite"></p>
    </form>
    <small>The passphrase is never transmitted or stored by this page.</small>
  </main>
  <script>
    const payload = ${JSON.stringify(encryptedPayload)};
    const form = document.getElementById("unlock-form");
    const input = document.getElementById("passphrase");
    const button = document.getElementById("unlock-button");
    const status = document.getElementById("status");
    const bytes = (value) => Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
    const minimumAutofillLength = 20;
    let unlocking = false;
    let observedValue = input.value;
    let autoSubmitTimer;

    const scheduleAutofillSubmit = () => {
      if (unlocking || input.value.length < minimumAutofillLength) return;
      window.clearTimeout(autoSubmitTimer);
      autoSubmitTimer = window.setTimeout(() => {
        if (!unlocking && input.value.length >= minimumAutofillLength) form.requestSubmit();
      }, 180);
    };

    input.addEventListener("input", (event) => {
      const insertedLength = input.value.length - observedValue.length;
      observedValue = input.value;
      if (insertedLength > 1 || event.inputType === "insertReplacementText") {
        scheduleAutofillSubmit();
      }
    });
    input.addEventListener("change", () => {
      observedValue = input.value;
      scheduleAutofillSubmit();
    });
    input.addEventListener("animationstart", (event) => {
      if (event.animationName === "autofill-start") scheduleAutofillSubmit();
    });
    window.addEventListener("pageshow", () => {
      window.setTimeout(scheduleAutofillSubmit, 250);
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (unlocking) return;
      unlocking = true;
      window.clearTimeout(autoSubmitTimer);
      button.disabled = true;
      button.textContent = "Unlocking…";
      status.textContent = "";

      try {
        const material = await crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(input.value),
          "PBKDF2",
          false,
          ["deriveKey"],
        );
        const key = await crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: bytes(payload.salt),
            iterations: payload.iterations,
          },
          material,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"],
        );
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: bytes(payload.iv) },
          key,
          bytes(payload.ciphertext),
        );
        input.value = "";
        const html = new TextDecoder().decode(decrypted);
        document.open();
        document.write(html);
        document.close();
      } catch {
        unlocking = false;
        observedValue = "";
        input.value = "";
        status.textContent = "That passphrase did not unlock the itinerary.";
        button.disabled = false;
        button.textContent = "Unlock itinerary";
        input.focus();
      }
    });
  </script>
</body>
</html>`;
}
