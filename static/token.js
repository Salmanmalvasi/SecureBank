// Talks to the ESP32 token over USB (Web Serial) and polls for Wi-Fi pushes.
(function () {
  const csrf = document.querySelector('meta[name=csrf]').content;
  const input = document.getElementById('otp');
  const form = document.getElementById('otp-form');
  const status = document.getElementById('tokstatus');
  const connectBtn = document.getElementById('connect');
  const syncBtn = document.getElementById('sync');

  // Wi-Fi path: ask the server every 2 s whether the token pushed a code.
  setInterval(() => {
    fetch('/api/poll', { method: 'POST', headers: { 'X-CSRF': csrf } })
      .then(r => r.json())
      .then(d => { if (d.done) window.location = d.next; })
      .catch(() => {});
  }, 2000);

  // USB path
  if (!('serial' in navigator)) {
    connectBtn.disabled = true;
    status.textContent = 'USB connect needs Chrome or Edge. You can still type the code.';
    return;
  }
  let writer = null;

  connectBtn.addEventListener('click', async () => {
    try {
      const port = await navigator.serial.requestPort();
      await port.open({ baudRate: 115200 });
      const enc = new TextEncoderStream();
      enc.readable.pipeTo(port.writable);
      writer = enc.writable.getWriter();
      syncBtn.disabled = false;
      connectBtn.disabled = true;
      status.textContent = 'Token connected. Press the button on the token.';
      readLoop(port);
    } catch (e) {
      status.textContent = 'Could not open the port (close the Arduino Serial Monitor first).';
    }
  });

  syncBtn.addEventListener('click', () => {
    if (writer) writer.write('T' + Math.floor(Date.now() / 1000) + '\n');
  });

  async function readLoop(port) {
    const dec = new TextDecoderStream();
    port.readable.pipeTo(dec.writable);
    const reader = dec.readable.getReader();
    let buf = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += value;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        const m = line.match(/^OTP:(\d{6})$/);
        if (m) {
          input.value = m[1];
          status.textContent = 'Code received from token.';
          form.submit();
        } else if (line.startsWith('OK')) {
          status.textContent = 'Token says: ' + line;
        }
      }
    }
  }
})();
