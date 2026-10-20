(function () {
  const input = document.getElementById('otp');
  const status = document.getElementById('tokstatus');
  const connectBtn = document.getElementById('connect');
  const syncBtn = document.getElementById('sync');
  const getOtpBtn = document.getElementById('get-otp');
  const connectionBadge = document.getElementById('token-connection-status');
  const clockBadge = document.getElementById('token-clock-status');

  if (!status || !connectBtn || !syncBtn) return;

  let writer = null;
  let port = null;
  let connected = false;
  let waitingForOtp = false;
  let reader = null;

  function setConnection(text, state) {
    status.textContent = text;

    if (connectionBadge) {
      connectionBadge.textContent =
        state === 'connected' ? 'Connected' :
        state === 'disconnected' ? 'Disconnected' :
        'Not connected';

      connectionBadge.dataset.state = state;
    }
  }

  function setClock(text, synced) {
    if (clockBadge) {
      clockBadge.textContent = synced
        ? 'Synchronized'
        : 'Needs synchronization';

      clockBadge.dataset.state = synced ? 'connected' : 'warning';
    }

    if (text) status.textContent = text;
  }

  if (!('serial' in navigator)) {
    connectBtn.disabled = true;

    setConnection(
      'USB serial requires Chrome or Edge on a supported desktop.',
      'disconnected'
    );

    setClock('', false);
    return;
  }

  if (getOtpBtn) getOtpBtn.disabled = true;
  syncBtn.disabled = true;

  connectBtn.addEventListener('click', async function () {
    try {
      port = await navigator.serial.requestPort();
      await port.open({ baudRate: 115200 });

      const encoder = new TextEncoderStream();
      encoder.readable.pipeTo(port.writable).catch(() => {});
      writer = encoder.writable.getWriter();

      connected = true;
      syncBtn.disabled = false;

      if (getOtpBtn) getOtpBtn.disabled = false;

      connectBtn.disabled = true;

      setConnection(
        'USB token connected. Checking device identity...',
        'connected'
      );

      readLoop(port);

      await writer.write('ID\n');
    } catch (error) {
      connected = false;
      writer = null;

      syncBtn.disabled = true;

      if (getOtpBtn) getOtpBtn.disabled = true;

      connectBtn.disabled = false;

      setConnection(
        'Could not connect. Close Arduino Serial Monitor and try again.',
        'disconnected'
      );
    }
  });

  if (getOtpBtn) {
    getOtpBtn.addEventListener('click', async function () {
      if (!writer || !connected) {
        setConnection('Connect the token first.', 'disconnected');
        return;
      }

      try {
        waitingForOtp = true;
        getOtpBtn.disabled = true;

        status.textContent = 'Requesting the current OTP from the token...';

        await writer.write('GETOTP\n');
      } catch (error) {
        waitingForOtp = false;
        getOtpBtn.disabled = false;

        setConnection(
          'Could not request an OTP. Reconnect the token and try again.',
          'disconnected'
        );
      }
    });
  }

  syncBtn.addEventListener('click', async function () {
    if (!writer || !connected) {
      setConnection(
        'Connect the token before synchronizing its clock.',
        'disconnected'
      );
      return;
    }

    try {
      const unixTime = Math.floor(Date.now() / 1000);

      await writer.write('T' + unixTime + '\n');

      status.textContent =
        'Clock synchronization requested. Waiting for confirmation...';
    } catch (error) {
      setClock(
        'Clock synchronization failed. Reconnect the token and try again.',
        false
      );
    }
  });

  async function readLoop(activePort) {
    try {
      const decoder = new TextDecoderStream();

      activePort.readable.pipeTo(decoder.writable).catch(() => {});

      reader = decoder.readable.getReader();

      let buffer = '';

      while (true) {
        const result = await reader.read();

        if (result.done) break;

        buffer += result.value;

        let newline;

        while ((newline = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, newline).trim();

          buffer = buffer.slice(newline + 1);

          const match = line.match(/^OTP:(\d{6})$/);

          if (match && waitingForOtp) {
            if (input) {
              input.value = match[1];
              input.focus();
            }

            waitingForOtp = false;

            if (getOtpBtn) getOtpBtn.disabled = false;

            status.textContent = input
              ? 'OTP received. Check the code, then confirm the action.'
              : 'Token is connected and generating OTPs successfully.';

          } else if (line.startsWith('OK TIME')) {
            setClock('Token clock synchronized successfully.', true);

          } else if (line.startsWith('OK ID')) {
            setConnection(
              'Token connected: ' + line.slice(3).trim(),
              'connected'
            );

          } else if (line.startsWith('ERR')) {
            waitingForOtp = false;

            if (getOtpBtn) getOtpBtn.disabled = false;

            status.textContent = 'Token reported an error: ' + line;
          }
        }
      }
    } catch (error) {
      // USB disconnection may cause the read operation to fail.
    } finally {
      if (reader) {
        try {
          reader.releaseLock();
        } catch (error) {}

        reader = null;
      }

      connected = false;
      writer = null;

      syncBtn.disabled = true;

      if (getOtpBtn) getOtpBtn.disabled = true;

      connectBtn.disabled = false;

      setConnection(
        'USB connection interrupted. Reconnect the token to continue.',
        'disconnected'
      );
    }
  }
})();