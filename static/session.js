(function () {
  var timer = document.getElementById('session-timer');
  if (!timer) return;
  var total = parseInt(timer.dataset.seconds, 10) || 300;
  var remaining = total;
  var label = document.getElementById('session-time');
  var warn = document.getElementById('session-warning');
  var warnTime = document.getElementById('session-warn-time');
  var stay = document.getElementById('session-stay');
  var csrf = document.querySelector('meta[name="csrf"]');

  function fmt(s) {
    s = Math.max(0, s);
    return Math.floor(s / 60) + ':' + ('0' + (s % 60)).slice(-2);
  }

  function render() {
    label.textContent = fmt(remaining);
    if (warnTime) warnTime.textContent = fmt(remaining);
    timer.classList.toggle('low', remaining <= 60);
    if (warn) warn.hidden = remaining > 60;
  }

  var tick = setInterval(function () {
    remaining -= 1;
    render();
    if (remaining <= 0) {
      clearInterval(tick);
      window.location.href = timer.dataset.logout;
    }
  }, 1000);
  render();

  if (stay) {
    stay.addEventListener('click', function () {
      stay.disabled = true;
      fetch(timer.dataset.ping, {
        method: 'POST',
        headers: { 'X-CSRF': csrf ? csrf.content : '' },
        credentials: 'same-origin'
      }).then(function (r) {
        if (r.ok) remaining = total;
        render();
      }).catch(function () {}).then(function () { stay.disabled = false; });
    });
  }
})();
