(function () {
  var chips = document.getElementById('payee-chips');
  var to = document.getElementById('to');
  if (!chips || !to) return;
  chips.addEventListener('click', function (e) {
    var b = e.target.closest('button[data-account]');
    if (!b) return;
    to.value = b.dataset.account;
    var amount = document.getElementById('amount');
    if (amount) amount.focus();
  });
})();
