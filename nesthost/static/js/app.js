(function () {
  'use strict';
  var $ = function (s) { return document.querySelector(s); };
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  // reveal on scroll
  var io = 'IntersectionObserver' in window ? new IntersectionObserver(function (es) { es.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }); }, { threshold: .12 }) : null;
  document.querySelectorAll('.rv').forEach(function (el) { io ? io.observe(el) : el.classList.add('in'); });

  // domain / subdomain checker (home page + domain guide)
  function checker(form, input, out) {
    if (!form) return;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var v = input.value.trim().toLowerCase();
      if (!v) return;
      out.className = out.className.replace(/\b(ok|bad)\b/g, '').trim(); out.textContent = 'Checking...';
      var full = v.indexOf('.') > -1;
      fetch(full ? '/api/domain?d=' + encodeURIComponent(v) : '/api/check?name=' + encodeURIComponent(v))
        .then(function (r) { return r.json(); }).then(function (j) {
          if (j.error) { out.className += ' bad'; out.textContent = j.error; return; }
          if (full) {
            var m = { taken: ['bad', esc(j.domain) + ' is already registered.'], available: ['ok', esc(j.domain) + ' looks available. Confirm at a registrar (it costs money).'], unknown: ['bad', 'Could not get the status of this domain right now.'] }[j.status];
            out.className += ' ' + m[0]; out.innerHTML = m[1] + (j.status === 'available' ? ' Or <a href="/signup">get a free subdomain</a>.' : '');
          } else if (j.available) {
            out.className += ' ok'; out.innerHTML = esc(j.host) + ' is available! <a href="/signup?next=/dashboard">Claim it for free</a>';
          } else { out.className += ' bad'; out.textContent = j.reason || 'Not available.'; }
        }).catch(function () { out.className += ' bad'; out.textContent = 'Check failed. Please try again.'; });
    });
  }
  checker($('#dc'), $('#dcq'), $('#dcr'));
  checker($('#dc2'), $('#dc2q'), $('#dc2r'));

  // live subdomain hint on dashboard
  var sub = $('#sub'), hint = $('#subh'), t;
  if (sub) sub.addEventListener('input', function () {
    clearTimeout(t); var v = sub.value.trim().toLowerCase(); hint.className = 'hint'; if (!v) { hint.textContent = ''; return; }
    t = setTimeout(function () { fetch('/api/check?name=' + encodeURIComponent(v)).then(function (r) { return r.json(); }).then(function (j) { hint.className = 'hint ' + (j.available ? 'ok' : 'bad'); hint.textContent = j.available ? 'Available' : (j.reason || ''); }).catch(function () { }); }, 350);
  });

  // zip upload with progress
  var zf = $('#zipform');
  if (zf) {
    var drop = $('#zdrop'), file = zf.querySelector('input[type=file]'), bar = zf.querySelector('.bar2'), msg = $('#zmsg');
    drop.addEventListener('click', function () { file.click(); });
    drop.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); file.click(); } });
    ['dragenter', 'dragover'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('over'); }); });
    ['dragleave', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('over'); }); });
    drop.addEventListener('drop', function (e) { if (e.dataTransfer.files[0]) send(e.dataTransfer.files[0]); });
    file.addEventListener('change', function () { if (file.files[0]) send(file.files[0]); });
    function send(f) {
      var fd = new FormData(); fd.append('csrf', zf.querySelector('[name=csrf]').value); fd.append('zip', f);
      bar.hidden = false; bar.firstElementChild.style.width = '0'; msg.className = 'hint'; msg.textContent = 'Uploading...';
      var x = new XMLHttpRequest(); x.open('POST', zf.dataset.action);
      x.upload.onprogress = function (e) { if (e.lengthComputable) bar.firstElementChild.style.width = Math.round(e.loaded / e.total * 100) + '%'; };
      x.onload = function () {
        var j = {}; try { j = JSON.parse(x.responseText); } catch (e) { }
        msg.className = 'hint ' + (j.ok ? 'ok' : 'bad'); msg.textContent = j.message || 'Upload failed.';
        if (j.ok) setTimeout(function () { location.reload(); }, 1200);
      };
      x.onerror = function () { msg.className = 'hint bad'; msg.textContent = 'Connection lost.'; };
      x.send(fd);
    }
  }

  document.querySelectorAll('[data-copy]').forEach(function (b) {
    b.addEventListener('click', function () { var old = b.textContent; (navigator.clipboard ? navigator.clipboard.writeText(b.dataset.copy) : Promise.reject()).then(function () { b.textContent = 'Copied'; }).catch(function () { b.textContent = b.dataset.copy; }); setTimeout(function () { b.textContent = old; }, 2000); });
  });

  // dark mode toggle
  var th = $('#theme');
  if (th) th.addEventListener('click', function () {
    var dark = document.documentElement.dataset.theme === 'dark';
    if (dark) { delete document.documentElement.dataset.theme; } else { document.documentElement.dataset.theme = 'dark'; }
    try { localStorage.setItem('theme', dark ? 'light' : 'dark'); } catch (e) { }
  });

  // Ctrl+S saves in the file editor
  var ed = document.querySelector('textarea.editor');
  if (ed) document.addEventListener('keydown', function (e) { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); ed.form.submit(); } });
})();
