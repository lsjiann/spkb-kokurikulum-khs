/* ============================================================
   SPKB-AUTH — log masuk Google (Google Identity Services) untuk SPKB
   Audit 7 Nov 2026: C1 & H2.

   • Token ID Google disimpan dalam sessionStorage (hilang bila tab ditutup; dikongsi dengan
     modul iframe pada asal yang sama).
   • Panggilan data dilindungi: SPKBAuth.post(url, action, params) → POST { action, idToken, ... }
   • Pelayan (Auth_SPKB.gs) mengesahkan token, domain dan senarai pengguna.

   Konfigurasi: SPKB_AUTH_CONFIG.clientId — OAuth Client ID (bukan rahsia; selamat dalam HTML).
   CSP setiap halaman yang memuat fail ini mesti membenarkan https://accounts.google.com/gsi/
   ============================================================ */
(function () {
  'use strict';

  var CONFIG = window.SPKB_AUTH_CONFIG = window.SPKB_AUTH_CONFIG || {
    clientId: '',                 // diisi selepas OAuth Client ID dicipta
    domain: 'moe-dl.edu.my'       // petunjuk akaun (bukan kawalan keselamatan — pelayan yang menyemak)
  };
  var KUNCI = 'spkb_id_token';
  var pendengar = [];
  var gsiSedia = null;

  function simpan(t) { try { if (t) sessionStorage.setItem(KUNCI, t); else sessionStorage.removeItem(KUNCI); } catch (e) {} }
  function baca() { try { return sessionStorage.getItem(KUNCI) || ''; } catch (e) { return ''; } }

  /** Nyahkod bahagian payload JWT (untuk paparan sahaja — BUKAN pengesahan). */
  function payload(t) {
    try {
      var b = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(decodeURIComponent(atob(b).split('').map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join('')));
    } catch (e) { return null; }
  }

  function tokenSah() {
    var t = baca(); if (!t) return '';
    var p = payload(t);
    if (!p || !p.exp || p.exp * 1000 < Date.now() + 60000) { simpan(''); return ''; } // tamat / hampir tamat
    return t;
  }

  function maklum() {
    var u = SPKBAuth.pengguna();
    pendengar.forEach(function (fn) { try { fn(u); } catch (e) {} });
  }

  function muatGsi() {
    if (gsiSedia) return gsiSedia;
    gsiSedia = new Promise(function (ok, gagal) {
      if (window.google && google.accounts && google.accounts.id) return ok();
      var s = document.createElement('script');
      s.src = 'https://accounts.google.com/gsi/client';
      s.async = true; s.defer = true;
      s.onload = function () { ok(); };
      s.onerror = function () { gsiSedia = null; gagal(new Error('Tidak dapat memuat Google Sign-In')); };
      document.head.appendChild(s);
    }).then(function () {
      if (!CONFIG.clientId) throw new Error('OAuth Client ID belum ditetapkan (SPKB_AUTH_CONFIG.clientId).');
      google.accounts.id.initialize({
        client_id: CONFIG.clientId,
        callback: function (r) { simpan(r.credential); maklum(); },
        auto_select: true,
        cancel_on_tap_outside: false,
        hd: CONFIG.domain || undefined,
        ux_mode: 'popup',
        itp_support: true
      });
    });
    return gsiSedia;
  }

  var SPKBAuth = window.SPKBAuth = {
    config: CONFIG,

    /** Pengguna semasa daripada token (untuk paparan), atau null. */
    pengguna: function () {
      var t = tokenSah(); if (!t) return null;
      var p = payload(t);
      return p ? { email: p.email, nama: p.name || p.email, gambar: p.picture || '', hd: p.hd || '', tamat: p.exp * 1000 } : null;
    },

    token: tokenSah,

    /** Lukis butang "Log masuk dengan Google" dalam elemen. */
    butang: function (el, pilihan) {
      return muatGsi().then(function () {
        google.accounts.id.renderButton(el, Object.assign({ theme: 'outline', size: 'large', text: 'signin_with', shape: 'pill', locale: 'ms' }, pilihan || {}));
      });
    },

    /** Cuba log masuk senyap (One Tap / auto_select). Selesai dengan pengguna atau null. */
    cubaSenyap: function () {
      if (SPKBAuth.pengguna()) return Promise.resolve(SPKBAuth.pengguna());
      return muatGsi().then(function () {
        return new Promise(function (ok) {
          var selesai = false, henti = function (u) { if (!selesai) { selesai = true; ok(u); } };
          var fn = function (u) { if (u) henti(u); };
          pendengar.push(fn);
          google.accounts.id.prompt(function (n) {
            if (n.isNotDisplayed && n.isNotDisplayed() || n.isSkippedMoment && n.isSkippedMoment()) henti(SPKBAuth.pengguna());
          });
          setTimeout(function () { henti(SPKBAuth.pengguna()); }, 8000);
        });
      }).catch(function () { return null; });
    },

    keluar: function () {
      var u = SPKBAuth.pengguna();
      simpan('');
      try { if (window.google && google.accounts) { google.accounts.id.disableAutoSelect(); if (u) google.accounts.id.revoke(u.email, function () {}); } } catch (e) {}
      maklum();
    },

    /** Daftar fungsi yang dipanggil apabila status log masuk berubah. */
    apabilaBerubah: function (fn) { pendengar.push(fn); },

    /**
     * POST ke Apps Script dengan token. Jika pelayan memulangkan PERLU_LOG_MASUK, token dibuang
     * dan ralat dengan .perluLogMasuk = true dilempar supaya UI boleh memaparkan butang log masuk.
     */
    post: function (url, action, params) {
      var t = tokenSah();
      if (!t) { var e0 = new Error('Sila log masuk dengan akaun DELIMa yang dibenarkan.'); e0.perluLogMasuk = true; return Promise.reject(e0); }
      return fetch(url, {
        method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' },
        body: JSON.stringify(Object.assign({ action: action, idToken: t }, params || {}))
      }).then(function (r) { return r.json(); }).then(function (j) {
        var m = String((j && (j.error || j.ralat)) || '');
        if (j && j.success === false && /PERLU_LOG_MASUK/.test(m)) {
          simpan(''); maklum();
          var e1 = new Error(m.replace(/^PERLU_LOG_MASUK:\s*/, '')); e1.perluLogMasuk = true; throw e1;
        }
        if (j && j.success === false && /AKSES_DITOLAK/.test(m)) {
          var e2 = new Error(m.replace(/^AKSES_DITOLAK:\s*/, '')); e2.aksesDitolak = true; throw e2;
        }
        return j;
      });
    }
  };

  // Segerakkan antara tab/iframe: jika token berubah di tempat lain, maklumkan
  window.addEventListener('storage', function (e) { if (e.key === KUNCI) maklum(); });
})();
