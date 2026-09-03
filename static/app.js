// CryptoPegion — shared front-end helpers (session wiring + ad loading)
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  function csrfToken() {
    const m = document.querySelector('meta[name="csrf"]');
    return m ? m.getAttribute('content') : '';
  }

  async function api(path, opts) {
    opts = opts || {};
    const headers = { 'Accept': 'application/json' };
    let body = opts.body;
    if (body && typeof body !== 'string') {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(body);
    }
    const method = (opts.method || (body ? 'POST' : 'GET')).toUpperCase();
    if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken();
    const res = await fetch(path, { method, headers, body, credentials: 'same-origin' });
    let data = {};
    try { data = await res.json(); } catch (e) { /* empty */ }
    if (!res.ok) {
      const err = new Error(data.error || ('Request failed (' + res.status + ')'));
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function fmtSize(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
    if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
    return Math.max(1, Math.round(b / 1024)) + ' KB';
  }

  function fmtTime(sec) {
    if (sec <= 0) return 'expired';
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    if (d) return d + 'd ' + h + 'h left';
    if (h) return h + 'h ' + m + 'm left';
    return m + ' min left';
  }

  async function getMe() {
    try { return await api('/api/me'); } catch (e) { return null; }
  }

  function applyMe(me) {
    const body = document.body;
    if (!body) return;
    body.dataset.plan = me ? me.plan : 'anon';
    body.dataset.ads = me ? String(!!me.ads) : 'true';

    const planChip = $('navPlanChip');
    if (planChip && me && me.authed) {
      planChip.style.display = 'inline-flex';
      planChip.textContent = me.plan + ' plan';
      planChip.className = 'chip ' + me.plan;
    }
    const guestBox = $('navGuest');
    const userBox = $('navUser');
    if (guestBox && userBox) {
      guestBox.style.display = me && me.authed ? 'none' : 'flex';
      userBox.style.display = me && me.authed ? 'flex' : 'none';
      if (me && me.authed && $('navUserName')) $('navUserName').textContent = me.name || me.email;
    }
    // Hide premium-only affordances for free users.
    if (me && !me.limits.branding) {
      document.querySelectorAll('[data-paid]').forEach((el) => { el.classList.add('ad-hidden'); });
    }
  }

  async function loadAd(slot) {
    const host = document.querySelector('.ad-slot[data-ad="' + slot + '"] .inner');
    if (!host) return null;
    if (host.dataset.loaded) return null;
    host.dataset.loaded = '1';
    try {
      const data = await api('/api/ads?slot=' + encodeURIComponent(slot));
      if (!data.enabled || !data.ad) {
        const unit = host.closest('.ad-slot');
        if (unit) unit.classList.add('ad-hidden');
        return null;
      }
      const ad = data.ad;
      host.innerHTML =
        '<span class="ad-label">Sponsored</span>' +
        '<div class="ad-unit inline" data-ad-id="' + ad.id + '" data-ad-url="' + (ad.url || '').replace(/"/g, '&quot;') + '">' +
        ad.code + '</div>';
      const wrap = host.querySelector('.ad-unit');
      if (!wrap) return ad;
      wrap.addEventListener('click', (e) => {
        fetch('/api/ads/' + ad.id + '/click', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
        const href = e.target.closest('a');
        if (!href && ad.url) {
          e.preventDefault();
          window.open(ad.url, '_blank', 'noopener');
        }
      });
      return ad;
    } catch (e) {
      const unit = host.closest('.ad-slot');
      if (unit) unit.classList.add('ad-hidden');
      return null;
    }
  }

  function stripTags(html) {
    const div = document.createElement('div');
    div.innerHTML = html;
    return div.textContent || '';
  }

  window.CP = {
    $: $,
    api: api,
    getMe: getMe,
    applyMe: applyMe,
    loadAd: loadAd,
    fmtSize: fmtSize,
    fmtTime: fmtTime,
    csrfToken: csrfToken,
    stripTags: stripTags,
  };

  async function boot() {
    const me = await getMe();
    applyMe(me);
    const wantAds = !(me && me.ads === false);
    if (wantAds) {
      const slots = Array.from(document.querySelectorAll('.ad-slot[data-ad]'));
      for (const el of slots) await loadAd(el.dataset.ad);
    } else {
      document.querySelectorAll('.ad-slot[data-ad]').forEach((el) => el.classList.add('ad-hidden'));
    }
    document.body.classList.add('cp-ready');
    document.dispatchEvent(new CustomEvent('cp:ready', { detail: { me: me } }));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
