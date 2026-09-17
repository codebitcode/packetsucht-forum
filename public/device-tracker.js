(() => {
  const nativeFetch = window.fetch.bind(window);

  function detectOS(ua, platform) {
    const text = `${ua} ${platform}`;
    if (/iPad|iPhone|iPod/i.test(text) || (/Mac/i.test(platform) && navigator.maxTouchPoints > 1)) return 'iOS/iPadOS';
    if (/Android/i.test(text)) return 'Android';
    if (/Windows/i.test(text)) return 'Windows';
    if (/CrOS/i.test(text)) return 'Chrome OS';
    if (/Mac/i.test(text)) return 'macOS';
    if (/Linux/i.test(text)) return 'Linux';
    return platform || 'Unbekannt';
  }

  function detectBrowser(ua) {
    if (/Edg\//i.test(ua)) return 'Edge';
    if (/OPR\//i.test(ua) || /Opera/i.test(ua)) return 'Opera';
    if (/Firefox\//i.test(ua)) return 'Firefox';
    if (/Chrome\//i.test(ua) || /CriOS\//i.test(ua)) return 'Chrome';
    if (/Safari\//i.test(ua) && !/Chrome|CriOS|Edg|OPR/i.test(ua)) return 'Safari';
    return 'Unbekannt';
  }

  function detectDeviceType(ua) {
    if (/iPad|Tablet/i.test(ua)) return 'Tablet';
    if (/Mobi|Android|iPhone|iPod/i.test(ua)) return 'Handy';
    return 'Desktop';
  }

  async function collectVisitorDeviceInfo() {
    const ua = navigator.userAgent || '';
    const platform = navigator.userAgentData?.platform || navigator.platform || '';
    let browser = detectBrowser(ua);

    try {
      if (navigator.brave && typeof navigator.brave.isBrave === 'function' && await navigator.brave.isBrave()) {
        browser = 'Brave';
      }
    } catch (_) {}

    let timezone = '';
    try {
      timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    } catch (_) {}

    return {
      os: detectOS(ua, platform),
      browser,
      language: navigator.language || '',
      screen: window.screen ? `${window.screen.width}×${window.screen.height}` : '',
      viewport: `${window.innerWidth || 0}×${window.innerHeight || 0}`,
      timezone,
      deviceType: detectDeviceType(ua),
      platform,
      userAgent: ua
    };
  }

  window.collectVisitorDeviceInfo = collectVisitorDeviceInfo;

  window.fetch = async function(input, init) {
    try {
      const rawUrl = typeof input === 'string' ? input : (input && input.url) || '';
      const url = new URL(rawUrl, location.href);
      const method = String(init?.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();

      if (url.pathname === '/api/track-page' && method === 'POST' && typeof init?.body === 'string') {
        const body = JSON.parse(init.body);
        body.client = await collectVisitorDeviceInfo();
        init = { ...init, body: JSON.stringify(body) };
      }
    } catch (_) {}

    return nativeFetch(input, init);
  };
})();
