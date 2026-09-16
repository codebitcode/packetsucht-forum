const MEDIA_URL = '/paketsucht.mp3';
const MEDIA_TIME_KEY = 'paketsucht-media-time';
const MEDIA_PAUSED_KEY = 'paketsucht-media-manual-pause';

let currentThreadId = null;
let isPosting = false;
let lastSavedSecond = -1;
let manualPaused = sessionStorage.getItem(MEDIA_PAUSED_KEY) === '1';

const banner = document.getElementById('banner');
const overviewView = document.getElementById('overviewView');
const threadView = document.getElementById('threadView');
const player = document.getElementById('ambientPlayer');
const audioToggle = document.getElementById('audioToggle');

function trackPage() {
  fetch('/api/track-page', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      path: location.host + location.pathname + location.search
    })
  }).catch(() => {});
}

function updateAudioButton() {
  audioToggle.hidden = false;
  audioToggle.textContent = player.paused ? '▶ Play' : '⏸ Pause';
  audioToggle.setAttribute(
    'aria-label',
    player.paused ? 'Hintergrundmusik abspielen' : 'Hintergrundmusik pausieren'
  );
}

function savePlayerTime() {
  if (!Number.isFinite(player.currentTime)) return;

  const second = Math.floor(player.currentTime);
  if (second === lastSavedSecond) return;

  lastSavedSecond = second;
  localStorage.setItem(MEDIA_TIME_KEY, String(player.currentTime));
}

function restorePlayerTime() {
  const saved = Number(localStorage.getItem(MEDIA_TIME_KEY));
  if (!Number.isFinite(saved) || saved <= 0) return;

  if (Number.isFinite(player.duration) && saved >= player.duration) {
    localStorage.removeItem(MEDIA_TIME_KEY);
    return;
  }

  try {
    player.currentTime = saved;
  } catch (_) {}
}

function tryPlayAfterInteraction() {
  if (manualPaused) {
    updateAudioButton();
    return;
  }

  const playPromise = player.play();
  if (playPromise && typeof playPromise.catch === 'function') {
    playPromise.catch(() => updateAudioButton());
  }
}

async function loadThreads() {
  const res = await fetch('/api/threads');
  const data = await res.json();

  const container = document.getElementById('threads');
  container.innerHTML = '';

  data.forEach(t => {
    const row = document.createElement('div');
    row.className = 'thread';

    const link = document.createElement('a');
    link.href = '/thread.html?id=' + encodeURIComponent(t.id);
    link.textContent = t.title;

    link.addEventListener('click', event => {
      if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;

      event.preventDefault();
      tryPlayAfterInteraction();
      openThread(t.id, true);
    });

    row.appendChild(link);
    container.appendChild(row);
  });
}

async function createThread() {
  const titleInput = document.getElementById('titleInput');
  const title = titleInput.value.trim();
  if (!title) return;

  const res = await fetch('/api/threads', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title })
  });

  if (!res.ok) {
    alert(await res.text());
    return;
  }

  titleInput.value = '';
  await loadThreads();
}

async function checkOverviewLogin() {
  const res = await fetch('/api/me');
  const data = await res.json();
  const el = document.getElementById('auth');

  el.innerHTML = '';

  if (data.loggedIn) {
    el.appendChild(document.createTextNode(data.user.username + ' | '));

    const logoutLink = document.createElement('a');
    logoutLink.href = '#';
    logoutLink.textContent = 'Logout';
    logoutLink.addEventListener('click', async event => {
      event.preventDefault();
      await logout();
    });

    el.appendChild(logoutLink);
  } else {
    const login = document.createElement('a');
    login.href = '/login.html';
    login.textContent = 'Login';

    const register = document.createElement('a');
    register.href = '/register.html';
    register.textContent = 'Register';

    el.appendChild(login);
    el.appendChild(document.createTextNode(' | '));
    el.appendChild(register);
  }
}

async function logout() {
  await fetch('/api/logout', { method: 'POST' });
  history.replaceState({}, '', '/index.html');
  location.reload();
}

async function loadThread() {
  if (currentThreadId === null) return;

  const requestedId = String(currentThreadId);
  const res = await fetch('/api/threads');
  const threads = await res.json();
  const thread = threads.find(t => String(t.id) === requestedId);

  if (String(currentThreadId) !== requestedId) return;

  document.getElementById('threadTitle').textContent = thread ? thread.title : 'Thread nicht gefunden';
}

async function checkThreadLogin() {
  const res = await fetch('/api/me');
  const data = await res.json();
  const form = document.getElementById('postForm');
  const error = document.getElementById('error');

  if (!data.loggedIn) {
    form.style.display = 'none';
    error.innerText = 'Bitte einloggen';
  } else {
    form.style.display = '';
    if (error.innerText === 'Bitte einloggen') error.innerText = '';
  }
}

async function loadPosts() {
  if (currentThreadId === null) return;

  const requestedId = String(currentThreadId);
  const res = await fetch('/api/posts?thread_id=' + Number(requestedId));
  const data = await res.json();

  if (currentThreadId === null || String(currentThreadId) !== requestedId) return;

  const container = document.getElementById('posts');
  container.innerHTML = '';

  data.forEach(p => {
    const el = document.createElement('div');
    el.style.marginBottom = '12px';

    const name = document.createElement('b');
    name.textContent = p.username + ':';

    const text = document.createElement('div');
    text.textContent = p.content || '';

    el.appendChild(name);
    el.appendChild(document.createElement('br'));
    el.appendChild(text);

    if (p.image) {
      if (p.status === 'approved') {
        const img = document.createElement('img');
        img.src = '/api/image/' + encodeURIComponent(p.image);
        img.className = 'post-image';
        el.appendChild(img);
      } else if (p.status === 'pending') {
        const box = document.createElement('div');
        box.textContent = 'PENDING';
        box.className = 'box pending';
        el.appendChild(box);
      } else if (p.status === 'rejected') {
        const box = document.createElement('div');
        box.textContent = 'ABGELEHNT';
        box.className = 'box rejected';
        el.appendChild(box);
      }
    }

    container.appendChild(el);
  });
}

function showOverview(track = false) {
  currentThreadId = null;

  banner.hidden = false;
  overviewView.hidden = false;
  threadView.hidden = true;
  document.title = 'Paketsucht Forum';
  updateAudioButton();

  loadThreads().catch(console.error);
  checkOverviewLogin().catch(console.error);
  if (track) trackPage();
}

function openThread(id, pushHistory = false, track = false) {
  const numericId = Number(id);
  if (!Number.isFinite(numericId)) {
    showOverview(track);
    return;
  }

  currentThreadId = numericId;

  if (pushHistory) {
    history.pushState({ threadId: numericId }, '', '/thread.html?id=' + encodeURIComponent(numericId));
    track = true;
  }

  banner.hidden = true;
  overviewView.hidden = true;
  threadView.hidden = false;
  document.getElementById('threadTitle').textContent = 'Lade...';
  document.getElementById('posts').innerHTML = '';
  document.getElementById('error').innerText = '';
  document.title = 'Paketsucht';

  updateAudioButton();

  loadThread().catch(console.error);
  loadPosts().catch(console.error);
  checkThreadLogin().catch(console.error);
  if (track) trackPage();
}

function navigateOverview() {
  history.pushState({}, '', '/index.html');
  showOverview(true);
}

function renderCurrentRoute(track = false) {
  const params = new URLSearchParams(location.search);

  if (location.pathname.endsWith('/thread.html') && params.get('id')) {
    openThread(params.get('id'), false, track);
  } else {
    showOverview(track);
  }
}

window.createThread = createThread;

document.getElementById('backToOverview').addEventListener('click', event => {
  if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;

  event.preventDefault();
  navigateOverview();
});

document.getElementById('postForm').addEventListener('submit', async event => {
  event.preventDefault();

  if (isPosting || currentThreadId === null) return;
  isPosting = true;

  const submitBtn = document.querySelector('#postForm button[type="submit"]');
  if (submitBtn) submitBtn.disabled = true;

  try {
    const content = document.getElementById('content').value.trim();
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];

    if (!content && !file) return;

    document.getElementById('error').innerText = '';
    let uploadedFile = null;

    if (file) {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('thread_id', currentThreadId);

      const uploadRes = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });

      const uploadText = await uploadRes.text();
      console.log('POST /api/upload:', uploadRes.status, uploadText);

      if (!uploadRes.ok) {
        document.getElementById('error').innerText = uploadText;
        return;
      }

      const uploadData = JSON.parse(uploadText);
      uploadedFile = uploadData.filename;
    }

    const res = await fetch('/api/posts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        thread_id: Number(currentThreadId),
        content,
        image: uploadedFile
      })
    });

    const text = await res.text();
    console.log('POST /api/posts:', res.status, text);

    if (!res.ok) {
      document.getElementById('error').innerText = text;
      return;
    }

    document.getElementById('content').value = '';
    fileInput.value = '';
    await loadPosts();
  } finally {
    isPosting = false;
    if (submitBtn) submitBtn.disabled = false;
  }
});

player.src = MEDIA_URL;
player.addEventListener('loadedmetadata', restorePlayerTime);
player.addEventListener('timeupdate', savePlayerTime);
player.addEventListener('play', updateAudioButton);
player.addEventListener('pause', updateAudioButton);
player.addEventListener('ended', () => {
  localStorage.removeItem(MEDIA_TIME_KEY);
  lastSavedSecond = -1;
  updateAudioButton();
});
player.addEventListener('error', updateAudioButton);

audioToggle.addEventListener('click', async () => {
  if (player.paused) {
    manualPaused = false;
    sessionStorage.removeItem(MEDIA_PAUSED_KEY);

    try {
      await player.play();
    } catch (_) {}
  } else {
    manualPaused = true;
    sessionStorage.setItem(MEDIA_PAUSED_KEY, '1');
    player.pause();
  }

  updateAudioButton();
});

window.addEventListener('popstate', () => {
  renderCurrentRoute(true);
});

window.addEventListener('pagehide', savePlayerTime);

renderCurrentRoute(true);
updateAudioButton();

setInterval(() => {
  if (currentThreadId === null) {
    loadThreads().catch(() => {});
  } else {
    loadPosts().catch(() => {});
  }
}, 5000);
