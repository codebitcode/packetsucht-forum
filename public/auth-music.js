const FALLBACK_MEDIA_URL = '/paketsucht.mp3';
const MUSIC_FOLDER = '/music/';
const MEDIA_TIME_KEY = 'paketsucht-media-time';
const MEDIA_PAUSED_KEY = 'paketsucht-media-manual-pause';
const MEDIA_TRACK_KEY = 'paketsucht-media-track-index';

const player = document.getElementById('ambientPlayer');
const audioToggle = document.getElementById('audioToggle');
const audioPrev = document.getElementById('audioPrev');
const audioNext = document.getElementById('audioNext');

let playlist = [FALLBACK_MEDIA_URL];
let currentTrackIndex = 0;
let lastSavedSecond = -1;
let manualPaused = sessionStorage.getItem(MEDIA_PAUSED_KEY) === '1';

function updateAudioButton() {
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
  localStorage.setItem(MEDIA_TRACK_KEY, String(currentTrackIndex));
}

function restorePlayerTime() {
  const saved = Number(localStorage.getItem(MEDIA_TIME_KEY));
  if (!Number.isFinite(saved) || saved <= 0) return;
  if (Number.isFinite(player.duration) && saved >= player.duration) {
    localStorage.removeItem(MEDIA_TIME_KEY);
    return;
  }
  try { player.currentTime = saved; } catch (_) {}
}

async function discoverPlaylist() {
  const found = [];
  for (let i = 1; i <= 99; i++) {
    const filename = String(i).padStart(2, '0') + '.mp3';
    const url = MUSIC_FOLDER + filename;
    try {
      const res = await fetch(url, { method: 'HEAD', cache: 'no-store' });
      const type = (res.headers.get('content-type') || '').toLowerCase();
      if (!res.ok || (!type.includes('audio') && !type.includes('mpeg') && !type.includes('octet-stream'))) break;
      found.push(url);
    } catch (_) {
      break;
    }
  }

  playlist = found.length ? found : [FALLBACK_MEDIA_URL];
  const savedIndex = Number(localStorage.getItem(MEDIA_TRACK_KEY));
  currentTrackIndex = Number.isInteger(savedIndex) && savedIndex >= 0 && savedIndex < playlist.length ? savedIndex : 0;

  player.src = playlist[currentTrackIndex];
  player.load();

  if (!manualPaused) {
    try { await player.play(); } catch (_) {}
  }
  updateAudioButton();
}

function loadTrack(index, resume = false) {
  if (!playlist.length) return;
  currentTrackIndex = ((index % playlist.length) + playlist.length) % playlist.length;
  localStorage.setItem(MEDIA_TRACK_KEY, String(currentTrackIndex));
  localStorage.removeItem(MEDIA_TIME_KEY);
  lastSavedSecond = -1;

  player.src = playlist[currentTrackIndex];
  player.load();

  if (resume && !manualPaused) {
    const p = player.play();
    if (p && typeof p.catch === 'function') p.catch(() => updateAudioButton());
  }
}

player.addEventListener('loadedmetadata', restorePlayerTime);
player.addEventListener('timeupdate', savePlayerTime);
player.addEventListener('play', updateAudioButton);
player.addEventListener('pause', updateAudioButton);
player.addEventListener('ended', () => {
  localStorage.removeItem(MEDIA_TIME_KEY);
  lastSavedSecond = -1;
  loadTrack(currentTrackIndex + 1, true);
});
player.addEventListener('error', updateAudioButton);

audioToggle.addEventListener('click', async () => {
  if (player.paused) {
    manualPaused = false;
    sessionStorage.removeItem(MEDIA_PAUSED_KEY);
    try { await player.play(); } catch (_) {}
  } else {
    manualPaused = true;
    sessionStorage.setItem(MEDIA_PAUSED_KEY, '1');
    player.pause();
  }
  updateAudioButton();
});

audioPrev.addEventListener('click', () => {
  const wasPlaying = !player.paused;
  loadTrack(currentTrackIndex - 1, wasPlaying);
});

audioNext.addEventListener('click', () => {
  const wasPlaying = !player.paused;
  loadTrack(currentTrackIndex + 1, wasPlaying);
});

window.addEventListener('pagehide', savePlayerTime);
updateAudioButton();
discoverPlaylist().catch(() => {
  playlist = [FALLBACK_MEDIA_URL];
  currentTrackIndex = 0;
  player.src = FALLBACK_MEDIA_URL;
  player.load();
});
