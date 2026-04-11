document.getElementById('postForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const content = document.getElementById('content').value.trim();
  if (!content) return;

  const res = await fetch('/api/posts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      thread_id: Number(threadId),
      user_id: 1,
      content: content
    })
  });

  const text = await res.text();
  alert(text);

  if (!res.ok) return;

  document.getElementById('content').value = '';
  loadPosts();
});
