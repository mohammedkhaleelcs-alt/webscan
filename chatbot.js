// static/chatbot.js
const bubble = document.getElementById('chat-bubble');
const panel = document.getElementById('chat-panel');
const close = document.getElementById('chat-close');
const historyEl = document.getElementById('chat-history');
const qInput = document.getElementById('chat-q');

function appendMsg(who, text){
  const d = document.createElement('div'); d.className = 'chat-msg'; d.innerHTML = `<strong>${who}</strong>: <div>${text}</div>`;
  historyEl.appendChild(d); historyEl.scrollTop = historyEl.scrollHeight;
}

bubble.addEventListener('click', ()=>{ panel.classList.remove('chat-hidden'); });
close.addEventListener('click', ()=>{ panel.classList.add('chat-hidden'); });

document.getElementById('chat-send').addEventListener('click', async ()=>{
  const q = qInput.value.trim(); if(!q) return;
  appendMsg('You', q); qInput.value='';
  const res = await fetch('/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({q})});
  const js = await res.json();
  appendMsg('WebScan', js.answer || '...');
});
