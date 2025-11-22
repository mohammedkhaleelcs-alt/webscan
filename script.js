// static/script.js

async function postForm(path, form){
  const res = await fetch(path, {method:'POST', body: form});
  return res.json();
}

// ---------- Scanning indicator ----------
function createScanStatus() {
  let existing = document.getElementById('scan-status');
  if(!existing){
    existing = document.createElement('div');
    existing.id = 'scan-status';
    existing.style.margin = '10px 0';
    existing.style.color = '#ccc';
    existing.style.display = 'none'; // hidden by default
    existing.innerHTML = '🔍 Scanning... please wait';
    document.querySelector('.controls').insertAdjacentElement('afterend', existing);
  }
}
createScanStatus(); // make sure it exists but hidden initially

function showScanning(){
  const el = document.getElementById('scan-status');
  if(el) el.style.display = 'block';
}

function hideScanning(){
  const el = document.getElementById('scan-status');
  if(el) el.style.display = 'none';
}

// ---------- Rendering helpers ----------
function severityRank(s){
  if(!s) return 2;
  s = s.toString().toLowerCase();
  if(s === 'high') return 0;
  if(s === 'medium') return 1;
  if(s === 'low') return 2;
  return 3;
}

function normalizeSeverity(s){
  if(!s) return 'medium';
  s = s.toString().toLowerCase();
  if(['high','medium','low'].includes(s)) return s;
  if(s.includes('critical') || s.includes('vuln')) return 'high';
  return 'medium';
}

function renderItems(containerId, items){
  const el = document.getElementById(containerId);
  el.innerHTML = '';
  if(!items || items.length === 0){
    el.innerHTML = '<div class="item"><div class="content">No findings</div></div>';
    return;
  }
  items.forEach(i=>{
    const sev = normalizeSeverity(i.severity);
    const item = document.createElement('div');
    item.className = `item ${sev}`;
    const meta = document.createElement('div');
    meta.className = 'meta';
    const badge = document.createElement('div');
    badge.className = 'badge ' + (sev === 'high' ? 'sev-high' : (sev === 'medium' ? 'sev-medium' : 'sev-low'));
    badge.textContent = sev.toUpperCase();
    meta.appendChild(badge);
    if(i.id) {
      const idel = document.createElement('div');
      idel.style.marginTop='8px';
      idel.textContent = i.id;
      idel.style.fontSize='12px';
      idel.style.color='var(--muted)';
      meta.appendChild(idel);
    }

    const content = document.createElement('div');
    content.className = 'content';
    const title = document.createElement('div');
    title.className = 'title';
    title.textContent = i.title || (i.raw || JSON.stringify(i));
    const rem = document.createElement('div');
    rem.className = 'remediation';
    rem.textContent = i.remediation || (i.value ? ('Value: ' + i.value) : '');

    content.appendChild(title);
    content.appendChild(rem);

    item.appendChild(meta);
    item.appendChild(content);
    el.appendChild(item);
  });
}

function renderAll(){
  const state = window.__webscan_state || {};
  const filterSeverity = document.getElementById('filter-severity').value;
  const filterText = (document.getElementById('filter-text').value || '').toLowerCase().trim();

  const passive = (state.passive || []).map(r => ({...r, severity: normalizeSeverity(r.severity)}));
  const active = (state.active && state.active.ports ? state.active.ports : []).map(r => ({...r, title: r.raw || r.title, severity: normalizeSeverity(r.severity)}));

  const matchFilter = (it) => {
    if(filterSeverity !== 'all'){
      if(normalizeSeverity(it.severity) !== filterSeverity) return false;
    }
    if(filterText){
      const hay = ((it.title||'') + ' ' + (it.remediation||'') + ' ' + (it.id||'') + ' ' + (it.value||'')).toLowerCase();
      if(!hay.includes(filterText)) return false;
    }
    return true;
  };

  const sortFn = (a,b) => {
    const ra = severityRank(normalizeSeverity(a.severity));
    const rb = severityRank(normalizeSeverity(b.severity));
    if(ra !== rb) return ra - rb;
    return (a.title || '').localeCompare(b.title || '');
  };

  const passiveFiltered = passive.filter(matchFilter).sort(sortFn);
  const activeFiltered = active.filter(matchFilter).sort(sortFn);

  document.getElementById('passive-count').textContent = `(${passiveFiltered.length})`;
  document.getElementById('active-count').textContent = `(${activeFiltered.length})`;

  renderItems('passive-results', passiveFiltered);
  renderItems('active-results', activeFiltered);
}

// ---------- Filter Events ----------
document.getElementById('filter-severity').addEventListener('change', renderAll);
document.getElementById('filter-text').addEventListener('input', ()=> { debounce(renderAll, 250)(); });
document.getElementById('btn-clear-filters').addEventListener('click', ()=>{
  document.getElementById('filter-severity').value = 'all';
  document.getElementById('filter-text').value = '';
  renderAll();
});

function debounce(fn, ms){
  let t;
  return function(...a){
    clearTimeout(t);
    t = setTimeout(()=> fn.apply(this, a), ms);
  };
}

// ---------- Scan Buttons ----------
document.getElementById('btn-passive').addEventListener('click', async ()=>{
  const target = document.getElementById('target').value;
  const max_pages = document.getElementById('max_pages').value || 10;
  const max_depth = document.getElementById('max_depth').value || 1;
  if(!target) return alert('Enter target');
  
  showScanning();
  const form = new FormData(); 
  form.append('url', target); 
  form.append('max_pages', max_pages); 
  form.append('max_depth', max_depth);
  
  const json = await postForm('/scan/passive', form);
  hideScanning();

  if(json.error) return alert(json.error||'error');
  window.__webscan_state = window.__webscan_state || {};
  window.__webscan_state.passive = json.results || [];
  window.__webscan_state.target = target;
  renderAll();
});

document.getElementById('btn-active').addEventListener('click', async ()=>{
  const target = document.getElementById('target').value;
  const consent = document.getElementById('consent').checked;
  if(!target) return alert('Enter target');
  if(!consent) return alert('You must consent to run active scan');

  showScanning();
  const form = new FormData(); 
  form.append('url', target); 
  form.append('consent', 'on');
  
  const json = await postForm('/scan/active', form);
  hideScanning();

  if(json.error) return alert(json.error||'error');
  window.__webscan_state = window.__webscan_state || {};
  window.__webscan_state.active = json;
  window.__webscan_state.target = target;
  renderAll();
});

// ---------- Exports ----------
document.getElementById('export-csv').addEventListener('click', async ()=>{
  const state = window.__webscan_state || {};
  if(!state.target) return alert('Run a scan first');
  const res = await fetch('/export/csv',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:state.target, passive:state.passive||[], active:state.active||{}})});
  const blob = await res.blob(); 
  const url = URL.createObjectURL(blob); 
  const a = document.createElement('a'); 
  a.href=url; 
  a.download = `webscan_${state.target}.csv`; 
  document.body.appendChild(a); 
  a.click(); 
  a.remove();
});

document.getElementById('export-pdf').addEventListener('click', async ()=>{
  const state = window.__webscan_state || {};
  if(!state.target) return alert('Run a scan first');
  const res = await fetch('/export/pdf',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:state.target, passive:state.passive||[], active:state.active||{}})});
  const blob = await res.blob(); 
  const url = URL.createObjectURL(blob); 
  const a = document.createElement('a'); 
  a.href=url; 
  a.download = `webscan_${state.target}.pdf`; 
  document.body.appendChild(a); 
  a.click(); 
  a.remove();
});

window.addEventListener('load', ()=> { 
  hideScanning(); // make 100% sure hidden on page load
  setTimeout(renderAll, 200); 
});
