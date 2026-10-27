const API = {
  register: "/auth/register",
  login: "/auth/login",
  logout: "/auth/logout",
  predict: "/predict",
  history: "/history",
  stats: "/stats",
  alerts: "/alerts",
  dbHealth: "/health/database",
};
const $ = (id) => document.getElementById(id);

function applyTheme(theme) {
  const selected = theme === "dark" ? "dark" : "light";
  document.body.dataset.theme = selected;
  document.querySelectorAll(".theme-toggle").forEach((button) => {
    const icon = button.querySelector(".theme-icon");
    const label = button.querySelector(".theme-label");
    const goingDark = selected === "light";
    if (icon) icon.textContent = selected === "dark" ? "☀" : "☾";
    if (label) label.textContent = selected === "dark" ? "Açık tema" : "Koyu tema";
    button.setAttribute("aria-label", goingDark ? "Koyu temaya geç" : "Açık temaya geç");
    button.title = goingDark ? "Koyu temaya geç" : "Açık temaya geç";
  });
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = selected === "dark" ? "#222428" : "#f5f5f2";
}
function toggleTheme() {
  const next = document.body.dataset.theme === "dark" ? "light" : "dark";
  try { localStorage.setItem("phishguard-theme", next); } catch (_) {}
  applyTheme(next);
}
document.querySelectorAll(".theme-toggle").forEach((button) => button.addEventListener("click", toggleTheme));
try { applyTheme(localStorage.getItem("phishguard-theme") || "light"); }
catch (_) { applyTheme("light"); }


let authMode = "login";
let currentUser = null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function fmt(v){return new Intl.NumberFormat("tr-TR").format(Number(v||0));}
function pct(v){return `${Number(v||0).toLocaleString("tr-TR",{maximumFractionDigits:2})}%`;}
function showToast(message){
  const el=$("toast");el.textContent=message;el.classList.add("show");
  clearTimeout(showToast.timer);showToast.timer=setTimeout(()=>el.classList.remove("show"),3300);
}
async function fetchJson(url, options={}){
  const response=await fetch(url,{credentials:"same-origin",headers:{"Content-Type":"application/json",...(options.headers||{})},...options});
  let data={};try{data=await response.json();}catch{}
  if(!response.ok){const detail=data.detail||data.message||`İstek başarısız (${response.status})`;throw new Error(typeof detail==="string"?detail:JSON.stringify(detail));}
  return data;
}
function setAuthMode(mode){
  authMode=mode;
  const isRegister=mode==="register";
  $("login-tab").classList.toggle("active",!isRegister);
  $("register-tab").classList.toggle("active",isRegister);
  $("login-tab").setAttribute("aria-selected",String(!isRegister));
  $("register-tab").setAttribute("aria-selected",String(isRegister));
  $("auth-kicker").textContent=isRegister?"YENİ HESAP":"PHISHGUARD HESABI";
  $("auth-title").textContent=isRegister?"Hesabını oluştur.":"Tekrar hoş geldin.";
  $("auth-subtitle").textContent=isRegister?"PhishGuard hesabını oluştur ve analizlerini takip et.":"Hesabına giriş yaparak analizlerine devam et.";
  $("username-field").hidden=!isRegister;
  $("confirm-field").hidden=!isRegister;
  $("auth-username").required=isRegister;
  $("auth-confirm").required=isRegister;
  $("auth-password").autocomplete=isRegister?"new-password":"current-password";
  $("auth-submit-text").textContent=isRegister?"Hesap oluştur":"Giriş yap";
  $("auth-switch-copy").innerHTML=isRegister?'Zaten hesabın var mı? <button type="button" id="switch-login">Giriş yap</button>':'Henüz hesabın yok mu? <button type="button" id="switch-register">Hesap oluştur</button>';
  $("auth-error").hidden=true;
}
function enterApp(user){
  currentUser=user||{};
  $("auth-screen").hidden=true;$("app-screen").hidden=false;
  const name=currentUser.username||currentUser.email||"kullanıcı";
  $("welcome-user").textContent=name;
  $("user-avatar").textContent=String(name).slice(0,2).toUpperCase();
  showSection("overview");
  refreshDashboard();
}
function showAuth(){
  $("app-screen").hidden=true;$("auth-screen").hidden=false;
  $("auth-form").reset();setAuthMode("login");
}
function showSection(section){
  const names={overview:"Genel bakış",analyze:"URL analizi",history:"Analiz geçmişi",alerts:"Güvenlik uyarıları"};
  // The analysis form lives on the dashboard. Selecting URL Analysis keeps
  // that form visible and scrolls directly to it instead of opening an empty page.
  if(section==="analyze"){
    document.querySelectorAll(".page-section").forEach(el=>el.hidden=el.id!=="section-overview");
    setTimeout(()=>{$("analyze").scrollIntoView({behavior:"smooth",block:"start"});$("url-input").focus({preventScroll:true});},0);
  } else {
    document.querySelectorAll(".page-section").forEach(el=>el.hidden=el.id!==`section-${section}`);
  }
  document.querySelectorAll(".nav-item").forEach(el=>el.classList.toggle("active",el.dataset.section===section));
  $("page-title").textContent=names[section]||"Genel bakış";
  $("breadcrumb-current").textContent=(names[section]||"Genel bakış").toLocaleUpperCase("tr-TR");
}
function resultLabel(label){return Number(label)===0?"PHISHING":"LEGITIMATE";}
function safeDomain(url){try{return new URL(url.startsWith("http")?url:`https://${url}`).hostname;}catch{return url;}}
function formatDate(value){if(!value)return "—";const d=new Date(value);return Number.isNaN(d.getTime())?String(value):d.toLocaleString("tr-TR",{day:"2-digit",month:"2-digit",year:"numeric",hour:"2-digit",minute:"2-digit"});}
function confidenceOf(item){
  if(item.confidence_percent!==undefined&&item.confidence_percent!==null)return Number(item.confidence_percent);
  return Number(item.probability||0)*100;
}
function renderHistory(items,targetId="history-body"){
  const body=$(targetId);if(!body)return;
  if(!Array.isArray(items)||!items.length){body.innerHTML='<tr><td colspan="5" class="table-message">Henüz analiz kaydı bulunamadı.</td></tr>';if(targetId==="history-body")$("history-count").textContent="Gösterilecek kayıt yok";return;}
  body.innerHTML=items.map(item=>{
    const label=Number(item.predicted_label??item.prediction),bad=label===0,confidence=Math.max(0,Math.min(100,confidenceOf(item)));
    const url=item.url||"",domain=item.domain_name||item.full_domain||safeDomain(url),sev=String(item.severity||"").toLowerCase();
    const severity=sev|| (bad?(confidence>=85?"high":confidence>=60?"medium":"low"):"—");
    const sevLabel=({high:"Yüksek",medium:"Orta",low:"Düşük","—":"—"})[severity]||escapeHtml(severity);
    return `<tr><td class="url-cell"><span class="url-main" title="${escapeHtml(url)}">${escapeHtml(url||domain)}</span><span class="url-domain">${escapeHtml(domain)}</span></td><td><span class="pill ${bad?"phishing":"legitimate"}">${bad?"PHISHING":"LEGITIMATE"}</span></td><td class="confidence-cell"><div class="confidence-value"><span>Güven</span><b>${pct(confidence)}</b></div><div class="mini-track"><span class="${bad?"high-risk":""}" style="width:${confidence}%"></span></div></td><td><span class="severity ${severity}">${sevLabel}</span></td><td class="table-date">${escapeHtml(formatDate(item.predicted_at||item.submitted_at))}</td></tr>`;
  }).join("");
  if(targetId==="history-body")$("history-count").textContent=`${fmt(items.length)} kayıt gösteriliyor`;
}
function renderAlerts(items){
  $("sidebar-alert-count").textContent=fmt(items.length);
  const root=$("alerts-list");if(!root)return;
  if(!items.length){root.innerHTML='<div class="surface table-message">Şu anda listelenecek şüpheli analiz uyarısı yok.</div>';return;}
  root.innerHTML=items.map(item=>{
    const severity=String(item.severity||"low").toLowerCase(),confidence=item.confidence_percent??Number(item.probability||0)*100;
    return `<article class="alert-item"><div class="alert-symbol">⚑</div><div class="alert-copy"><strong title="${escapeHtml(item.url||item.domain_name)}">${escapeHtml(item.domain_name||item.url||"Şüpheli URL")}</strong><small>${escapeHtml(item.reason||"Model tarafından phishing olarak sınıflandırıldı.")}</small></div><div class="alert-meta"><span class="severity ${severity}">${severity==="high"?"YÜKSEK":severity==="medium"?"ORTA":"DÜŞÜK"}</span><small>${pct(confidence)}</small></div></article>`;
  }).join("");
}
async function loadStats(){
  try{const d=await fetchJson(API.stats);$("stat-total").textContent=fmt(d.total_analyses);$("stat-phishing").textContent=fmt(d.phishing);$("stat-legitimate").textContent=fmt(d.legitimate);$("stat-alerts").textContent=fmt(d.unreviewed_alerts);$("sidebar-alert-count").textContent=fmt(d.unreviewed_alerts);}
  catch(e){["stat-total","stat-phishing","stat-legitimate","stat-alerts"].forEach(id=>$(id).textContent="—");console.warn("İstatistikler alınamadı",e);}
}
async function loadHistory(){
  try{const d=await fetchJson(API.history);const items=d.items||[];renderHistory(items,"history-body");renderHistory(items,"history-body-full");}
  catch(e){["history-body","history-body-full"].forEach(id=>{if($(id))$(id).innerHTML=`<tr><td colspan="5" class="table-message">Geçmiş alınamadı: ${escapeHtml(e.message)}</td></tr>`;});if($("history-count"))$("history-count").textContent="Bağlantı hatası";}
}
async function loadAlerts(){
  try{const d=await fetchJson(API.alerts);renderAlerts(d.items||[]);}
  catch(e){if($("alerts-list"))$("alerts-list").innerHTML=`<div class="surface table-message">Uyarılar alınamadı: ${escapeHtml(e.message)}</div>`;}
}
async function checkDatabase(){
  try{await fetchJson(API.dbHealth);$("system-status-text").textContent="SQL Server bağlantısı aktif";$("db-state").textContent="Bağlı";}
  catch(e){$("system-status-text").textContent="Veritabanı bağlantısı kontrol edilmeli";$("db-state").textContent="Kontrol gerekli";console.warn("DB kontrolü",e);}
}
async function refreshDashboard(){
  if($("refresh-button")){$("refresh-button").disabled=true;$("refresh-button").textContent="Yükleniyor…";}
  await Promise.all([loadStats(),loadHistory(),loadAlerts(),checkDatabase()]);
  if($("refresh-button")){$("refresh-button").disabled=false;$("refresh-button").textContent="↻ Yenile";}
}
function showResult(d){
  const bad=Number(d.prediction)===0,phishing=Number(d.phishing_probability||0),legitimate=Number(d.legitimate_probability||0),confidence=bad?phishing:legitimate;
  $("result-title").textContent=bad?"Şüpheli bağlantı tespit edildi":"Bağlantı meşru görünüyor";
  $("result-badge").textContent=bad?"PHISHING":"LEGITIMATE";$("result-badge").className=`result-badge${bad?" danger":""}`;
  $("result-url").textContent=d.url||"";$("result-phishing").textContent=pct(phishing);$("result-legitimate").textContent=pct(legitimate);
  $("phishing-bar").style.width=`${Math.max(0,Math.min(100,phishing))}%`;$("legitimate-bar").style.width=`${Math.max(0,Math.min(100,legitimate))}%`;
  $("result-domain").textContent=`Domain: ${d.full_domain||safeDomain(d.url||"")}`;$("result-confidence").textContent=`Tahmin güveni: ${pct(confidence)}`;$("result-card").hidden=false;
}
$("login-tab").addEventListener("click",()=>setAuthMode("login"));
$("register-tab").addEventListener("click",()=>setAuthMode("register"));
$("auth-switch-copy").addEventListener("click",e=>{if(e.target.id==="switch-register")setAuthMode("register");if(e.target.id==="switch-login")setAuthMode("login");});
$("auth-form").addEventListener("submit",async e=>{
  e.preventDefault();const err=$("auth-error"),btn=$("auth-submit");err.hidden=true;
  const email=$("auth-email").value.trim(),password=$("auth-password").value;
  if(authMode==="register"){
    if(password!==$("auth-confirm").value){err.textContent="Şifreler eşleşmiyor.";err.hidden=false;return;}
    const username=$("auth-username").value.trim();
    btn.disabled=true;$("auth-submit-text").textContent="Hesap oluşturuluyor…";
    try{
      const d=await fetchJson(API.register,{method:"POST",body:JSON.stringify({username,email,password})});
      showToast(d.message||"Hesap oluşturuldu. Şimdi giriş yapabilirsin.");setAuthMode("login");$("auth-email").value=email;$("auth-password").value="";
    }catch(error){err.textContent=`Kayıt başarısız: ${error.message}`;err.hidden=false;}
    finally{btn.disabled=false;$("auth-submit-text").textContent=authMode==="register"?"Hesap oluştur":"Giriş yap";}
  }else{
    btn.disabled=true;$("auth-submit-text").textContent="Giriş yapılıyor…";
    try{
      const d=await fetchJson(API.login,{method:"POST",body:JSON.stringify({email,password})});
      // Prefer server-managed HttpOnly cookies. This UI does not store passwords or tokens in localStorage.
      enterApp(d.user||{email,username:d.username});showToast("Başarıyla giriş yapıldı.");
    }catch(error){err.textContent=`Giriş başarısız: ${error.message}`;err.hidden=false;}
    finally{btn.disabled=false;$("auth-submit-text").textContent="Giriş yap";}
  }
});
$("logout-button").addEventListener("click",async()=>{
  try{await fetchJson(API.logout,{method:"POST",body:"{}"});}catch(e){console.warn("Oturum kapatma isteği:",e.message);}
  currentUser=null;showAuth();showToast("Oturum kapatıldı.");
});
document.querySelectorAll(".nav-item").forEach(button=>button.addEventListener("click",()=>showSection(button.dataset.section)));
$("refresh-button").addEventListener("click",refreshDashboard);
$("analyze-form").addEventListener("submit",async e=>{
  e.preventDefault();const url=$("url-input").value.trim();if(!url)return;
  const btn=$("analyze-button"),err=$("form-error");err.hidden=true;btn.disabled=true;btn.querySelector(".button-label").textContent="Analiz ediliyor…";
  try{const d=await fetchJson(API.predict,{method:"POST",body:JSON.stringify({url})});showResult(d);showToast(d.database?.saved?"Analiz tamamlandı ve kaydedildi.":"Analiz tamamlandı.");await Promise.all([loadStats(),loadHistory(),loadAlerts()]);}
  catch(error){err.textContent=`Analiz başarısız: ${error.message}`;err.hidden=false;showToast("Analiz tamamlanamadı.");}
  finally{btn.disabled=false;btn.querySelector(".button-label").textContent="Analiz et";}
});
async function bootstrapAuth() {
  try {
    const data = await fetchJson("/auth/me");
    enterApp(data.user);
  } catch {
    showAuth();
  }
}
bootstrapAuth();
