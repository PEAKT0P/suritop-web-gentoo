<?php
$ip = $_SERVER["HTTP_HOST"] ?? "";
?>
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" id="viewportMeta" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Suritop-Web Dashboard</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden;background:#0a0e14;font-family:"JetBrains Mono",monospace}

/* Базовый каркас */
.frame{display:flex;height:100vh;width:100vw;flex-direction:row;}
.panel{position:relative;overflow:hidden;border:1px solid rgba(255,255,255,0.04);background:#0a0e14;}
.panel iframe{width:100%;height:100%;border:none;background:#0a0e14;transition:opacity 0.2s;}
.panel-label{position:absolute;top:4px;left:8px;z-index:10;font-size:9px;font-weight:700;letter-spacing:1.5px;color:rgba(255,255,255,0.35);pointer-events:none;text-transform:uppercase}

/* Панели */
.left{flex:0 0 50%;display:flex;flex-direction:column;min-width:100px;}
.right{flex:1;display:flex;flex-direction:column;position:relative;min-width:100px;}
.right-top{flex:1;position:relative;overflow:hidden;min-height:150px;}
.right-bottom{flex:1;position:relative;overflow:hidden;min-height:150px;}

/* Сплиттеры */
.h-splitter{width:6px;cursor:col-resize;background:rgba(255,59,48,0.15);flex-shrink:0;transition:background 0.2s;z-index:50;}
.h-splitter:hover,.h-splitter.active{background:rgba(255,59,48,0.6)}
.v-splitter{height:6px;cursor:row-resize;background:rgba(255,59,48,0.15);flex-shrink:0;transition:background 0.2s;z-index:50;}
.v-splitter:hover,.v-splitter.active{background:rgba(255,59,48,0.6)}

.logo{position:fixed;top:6px;right:12px;z-index:100;font-size:8px;letter-spacing:2px;color:rgba(255,59,48,0.3);font-weight:700;pointer-events:none}

/* Фикс для плавного ресайза */
body.is-dragging iframe { pointer-events: none; opacity: 0.8; }
body.is-dragging { cursor: grabbing !important; }

/* ─── Панель управления (Layout & Scale) ─── */
.top-controls {
    position: fixed;
    top: 6px;
    left: 50%;
    transform: translateX(-50%);
    z-index: 1000;
    display: flex;
    gap: 8px;
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    background: rgba(15, 23, 42, 0.6);
    padding: 4px;
    border-radius: 14px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
}

.ctrl-btn {
    background: transparent;
    border: 1px solid transparent;
    color: #c5cdd8;
    padding: 4px 12px;
    border-radius: 10px;
    font-size: 10px;
    font-weight: 700;
    cursor: pointer;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    transition: 0.2s;
}
.ctrl-btn:hover { background: rgba(255, 255, 255, 0.1); color: #fff; }
.ctrl-btn.active-mode { background: rgba(0, 212, 170, 0.15); color: #00d4aa; border-color: rgba(0, 212, 170, 0.3); }

/* ─── Режим "ПОДРЯД" (Вертикальная колонка) ─── */
.frame.layout-col { flex-direction: column; overflow-y: auto; overflow-x: hidden; }
.frame.layout-col .left { 
    flex: none !important; width: 100% !important; height: 50vh !important; 
    border-right: none; border-bottom: 2px solid rgba(255,59,48,0.3); 
}
.frame.layout-col .right { flex: none !important; width: 100% !important; height: auto !important; }
.frame.layout-col .right-top { flex: none !important; height: 50vh !important; border-bottom: 2px solid rgba(255,59,48,0.3); }
.frame.layout-col .right-bottom { flex: none !important; height: 50vh !important; }
.frame.layout-col .h-splitter, .frame.layout-col .v-splitter { display: none; }
</style>
</head>
<body>

<div class="logo">SURITOP</div>

<div class="top-controls">
  <button class="ctrl-btn" id="btnToggleLayout" title="Переключить сетку">Вид: Сплит ◫</button>
  <button class="ctrl-btn" id="btnToggleScale" title="Форсировать ПК режим">Масштаб: Авто 📱</button>
</div>

<div class="frame" id="mainFrame">
  <div class="left panel" id="leftPanel">
    <span class="panel-label">&#x2694; Threat Map</span>
    <iframe src="attackmap/" loading="lazy"></iframe>
  </div>
  
  <div class="h-splitter" id="hSplitter"></div>
  
  <div class="right" id="rightPanel">
    <div class="right-top panel" id="topPanel">
      <span class="panel-label">&#x1f4ca; Admin Stats</span>
      <iframe src="admin_stats.php" loading="lazy"></iframe>
    </div>
    
    <div class="v-splitter" id="vSplitter"></div>
    
    <div class="right-bottom panel" id="bottomPanel">
      <span class="panel-label">&#x26e2; Firewall</span>
      <iframe src="iptables/" loading="lazy"></iframe>
    </div>
  </div>
</div>

<script>
(function(){
  const frame = document.getElementById("mainFrame");
  const btnLayout = document.getElementById("btnToggleLayout");
  const btnScale = document.getElementById("btnToggleScale");
  const viewportMeta = document.getElementById("viewportMeta");
  
  // --- Загрузка состояний из localStorage ---
  let isColMode = localStorage.getItem("suritop_layout") === "col";
  let isDesktopMode = localStorage.getItem("suritop_scale") === "desktop";
  
  // --- Управление Видом (Layout) ---
  function applyLayout() {
    if (isColMode) {
      frame.classList.add("layout-col");
      btnLayout.classList.add("active-mode");
      btnLayout.innerHTML = "Вид: Подряд ▼";
    } else {
      frame.classList.remove("layout-col");
      btnLayout.classList.remove("active-mode");
      btnLayout.innerHTML = "Вид: Сплит ◫";
    }
  }
  
  btnLayout.addEventListener("click", () => {
    isColMode = !isColMode;
    localStorage.setItem("suritop_layout", isColMode ? "col" : "split");
    applyLayout();
  });

  // --- Управление Масштабом (Viewport Scale) ---
  function applyScale() {
    if (isDesktopMode) {
      // Форсируем ПК режим (телефон думает, что экран 1280px шириной)
      viewportMeta.setAttribute("content", "width=1280, initial-scale=0.3, maximum-scale=3.0, user-scalable=yes");
      btnScale.classList.add("active-mode");
      btnScale.innerHTML = "Масштаб: ПК 🖥️";
    } else {
      // Стандартный адаптивный мобильный режим
      viewportMeta.setAttribute("content", "width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no");
      btnScale.classList.remove("active-mode");
      btnScale.innerHTML = "Масштаб: Авто 📱";
    }
  }

  btnScale.addEventListener("click", () => {
    isDesktopMode = !isDesktopMode;
    localStorage.setItem("suritop_scale", isDesktopMode ? "desktop" : "auto");
    applyScale();
  });

  // Применяем настройки при старте
  applyLayout();
  applyScale();


  // --- Логика сплиттеров (работает только в Сплит-режиме) ---
  const left = document.getElementById("leftPanel"),
        hSp = document.getElementById("hSplitter"),
        vSp = document.getElementById("vSplitter"),
        top = document.getElementById("topPanel"),
        body = document.body;

  let raf;

  // Горизонтальный сплиттер (Мышь)
  hSp.addEventListener("mousedown", function(e){
    if (isColMode) return;
    e.preventDefault();
    hSp.classList.add("active"); body.classList.add("is-dragging");
    let startX = e.clientX, startW = left.offsetWidth;
    
    function onMove(ev){
      if(raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        let nw = Math.max(100, startW + (ev.clientX - startX));
        nw = Math.min(nw, window.innerWidth - 100);
        left.style.flex = "0 0 " + nw + "px";
      });
    }
    function onUp(){
      hSp.classList.remove("active"); body.classList.remove("is-dragging");
      document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp);
    }
    document.addEventListener("mousemove", onMove); document.addEventListener("mouseup", onUp);
  });
  
  // Горизонтальный сплиттер (Тач)
  hSp.addEventListener("touchstart", function(e){
    if (isColMode) return;
    hSp.classList.add("active"); body.classList.add("is-dragging");
    let touch = e.touches[0];
    let startX = touch.clientX, startW = left.offsetWidth;
    
    function onMove(ev){
      let touchMove = ev.touches[0];
      if(raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        let nw = Math.max(100, startW + (touchMove.clientX - startX));
        nw = Math.min(nw, window.innerWidth - 100);
        left.style.flex = "0 0 " + nw + "px";
      });
    }
    function onUp(){
      hSp.classList.remove("active"); body.classList.remove("is-dragging");
      document.removeEventListener("touchmove", onMove); document.removeEventListener("touchend", onUp);
    }
    document.addEventListener("touchmove", onMove, {passive: false}); document.addEventListener("touchend", onUp);
  });

  // Вертикальный сплиттер (Мышь)
  vSp.addEventListener("mousedown", function(e){
    if (isColMode) return;
    e.preventDefault();
    vSp.classList.add("active"); body.classList.add("is-dragging");
    let startY = e.clientY, startH = top.offsetHeight;
    
    function onMove(ev){
      if(raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        let nh = Math.max(100, startH + (ev.clientY - startY));
        nh = Math.min(nh, top.parentElement.offsetHeight - 100);
        top.style.flex = "none"; top.style.height = nh + "px";
      });
    }
    function onUp(){
      vSp.classList.remove("active"); body.classList.remove("is-dragging");
      document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp);
    }
    document.addEventListener("mousemove", onMove); document.addEventListener("mouseup", onUp);
  });
  
  // Вертикальный сплиттер (Тач)
  vSp.addEventListener("touchstart", function(e){
    if (isColMode) return;
    vSp.classList.add("active"); body.classList.add("is-dragging");
    let touch = e.touches[0];
    let startY = touch.clientY, startH = top.offsetHeight;
    
    function onMove(ev){
      let touchMove = ev.touches[0];
      if(raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        let nh = Math.max(100, startH + (touchMove.clientY - startY));
        nh = Math.min(nh, top.parentElement.offsetHeight - 100);
        top.style.flex = "none"; top.style.height = nh + "px";
      });
    }
    function onUp(){
      vSp.classList.remove("active"); body.classList.remove("is-dragging");
      document.removeEventListener("touchmove", onMove); document.removeEventListener("touchend", onUp);
    }
    document.addEventListener("touchmove", onMove, {passive: false}); document.addEventListener("touchend", onUp);
  });

})();
</script>
</body>
</html>
