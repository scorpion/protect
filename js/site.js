(function () {
  "use strict";

  var toggle = document.querySelector(".nav-toggle");
  var links = document.querySelector(".nav-links");
  if (toggle && links) {
    toggle.addEventListener("click", function () {
      var open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  document.querySelectorAll(".copy-btn[data-copy-target]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = document.getElementById(btn.getAttribute("data-copy-target"));
      if (!target) return;
      var text = target.innerText;
      var reset = function () {
        setTimeout(function () {
          btn.textContent = "copy";
        }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
          btn.textContent = "copied";
          reset();
        });
      } else {
        btn.textContent = "copied";
        reset();
      }
    });
  });

  var term = document.querySelector("[data-term-lines]");
  if (term) {
    var lines = Array.prototype.slice.call(term.children);
    lines.forEach(function (line, i) {
      line.style.animationDelay = i * 0.16 + "s";
    });
  }

  // ---------- animated data-flow diagram ----------
  (function () {
    var flow = document.querySelector(".flow");
    var row = flow && flow.querySelector(".flow-row");
    if (!flow || !row) return;

    var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotion || typeof window.requestAnimationFrame !== "function") return;

    var canvas = document.createElement("canvas");
    canvas.className = "flow-canvas";
    flow.insertBefore(canvas, flow.firstChild);
    var ctx = canvas.getContext("2d");
    if (!ctx) return;

    var boxes = row.querySelectorAll(".flow-step .flow-box");
    var boxClient = boxes[0];
    var boxDecode = boxes[1];
    var boxActionable = boxes[2];
    var boxAllow = row.querySelector(".flow-box.allow");
    var boxBlock = row.querySelector(".flow-box.block");
    if (!boxClient || !boxDecode || !boxActionable || !boxAllow || !boxBlock) return;

    var dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    var width = 0;
    var height = 0;

    function edgePoint(fromEl, toEl) {
      var a = fromEl.getBoundingClientRect();
      var b = toEl.getBoundingClientRect();
      var host = flow.getBoundingClientRect();
      var horizontal = Math.abs((b.left + b.right) / 2 - (a.left + a.right) / 2)
        >= Math.abs((b.top + b.bottom) / 2 - (a.top + a.bottom) / 2);
      var from, to;
      if (horizontal) {
        var leftToRight = b.left >= a.left;
        from = { x: leftToRight ? a.right : a.left, y: (a.top + a.bottom) / 2 };
        to = { x: leftToRight ? b.left : b.right, y: (b.top + b.bottom) / 2 };
      } else {
        var topToBottom = b.top >= a.top;
        from = { x: (a.left + a.right) / 2, y: topToBottom ? a.bottom : a.top };
        to = { x: (b.left + b.right) / 2, y: topToBottom ? b.top : b.bottom };
      }
      return {
        from: { x: from.x - host.left, y: from.y - host.top },
        to: { x: to.x - host.left, y: to.y - host.top },
      };
    }

    function curvePoints(p0, p3, n) {
      var c1 = { x: p0.x + (p3.x - p0.x) * 0.5, y: p0.y };
      var c2 = { x: p0.x + (p3.x - p0.x) * 0.5, y: p3.y };
      var pts = [];
      for (var i = 0; i <= n; i++) {
        var t = i / n;
        var mt = 1 - t;
        pts.push({
          x: mt * mt * mt * p0.x + 3 * mt * mt * t * c1.x + 3 * mt * t * t * c2.x + t * t * t * p3.x,
          y: mt * mt * mt * p0.y + 3 * mt * mt * t * c1.y + 3 * mt * t * t * c2.y + t * t * t * p3.y,
        });
      }
      return pts;
    }

    var segClientDecode, segDecodeAction, segActionAllow, segActionBlock;
    var pathAllow, pathBlock, branchStart;

    function layout() {
      var rect = flow.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      canvas.style.width = width + "px";
      canvas.style.height = height + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      var e1 = edgePoint(boxClient, boxDecode);
      var e2 = edgePoint(boxDecode, boxActionable);
      var e3 = edgePoint(boxActionable, boxAllow);
      var e4 = edgePoint(boxActionable, boxBlock);

      segClientDecode = curvePoints(e1.from, e1.to, 24);
      segDecodeAction = curvePoints(e2.from, e2.to, 24);
      segActionAllow = curvePoints(e3.from, e3.to, 24);
      segActionBlock = curvePoints(e4.from, e4.to, 24);

      pathAllow = segClientDecode.concat(segDecodeAction.slice(1), segActionAllow.slice(1));
      pathBlock = segClientDecode.concat(segDecodeAction.slice(1), segActionBlock.slice(1));
      branchStart = (segClientDecode.length + segDecodeAction.length - 2) / (pathAllow.length - 1);
    }

    layout();

    var ro = typeof ResizeObserver === "function" ? new ResizeObserver(layout) : null;
    if (ro) ro.observe(flow);
    window.addEventListener("resize", layout);
    window.addEventListener("load", layout);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(layout);

    var particles = [];
    var lastSpawn = 0;
    var spawnInterval = 550;
    var running = true;
    var lastTime = null;

    function spawn(now) {
      var toBlock = Math.random() < 0.22;
      particles.push({
        path: toBlock ? pathBlock : pathAllow,
        toBlock: toBlock,
        t: 0,
        speed: 0.00042 + Math.random() * 0.00018,
      });
      lastSpawn = now;
    }

    function pulse(el, cls) {
      el.classList.remove(cls);
      void el.offsetWidth;
      el.classList.add(cls);
      setTimeout(function () {
        el.classList.remove(cls);
      }, 500);
    }

    function drawLine(pts, color, dashOffset) {
      ctx.beginPath();
      ctx.moveTo(pts[0].x, pts[0].y);
      for (var i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.setLineDash([5, 7]);
      ctx.lineDashOffset = dashOffset;
      ctx.stroke();
    }

    var dashPhase = 0;

    function frame(now) {
      if (!running) return;
      if (lastTime === null) lastTime = now;
      var dt = now - lastTime;
      lastTime = now;

      ctx.clearRect(0, 0, width, height);

      dashPhase -= dt * 0.02;
      ctx.save();
      ctx.globalAlpha = 0.35;
      drawLine(segClientDecode, "rgba(153, 112, 235, 0.55)", dashPhase);
      drawLine(segDecodeAction, "rgba(153, 112, 235, 0.55)", dashPhase);
      drawLine(segActionAllow, "rgba(74, 222, 128, 0.45)", dashPhase);
      drawLine(segActionBlock, "rgba(251, 113, 133, 0.45)", dashPhase);
      ctx.restore();
      ctx.setLineDash([]);

      if (now - lastSpawn > spawnInterval) spawn(now);

      for (var i = particles.length - 1; i >= 0; i--) {
        var p = particles[i];
        p.t += p.speed * dt;
        if (p.t >= 1) {
          pulse(p.toBlock ? boxBlock : boxAllow, p.toBlock ? "pulse-block" : "pulse-allow");
          particles.splice(i, 1);
          continue;
        }
        var idx = p.t * (p.path.length - 1);
        var i0 = Math.floor(idx);
        var frac = idx - i0;
        var a = p.path[i0];
        var b = p.path[Math.min(i0 + 1, p.path.length - 1)];
        var x = a.x + (b.x - a.x) * frac;
        var y = a.y + (b.y - a.y) * frac;

        var inBranch = p.t > branchStart;
        var color = inBranch ? (p.toBlock ? "251, 113, 133" : "74, 222, 128") : "153, 112, 235";

        ctx.beginPath();
        ctx.fillStyle = "rgba(" + color + ", 1)";
        ctx.shadowColor = "rgba(" + color + ", 0.9)";
        ctx.shadowBlur = 8;
        ctx.arc(x, y, 2.6, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      requestAnimationFrame(frame);
    }

    requestAnimationFrame(frame);

    var io = typeof IntersectionObserver === "function"
      ? new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          var wasRunning = running;
          running = entry.isIntersecting && !document.hidden;
          if (running && !wasRunning) {
            lastTime = null;
            requestAnimationFrame(frame);
          }
        });
      }, { threshold: 0.05 })
      : null;
    if (io) io.observe(flow);

    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        running = false;
      } else {
        var rect = flow.getBoundingClientRect();
        var visible = rect.bottom > 0 && rect.top < (window.innerHeight || document.documentElement.clientHeight);
        if (visible && !running) {
          running = true;
          lastTime = null;
          requestAnimationFrame(frame);
        }
      }
    });
  })();
})();
