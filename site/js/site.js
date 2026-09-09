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
})();
