/* static/js/reutilizaveis/welcome.js */
(function () {
    'use strict';

    const ov = document.getElementById('msWelcomeOverlay');
    if (!ov) return;

    /* ══ WARP STARS ══════════════════════════════════════════════════════════ */
    (function initStars() {
        const canvas = document.getElementById('msStarsCanvas');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const N = 280;
        let W, H, stars;

        function resize() {
            W = canvas.width = window.innerWidth;
            H = canvas.height = window.innerHeight;
        }

        function makeStars() {
            stars = Array.from({ length: N }, () => ({
                x: (Math.random() - .5) * (W || 1200),
                y: (Math.random() - .5) * (H || 800),
                z: Math.random() * (W || 1200),
                pz: W || 1200,
            }));
        }

        function resetStar(s) {
            s.x = (Math.random() - .5) * W;
            s.y = (Math.random() - .5) * H;
            s.z = W;
            s.pz = W;
        }

        // Duração da aceleração reduzida para 3500ms (3.5 segundos)
        const DUR = 3500;
        let t0 = null;

        function draw(ts) {
            if (!t0) t0 = ts;
            const p = Math.min((ts - t0) / DUR, 1);
            
            // Aumentei o multiplicador de velocidade (de 18 para 25) para o efeito ficar mais rápido!
            const speed = p < .4
                ? 0.3 + 5 * (p / .4)
                : 0.3 + 25 * ((p - .4) / .6);

            ctx.fillStyle = 'rgba(6,8,15,0.2)';
            ctx.fillRect(0, 0, W, H);

            const cx = W / 2, cy = H / 2;

            for (const s of stars) {
                s.pz = s.z;
                s.z = Math.max(s.z - speed, 0.1);

                const sx = (s.x / s.z) * W + cx;
                const sy = (s.y / s.z) * H + cy;
                const spx = (s.x / s.pz) * W + cx;
                const spy = (s.y / s.pz) * H + cy;

                if (sx < 0 || sx > W || sy < 0 || sy > H) { resetStar(s); continue; }

                const sz = Math.max((1 - s.z / W) * 3.2, 0.3);
                const sa = Math.min((1 - s.z / W) * 1.5, 1);

                ctx.beginPath();
                ctx.moveTo(spx, spy);
                ctx.lineTo(sx, sy);
                ctx.strokeStyle = `rgba(180,210,255,${sa.toFixed(2)})`;
                ctx.lineWidth = sz;
                ctx.stroke();

                ctx.beginPath();
                ctx.arc(sx, sy, sz * .5, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(220,235,255,${Math.min(sa * 1.3, 1).toFixed(2)})`;
                ctx.fill();
            }

            if (p < 1) requestAnimationFrame(draw);
        }

        resize();
        makeStars();
        window.addEventListener('resize', () => { resize(); makeStars(); });
        requestAnimationFrame(draw);
    })();

    /* ══ SAÍDA após 3.5s ═══════════════════════════════════════════════════════ */
    // Reduzido para fechar a tela após 3500ms (3.5 segundos)
    setTimeout(function () {
        ov.classList.add('ms-exit');
        ov.addEventListener('animationend', function () {
            ov.remove();
        }, { once: true });
    }, 3500);

})();