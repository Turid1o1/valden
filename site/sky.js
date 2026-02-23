(() => {
  const canvas = document.getElementById("star-canvas");
  if (!canvas) {
    return;
  }

  const context = canvas.getContext("2d");
  if (!context) {
    return;
  }

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  let width = 0;
  let height = 0;
  let dpr = 1;
  let stars = [];
  let meteors = [];
  let showerCooldownMs = 0;
  let lastTime = 0;

  const tonePalette = [
    [255, 255, 255],
    [170, 216, 255],
    [255, 223, 176],
  ];

  const createStar = () => {
    const depth = Math.random();
    const tone = tonePalette[Math.floor(Math.random() * tonePalette.length)];

    return {
      x: Math.random() * width,
      y: Math.random() * height,
      radius: 0.35 + Math.random() * 1.8,
      depth: 0.15 + depth * 1.2,
      alpha: 0.16 + Math.random() * 0.78,
      twinkleSpeed: 0.45 + Math.random() * 1.9,
      twinkleOffset: Math.random() * Math.PI * 2,
      pulse: 0.7 + Math.random() * 1.3,
      tone,
    };
  };

  const resetCanvas = () => {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;

    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;

    context.setTransform(dpr, 0, 0, dpr, 0, 0);

    const starCount = Math.max(240, Math.min(980, Math.floor((width * height) / 4200)));
    stars = Array.from({ length: starCount }, createStar);

    meteors = [];
    showerCooldownMs = 0;
  };

  const spawnMeteor = () => {
    const fromLeft = Math.random() > 0.35;
    const angle = fromLeft ? 0.46 + Math.random() * 0.24 : 2.45 + Math.random() * 0.23;
    const speed = 380 + Math.random() * 420;

    return {
      x: fromLeft ? -170 + Math.random() * (width * 0.5) : width + 20 + Math.random() * 140,
      y: -80 + Math.random() * (height * 0.45),
      vx: Math.cos(angle) * speed,
      vy: Math.sin(angle) * speed,
      life: 0,
      ttl: 0.95 + Math.random() * 0.95,
      length: 130 + Math.random() * 210,
      alpha: 0.55 + Math.random() * 0.4,
    };
  };

  const updateScene = (deltaMs, seconds) => {
    const driftX = deltaMs * 0.0033;
    const driftY = deltaMs * 0.0012;

    for (const star of stars) {
      if (!reduceMotion) {
        star.x += driftX * star.depth;
        star.y += driftY * star.depth;

        if (star.x > width + 2) star.x = -2;
        if (star.y > height + 2) star.y = -2;
      }

      const baseTwinkle = 0.5 + 0.5 * Math.sin(seconds * star.twinkleSpeed + star.twinkleOffset);
      const microTwinkle = 0.5 + 0.5 * Math.sin(seconds * star.pulse * 3.2 + star.twinkleOffset * 1.8);
      star.currentAlpha = star.alpha * (0.44 + 0.4 * baseTwinkle + 0.16 * microTwinkle);
    }

    if (!reduceMotion) {
      showerCooldownMs = Math.max(0, showerCooldownMs - deltaMs);

      const spawnChance = deltaMs * 0.00016;
      if (Math.random() < spawnChance && meteors.length < 10) {
        meteors.push(spawnMeteor());
      }

      const showerChance = deltaMs * 0.000018;
      if (showerCooldownMs <= 0 && Math.random() < showerChance && meteors.length < 11) {
        const burstCount = 2 + Math.floor(Math.random() * 3);
        for (let burst = 0; burst < burstCount; burst += 1) {
          meteors.push(spawnMeteor());
        }
        showerCooldownMs = 3400 + Math.random() * 4800;
      }

      for (let index = meteors.length - 1; index >= 0; index -= 1) {
        const meteor = meteors[index];
        meteor.life += deltaMs / 1000;
        meteor.x += (meteor.vx * deltaMs) / 1000;
        meteor.y += (meteor.vy * deltaMs) / 1000;

        if (meteor.life >= meteor.ttl) {
          meteors.splice(index, 1);
        }
      }
    }
  };

  const drawStars = () => {
    for (const star of stars) {
      const [r, g, b] = star.tone;
      context.fillStyle = `rgba(${r}, ${g}, ${b}, ${star.currentAlpha.toFixed(3)})`;
      context.beginPath();
      context.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
      context.fill();

      if (star.radius > 1.2) {
        context.fillStyle = `rgba(${r}, ${g}, ${b}, ${(star.currentAlpha * 0.08).toFixed(3)})`;
        context.beginPath();
        context.arc(star.x, star.y, star.radius * 2.8, 0, Math.PI * 2);
        context.fill();
      }

      if (star.radius > 1.6) {
        context.strokeStyle = `rgba(${r}, ${g}, ${b}, ${(star.currentAlpha * 0.24).toFixed(3)})`;
        context.lineWidth = 1;
        context.beginPath();
        context.moveTo(star.x - star.radius * 2.7, star.y);
        context.lineTo(star.x + star.radius * 2.7, star.y);
        context.moveTo(star.x, star.y - star.radius * 2.7);
        context.lineTo(star.x, star.y + star.radius * 2.7);
        context.stroke();
      }
    }
  };

  const drawMeteors = () => {
    for (const meteor of meteors) {
      const speed = Math.hypot(meteor.vx, meteor.vy) || 1;
      const dirX = meteor.vx / speed;
      const dirY = meteor.vy / speed;

      const tailX = meteor.x - dirX * meteor.length;
      const tailY = meteor.y - dirY * meteor.length;

      const gradient = context.createLinearGradient(meteor.x, meteor.y, tailX, tailY);
      gradient.addColorStop(0, `rgba(255, 235, 193, ${meteor.alpha.toFixed(3)})`);
      gradient.addColorStop(0.4, `rgba(150, 210, 255, ${(meteor.alpha * 0.45).toFixed(3)})`);
      gradient.addColorStop(1, "rgba(255, 255, 255, 0)");

      context.strokeStyle = gradient;
      context.lineWidth = 1.9 + (meteor.alpha - 0.55) * 1.2;
      context.beginPath();
      context.moveTo(meteor.x, meteor.y);
      context.lineTo(tailX, tailY);
      context.stroke();

      context.fillStyle = `rgba(255, 241, 213, ${(meteor.alpha * 0.7).toFixed(3)})`;
      context.beginPath();
      context.arc(meteor.x, meteor.y, 1.2, 0, Math.PI * 2);
      context.fill();
    }
  };

  const render = (timestamp) => {
    if (!lastTime) {
      lastTime = timestamp;
    }

    const deltaMs = Math.min(40, timestamp - lastTime);
    lastTime = timestamp;
    const seconds = timestamp / 1000;

    updateScene(deltaMs, seconds);

    context.clearRect(0, 0, width, height);
    drawStars();
    drawMeteors();

    requestAnimationFrame(render);
  };

  resetCanvas();

  if (reduceMotion) {
    updateScene(16, 0);
    context.clearRect(0, 0, width, height);
    drawStars();
  } else {
    requestAnimationFrame(render);
  }

  window.addEventListener("resize", resetCanvas);
})();
