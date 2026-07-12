const gallery = document.querySelector("#gallery");
const viewport = document.querySelector("#viewport");
const world = document.querySelector("#world");
const login = document.querySelector("#login");
const loginForm = document.querySelector("#loginForm");
const codeInput = document.querySelector("#codeInput");
const goButton = document.querySelector("#goButton");
const loginStatus = document.querySelector("#loginStatus");
const addButton = document.querySelector("#addButton");
const fileInput = document.querySelector("#fileInput");
const preview = document.querySelector("#preview");
const previewImage = document.querySelector("#previewImage");
const previewCaption = document.querySelector("#previewCaption");
const closePreview = document.querySelector("#closePreview");
const scrollHint = document.querySelector("#scrollHint");
const toast = document.querySelector("#toast");

const state = {
  images: [],
  csrf: sessionStorage.getItem("gallery_csrf") || "",
  columns: 5,
  rows: 6,
  gap: 24,
  tileWidth: 0,
  portraitHeight: 0,
  landscapeHeight: 0,
  rowPitch: 0,
  boardWidth: 0,
  boardHeight: 0,
  offsetX: 0,
  offsetY: 0,
  initialized: false,
  dragging: false,
  pointerX: 0,
  pointerY: 0,
  moved: false,
};

const encoder = new TextEncoder();

function bytesToBase64Url(bytes) {
  let binary = "";
  bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function makeProof(code, challenge) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: encoder.encode(challenge.salt),
      iterations: challenge.iterations,
    },
    material,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(challenge.nonce));
  return bytesToBase64Url(new Uint8Array(signature));
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.headers || {}),
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || `request_${response.status}`);
    error.status = response.status;
    throw error;
  }
  return data;
}

async function authenticate(code) {
  const challenge = await api("/api/auth/challenge");
  const proof = await makeProof(code, challenge);
  return api("/api/auth/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ nonce: challenge.nonce, proof }),
  });
}

async function loadImages() {
  const payload = await api("/api/images");
  state.images = payload.images;
  renderWorld(true);
}

async function enterGallery() {
  await loadImages();
  gallery.classList.add("is-visible");
  gallery.setAttribute("aria-hidden", "false");
  login.classList.add("is-hidden");
  window.setTimeout(() => scrollHint.classList.add("is-hidden"), 4200);
}

function setLoginError(message) {
  loginForm.classList.remove("is-error");
  void loginForm.offsetWidth;
  loginForm.classList.add("is-error");
  loginStatus.textContent = message;
  codeInput.value = "";
  codeInput.placeholder = "WRONG CODE";
  codeInput.focus();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const code = codeInput.value.replace(/\D/g, "");
  if (code.length !== 10) {
    setLoginError("Enter all 10 digits");
    return;
  }
  goButton.disabled = true;
  loginStatus.textContent = "";
  try {
    const result = await authenticate(code);
    state.csrf = result.csrf;
    sessionStorage.setItem("gallery_csrf", state.csrf);
    codeInput.value = "";
    await enterGallery();
  } catch (error) {
    setLoginError(error.message === "rate_limited" ? "Try again in one minute" : "Wrong code");
  } finally {
    goButton.disabled = false;
  }
});

codeInput.addEventListener("input", () => {
  const clean = codeInput.value.replace(/\D/g, "").slice(0, 10);
  if (codeInput.value !== clean) codeInput.value = clean;
  loginForm.classList.remove("is-error");
  loginStatus.textContent = "";
  codeInput.placeholder = "INPUT CODE";
});

function calculateLayout() {
  state.columns = window.innerWidth < 600 ? 3 : 5;
  state.gap = window.innerWidth < 600 ? 10 : 24;
  state.tileWidth = (window.innerWidth - state.gap * (state.columns - 1)) / state.columns;
  state.portraitHeight = state.tileWidth * (4 / 3);
  state.landscapeHeight = state.tileWidth * 0.75;
  state.rowPitch = state.portraitHeight - state.gap;
  state.rows = Math.max(5, Math.ceil(window.innerHeight / state.rowPitch) + 2);
  state.boardWidth = window.innerWidth;
  state.boardHeight = state.rows * state.rowPitch;
}

function tileImage(index) {
  return state.images[index % state.images.length];
}

function createTile(image, x, y, width, height, imageIndex) {
  const button = document.createElement("button");
  button.className = "gallery__tile";
  button.type = "button";
  button.setAttribute("aria-label", `Open ${image.name || "image"}`);
  button.dataset.imageIndex = String(imageIndex % state.images.length);
  button.style.cssText = `left:${x}px;top:${y}px;width:${width}px;height:${height}px`;
  const img = document.createElement("img");
  img.src = image.url;
  img.alt = "";
  img.loading = "eager";
  img.decoding = "async";
  button.append(img);
  return button;
}

function createBoard(boardColumn, boardRow) {
  const board = document.createElement("div");
  board.className = "gallery__board";
  board.style.cssText = `left:${boardColumn * state.boardWidth}px;top:${boardRow * state.boardHeight}px;width:${state.boardWidth}px;height:${state.boardHeight}px`;
  let imageIndex = boardRow * state.columns + boardColumn * 3;

  for (let row = 0; row < state.rows; row += 1) {
    const globalRow = boardRow * state.rows + row;
    for (let column = 0; column < state.columns; column += 1) {
      // Continue the checkerboard through board boundaries. Without the global
      // row, an odd-sized board could place two tall cards directly together
      // at the wrap seam.
      if ((globalRow + column) % 2 !== 0) continue;
      const image = tileImage(imageIndex);
      if (!image) continue;
      const isPortrait = image.height >= image.width;
      const displayPortrait = (imageIndex + globalRow) % 3 !== 1 ? isPortrait : !isPortrait;
      const height = displayPortrait ? state.portraitHeight : state.landscapeHeight;
      const x = column * (state.tileWidth + state.gap);
      const y = row * state.rowPitch + (state.portraitHeight - height) / 2;
      board.append(createTile(image, x, y, state.tileWidth, height, imageIndex));
      imageIndex += 1;
    }
  }
  return board;
}

function renderWorld(resetPosition = false) {
  calculateLayout();
  world.replaceChildren();
  if (!state.images.length) return;
  const fragment = document.createDocumentFragment();
  for (let row = 0; row < 3; row += 1) {
    for (let column = 0; column < 3; column += 1) {
      fragment.append(createBoard(column, row));
    }
  }
  world.append(fragment);
  world.style.width = `${state.boardWidth * 3}px`;
  world.style.height = `${state.boardHeight * 3}px`;
  if (resetPosition || !state.initialized) {
    state.offsetX = -state.boardWidth;
    state.offsetY = -state.boardHeight - state.rowPitch * 0.35;
    state.initialized = true;
  } else {
    normalizePosition();
  }
  paintPosition();
}

function wrap(value, size) {
  if (!size) return value;
  while (value > -size * 0.35) value -= size;
  while (value < -size * 1.65) value += size;
  return value;
}

function normalizePosition() {
  state.offsetX = wrap(state.offsetX, state.boardWidth);
  state.offsetY = wrap(state.offsetY, state.boardHeight);
}

function paintPosition() {
  world.style.transform = `translate3d(${state.offsetX}px, ${state.offsetY}px, 0)`;
}

function moveWorld(deltaX, deltaY) {
  state.offsetX += deltaX;
  state.offsetY += deltaY;
  normalizePosition();
  paintPosition();
  scrollHint.classList.add("is-hidden");
}

viewport.addEventListener(
  "wheel",
  (event) => {
    event.preventDefault();
    const horizontal = event.shiftKey && Math.abs(event.deltaX) < 1 ? event.deltaY : event.deltaX;
    const vertical = event.shiftKey ? event.deltaX : event.deltaY;
    moveWorld(-horizontal, -vertical);
  },
  { passive: false },
);

viewport.addEventListener("pointerdown", (event) => {
  if (event.button !== 0) return;
  state.dragging = true;
  state.moved = false;
  state.pointerX = event.clientX;
  state.pointerY = event.clientY;
  viewport.classList.add("is-dragging");
  viewport.setPointerCapture(event.pointerId);
});

viewport.addEventListener("pointermove", (event) => {
  if (!state.dragging) return;
  const deltaX = event.clientX - state.pointerX;
  const deltaY = event.clientY - state.pointerY;
  if (Math.abs(deltaX) + Math.abs(deltaY) > 3) state.moved = true;
  state.pointerX = event.clientX;
  state.pointerY = event.clientY;
  moveWorld(deltaX, deltaY);
});

function finishDrag(event) {
  state.dragging = false;
  viewport.classList.remove("is-dragging");
  if (viewport.hasPointerCapture(event.pointerId)) viewport.releasePointerCapture(event.pointerId);
}

viewport.addEventListener("pointerup", finishDrag);
viewport.addEventListener("pointercancel", finishDrag);

viewport.addEventListener("click", (event) => {
  if (state.moved) {
    state.moved = false;
    event.preventDefault();
    return;
  }
  const tile = event.target.closest(".gallery__tile");
  if (!tile) return;
  const image = state.images[Number(tile.dataset.imageIndex)];
  if (image) openPreview(image);
});

function openPreview(image) {
  previewImage.src = image.url;
  previewImage.alt = image.name || "Gallery image";
  previewCaption.textContent = image.name || "";
  preview.showModal();
}

function closePreviewDialog() {
  preview.close();
  previewImage.removeAttribute("src");
}

closePreview.addEventListener("click", closePreviewDialog);
preview.addEventListener("click", (event) => {
  if (event.target.classList.contains("preview__backdrop")) closePreviewDialog();
});

addButton.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", async () => {
  const file = fileInput.files?.[0];
  if (!file) return;
  if (!file.type.startsWith("image/")) {
    showToast("Choose an image file");
    return;
  }
  addButton.classList.add("is-uploading");
  addButton.disabled = true;
  try {
    const payload = await api("/api/images", {
      method: "POST",
      headers: {
        "Content-Type": file.type,
        "X-Filename": encodeURIComponent(file.name),
        "X-CSRF-Token": state.csrf,
      },
      body: file,
    });
    state.images.unshift(payload.image);
    renderWorld(false);
    showToast("Image added");
  } catch (error) {
    const messages = {
      file_too_large: "Image is larger than 15 MB",
      invalid_image: "Unsupported image format",
      invalid_csrf: "Session expired — reload the page",
    };
    showToast(messages[error.message] || "Upload failed");
  } finally {
    addButton.classList.remove("is-uploading");
    addButton.disabled = false;
    fileInput.value = "";
  }
});

let toastTimer;
function showToast(message) {
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("is-visible"), 2600);
}

let resizeTimer;
window.addEventListener("resize", () => {
  window.clearTimeout(resizeTimer);
  resizeTimer = window.setTimeout(() => renderWorld(true), 120);
});

async function bootstrap() {
  try {
    const session = await api("/api/auth/session");
    if (session.authenticated) {
      state.csrf = session.csrf;
      sessionStorage.setItem("gallery_csrf", state.csrf);
      await enterGallery();
      return;
    }
  } catch {
    // The login screen is already the safe fallback.
  }
  window.setTimeout(() => codeInput.focus(), 300);
}

bootstrap();
