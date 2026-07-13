const gallery = document.querySelector("#gallery");
const viewport = document.querySelector("#viewport");
const world = document.querySelector("#world");
const login = document.querySelector("#login");
const loginForm = document.querySelector("#loginForm");
const codeInput = document.querySelector("#codeInput");
const goButton = document.querySelector("#goButton");
const addButton = document.querySelector("#addButton");
const fileInput = document.querySelector("#fileInput");
const preview = document.querySelector("#preview");
const previewImage = document.querySelector("#previewImage");
const closePreview = document.querySelector("#closePreview");
const toast = document.querySelector("#toast");

const state = {
  images: [],
  csrf: sessionStorage.getItem("gallery_csrf") || "",
  columns: 5,
  boardColumns: 10,
  rows: 6,
  gap: 24,
  tileWidth: 0,
  portraitHeight: 0,
  rowPitch: 0,
  boardWidth: 0,
  boardHeight: 0,
  offsetX: 0,
  offsetY: 0,
  initialized: false,
  dragging: false,
  pointerX: 0,
  pointerY: 0,
  dragDistance: 0,
  pressedImageIndex: null,
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
}

function setLoginError() {
  loginForm.classList.remove("is-error");
  void loginForm.offsetWidth;
  loginForm.classList.add("is-error");
  codeInput.value = "";
  codeInput.placeholder = "INPUT CODE";
  codeInput.setAttribute("aria-invalid", "true");
  codeInput.focus();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const code = codeInput.value.replace(/\D/g, "");
  if (code.length !== 10) {
    setLoginError();
    return;
  }
  goButton.disabled = true;
  try {
    const result = await authenticate(code);
    state.csrf = result.csrf;
    sessionStorage.setItem("gallery_csrf", state.csrf);
    codeInput.value = "";
    await enterGallery();
  } catch (error) {
    setLoginError();
  } finally {
    goButton.disabled = false;
  }
});

codeInput.addEventListener("input", () => {
  const clean = codeInput.value.replace(/\D/g, "").slice(0, 10);
  if (codeInput.value !== clean) codeInput.value = clean;
  loginForm.classList.remove("is-error");
  codeInput.removeAttribute("aria-invalid");
  codeInput.placeholder = "INPUT CODE";
});

function calculateLayout() {
  state.columns = window.innerWidth < 600 ? 3 : 5;
  // A double-width board always contains an even number of columns. That
  // preserves the checkerboard phase when identical boards repeat.
  state.boardColumns = state.columns * 2;
  state.gap = window.innerWidth < 600 ? 10 : 24;
  state.tileWidth = (window.innerWidth - state.gap * (state.columns - 1)) / state.columns;
  state.portraitHeight = state.tileWidth * (4 / 3);
  state.rowPitch = state.portraitHeight - state.gap;
  const rowsForViewport = Math.ceil(window.innerHeight / state.rowPitch) + 2;
  const imagesPerRow = state.boardColumns / 2;
  const rowsForImages = Math.ceil(state.images.length / imagesPerRow);
  const requiredRows = Math.max(6, rowsForViewport, rowsForImages);
  state.rows = requiredRows % 2 === 0 ? requiredRows : requiredRows + 1;
  state.boardWidth = state.boardColumns * (state.tileWidth + state.gap);
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

function imageBox(image) {
  const sourceWidth = Math.max(1, Number(image.width) || 1);
  const sourceHeight = Math.max(1, Number(image.height) || 1);
  let width;
  let height;

  if (sourceHeight > sourceWidth) {
    // Portraits are scaled by height, matching the 236.8 × 315.89 frame in
    // the supplied layout. Very wide near-square portraits are capped so they
    // cannot enter the neighbouring checkerboard cell.
    height = state.portraitHeight;
    width = height * (sourceWidth / sourceHeight);
    if (width > state.tileWidth) {
      width = state.tileWidth;
      height = width * (sourceHeight / sourceWidth);
    }
  } else {
    // Landscape and square images are scaled by the available column width.
    width = state.tileWidth;
    height = width * (sourceHeight / sourceWidth);
  }

  return { width, height };
}

function createBoard(boardColumn, boardRow) {
  const board = document.createElement("div");
  board.className = "gallery__board";
  board.style.cssText = `left:${boardColumn * state.boardWidth}px;top:${boardRow * state.boardHeight}px;width:${state.boardWidth}px;height:${state.boardHeight}px`;
  // Every board is an identical copy. Repositioning the world by exactly one
  // board therefore changes only coordinates, never the visible content.
  let imageIndex = 0;

  for (let row = 0; row < state.rows; row += 1) {
    for (let column = 0; column < state.boardColumns; column += 1) {
      if ((row + column) % 2 !== 0) continue;
      const image = tileImage(imageIndex);
      if (!image) continue;
      const box = imageBox(image);
      const x = column * (state.tileWidth + state.gap) + (state.tileWidth - box.width) / 2;
      const y = row * state.rowPitch + (state.portraitHeight - box.height) / 2;
      board.append(createTile(image, x, y, box.width, box.height, imageIndex));
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
  state.dragDistance = 0;
  const pressedTile = event.target.closest(".gallery__tile");
  state.pressedImageIndex = pressedTile ? Number(pressedTile.dataset.imageIndex) : null;
  state.pointerX = event.clientX;
  state.pointerY = event.clientY;
  viewport.classList.add("is-dragging");
  viewport.setPointerCapture(event.pointerId);
});

viewport.addEventListener("pointermove", (event) => {
  if (!state.dragging) return;
  const deltaX = event.clientX - state.pointerX;
  const deltaY = event.clientY - state.pointerY;
  state.dragDistance += Math.hypot(deltaX, deltaY);
  if (state.dragDistance > 8) state.moved = true;
  state.pointerX = event.clientX;
  state.pointerY = event.clientY;
  moveWorld(deltaX, deltaY);
});

function finishDrag(event) {
  const imageIndex = state.pressedImageIndex;
  const shouldOpenPreview = event.type === "pointerup" && !state.moved && Number.isInteger(imageIndex);
  state.dragging = false;
  state.pressedImageIndex = null;
  viewport.classList.remove("is-dragging");
  if (viewport.hasPointerCapture(event.pointerId)) viewport.releasePointerCapture(event.pointerId);
  if (shouldOpenPreview) {
    const image = state.images[imageIndex];
    if (image) openPreview(image);
  }
}

viewport.addEventListener("pointerup", finishDrag);
viewport.addEventListener("pointercancel", finishDrag);

viewport.addEventListener("click", (event) => {
  // Pointer clicks are handled on pointerup so pointer capture cannot change
  // their target. Keep native keyboard activation for the image buttons.
  if (event.detail !== 0) return;
  const tile = event.target.closest(".gallery__tile");
  if (!tile) return;
  const image = state.images[Number(tile.dataset.imageIndex)];
  if (image) openPreview(image);
});

function openPreview(image) {
  if (!preview.open) preview.showModal();
  previewImage.alt = image.name || "Gallery image";
  previewImage.src = image.url;
}

function closePreviewDialog() {
  preview.close();
  previewImage.removeAttribute("src");
}

closePreview.addEventListener("click", closePreviewDialog);
preview.addEventListener("cancel", (event) => {
  event.preventDefault();
  closePreviewDialog();
});
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
