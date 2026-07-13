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
const deleteImage = document.querySelector("#deleteImage");
const deleteLabel = document.querySelector("#deleteLabel");
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
  currentPreviewImageId: null,
  previewOpenedAt: 0,
};

const encoder = new TextEncoder();
const thumbnailJobs = new Set();
const ACCESS_CODE_PATTERN = /^[A-Za-z0-9]{10}$/;
const ALLOWED_IMAGE_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
const DELETE_HOLD_MS = 2000;
const PREVIEW_CLICK_GUARD_MS = 260;
let dimensionCorrectionFrame = 0;

function reconcileImageDimensions(element, imageRecord) {
  const width = element.naturalWidth;
  const height = element.naturalHeight;
  if (!width || !height || !imageRecord) return;

  const recordedRatio = Math.max(1, Number(imageRecord.width) || 1) / Math.max(1, Number(imageRecord.height) || 1);
  const renderedRatio = width / height;
  if (Math.abs(Math.log(recordedRatio / renderedRatio)) < 0.01) return;

  imageRecord.width = width;
  imageRecord.height = height;
  if (dimensionCorrectionFrame) return;
  dimensionCorrectionFrame = window.requestAnimationFrame(() => {
    dimensionCorrectionFrame = 0;
    renderWorld(false);
  });
}

function revealTileImage(image) {
  if (image.classList.contains("is-bubbling") || image.classList.contains("is-loaded")) return;
  image.classList.add("is-bubbling");
  const finish = () => {
    image.classList.remove("is-bubbling");
    image.classList.add("is-loaded");
    image.closest(".gallery__tile")?.classList.add("is-loaded");
  };
  image.addEventListener("animationend", finish, { once: true });
  window.setTimeout(finish, 1400);
}

function handleTileImageLoad(image) {
  const imageRecord = state.images[Number(image.dataset.imageIndex)];
  reconcileImageDimensions(image, imageRecord);
  revealTileImage(image);
  if (imageRecord?.needsThumbnail) backfillThumbnail(imageRecord, image);
}

const imageObserver = "IntersectionObserver" in window
  ? new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          const image = entry.target;
          if (image.dataset.src) {
            image.src = image.dataset.src;
            image.removeAttribute("data-src");
          }
          imageObserver.unobserve(image);
        });
      },
      { root: viewport, rootMargin: "300px" },
    )
  : null;

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
  const code = codeInput.value;
  if (!ACCESS_CODE_PATTERN.test(code)) {
    setLoginError();
    return;
  }
  goButton.disabled = true;
  try {
    const result = await authenticate(code);
    state.csrf = result.csrf;
    sessionStorage.setItem("gallery_csrf", state.csrf);
    codeInput.value = "";
    codeInput.blur();
    await enterGallery();
  } catch (error) {
    setLoginError();
  } finally {
    goButton.disabled = false;
  }
});

codeInput.addEventListener("input", () => {
  const clean = codeInput.value.replace(/[^A-Za-z0-9]/g, "").slice(0, 10);
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
  const source = image.thumbnailUrl || image.url;
  img.addEventListener("load", () => handleTileImageLoad(img), { once: true });
  img.style.setProperty("--bubble-delay", `${(imageIndex * 37) % 260}ms`);
  if (imageObserver) {
    img.dataset.src = source;
    imageObserver.observe(img);
  } else {
    img.src = source;
  }
  img.alt = "";
  img.dataset.imageIndex = String(imageIndex % state.images.length);
  img.loading = "lazy";
  img.decoding = "async";
  img.fetchPriority = "low";
  button.append(img);
  if (img.complete && img.naturalWidth) queueMicrotask(() => handleTileImageLoad(img));
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
  imageObserver?.disconnect();
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
  // Pointer activation is handled on pointerup. Keyboard activation keeps the
  // native button click target and has detail === 0.
  if (event.detail !== 0) return;
  const tile = event.target.closest(".gallery__tile");
  if (!tile) return;
  const image = state.images[Number(tile.dataset.imageIndex)];
  if (image) openPreview(image);
});

function openPreview(image) {
  resetDeleteControl(true);
  state.currentPreviewImageId = image.id;
  previewImage.alt = image.name || "Gallery image";
  previewImage.dataset.sourceWidth = String(image.width || 1);
  previewImage.dataset.sourceHeight = String(image.height || 1);
  previewImage.src = image.url;
  state.previewOpenedAt = performance.now();
  if (!preview.open) preview.showModal();
}

function closePreviewDialog() {
  resetDeleteControl(true);
  if (preview.open) preview.close();
  state.currentPreviewImageId = null;
  previewImage.removeAttribute("src");
  previewImage.removeAttribute("data-source-width");
  previewImage.removeAttribute("data-source-height");
}

function clickHitsRenderedPreviewImage(event) {
  const rect = previewImage.getBoundingClientRect();
  const sourceWidth = Number(previewImage.dataset.sourceWidth) || previewImage.naturalWidth;
  const sourceHeight = Number(previewImage.dataset.sourceHeight) || previewImage.naturalHeight;
  if (!sourceWidth || !sourceHeight || !rect.width || !rect.height) return false;

  const scale = Math.min(rect.width / sourceWidth, rect.height / sourceHeight);
  const renderedWidth = sourceWidth * scale;
  const renderedHeight = sourceHeight * scale;
  const left = rect.left + (rect.width - renderedWidth) / 2;
  const top = rect.top + (rect.height - renderedHeight) / 2;
  return (
    event.clientX >= left &&
    event.clientX <= left + renderedWidth &&
    event.clientY >= top &&
    event.clientY <= top + renderedHeight
  );
}

let deleteHoldFrame = 0;
let deleteHoldStartedAt = 0;
let deleteHoldPointerId = null;
let deleteHoldKey = null;
let deletionInProgress = false;

function setDeleteProgress(progress) {
  const percent = `${Math.max(0, Math.min(1, progress)) * 100}%`;
  deleteImage.style.setProperty("--delete-progress", percent);
}

function resetDeleteControl(initial = false) {
  window.cancelAnimationFrame(deleteHoldFrame);
  deleteHoldFrame = 0;
  deleteHoldStartedAt = 0;
  deleteHoldPointerId = null;
  deleteHoldKey = null;
  deleteImage.classList.remove("is-holding", "is-deleting");
  deleteImage.classList.toggle("is-armed", !initial);
  deleteLabel.textContent = initial ? "Delete" : "Hold To Delete";
  deleteImage.setAttribute("aria-label", initial ? "Delete image — hold for 2 seconds" : "Hold for 2 seconds to delete image");
  setDeleteProgress(0);
}

function cancelDeleteHold() {
  if (deletionInProgress || !deleteHoldStartedAt) return;
  resetDeleteControl(false);
}

function finishDeleteHold() {
  if (!deleteHoldStartedAt || deletionInProgress) return;
  if (performance.now() - deleteHoldStartedAt >= DELETE_HOLD_MS) {
    completeImageDeletion();
  } else {
    cancelDeleteHold();
  }
}

function startDeleteHold() {
  if (deletionInProgress || deleteHoldStartedAt || !Number.isInteger(state.currentPreviewImageId)) return;
  deleteHoldStartedAt = performance.now();
  deleteImage.classList.add("is-armed", "is-holding");
  deleteLabel.textContent = "Hold To Delete";
  setDeleteProgress(0);

  const update = (now) => {
    if (!deleteHoldStartedAt || deletionInProgress) return;
    const progress = Math.min(1, (now - deleteHoldStartedAt) / DELETE_HOLD_MS);
    setDeleteProgress(progress);
    if (progress >= 1) {
      completeImageDeletion();
      return;
    }
    deleteHoldFrame = window.requestAnimationFrame(update);
  };
  deleteHoldFrame = window.requestAnimationFrame(update);
}

async function completeImageDeletion() {
  if (deletionInProgress || !Number.isInteger(state.currentPreviewImageId)) return;
  deletionInProgress = true;
  window.cancelAnimationFrame(deleteHoldFrame);
  deleteHoldFrame = 0;
  deleteHoldStartedAt = 0;
  const imageId = state.currentPreviewImageId;
  deleteImage.classList.remove("is-holding");
  deleteImage.classList.add("is-deleting");
  deleteLabel.textContent = "Deleting…";
  setDeleteProgress(1);
  deleteImage.disabled = true;
  closePreview.disabled = true;

  try {
    await api(`/api/images/${imageId}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": state.csrf },
    });
    state.images = state.images.filter((image) => image.id !== imageId);
    deletionInProgress = false;
    closePreviewDialog();
    renderWorld(false);
    showToast("Image deleted");
  } catch (error) {
    if (error.status === 404) {
      state.images = state.images.filter((image) => image.id !== imageId);
      deletionInProgress = false;
      closePreviewDialog();
      renderWorld(false);
      showToast("Image already deleted");
    } else {
      deletionInProgress = false;
      resetDeleteControl(false);
      const message = error.message === "invalid_csrf" ? "Session expired — reload the page" : "Delete failed";
      showToast(message);
    }
  } finally {
    deleteImage.disabled = false;
    closePreview.disabled = false;
  }
}

closePreview.addEventListener("click", (event) => {
  if (deletionInProgress) return;
  if (event.detail !== 0 && performance.now() - state.previewOpenedAt < PREVIEW_CLICK_GUARD_MS) return;
  closePreviewDialog();
});

deleteImage.addEventListener("pointerdown", (event) => {
  if (event.button !== 0 || deletionInProgress) return;
  event.preventDefault();
  deleteHoldPointerId = event.pointerId;
  deleteImage.setPointerCapture(event.pointerId);
  startDeleteHold();
});

function finishDeletePointer(event) {
  if (deleteHoldPointerId !== event.pointerId) return;
  deleteHoldPointerId = null;
  if (deleteImage.hasPointerCapture(event.pointerId)) deleteImage.releasePointerCapture(event.pointerId);
  finishDeleteHold();
}

deleteImage.addEventListener("pointerup", finishDeletePointer);
deleteImage.addEventListener("pointercancel", finishDeletePointer);
deleteImage.addEventListener("pointerleave", finishDeletePointer);
deleteImage.addEventListener("lostpointercapture", cancelDeleteHold);
deleteImage.addEventListener("contextmenu", (event) => event.preventDefault());
deleteImage.addEventListener("click", (event) => event.preventDefault());
deleteImage.addEventListener("keydown", (event) => {
  if (event.repeat || !["Enter", " "].includes(event.key)) return;
  event.preventDefault();
  deleteHoldKey = event.key;
  startDeleteHold();
});
deleteImage.addEventListener("keyup", (event) => {
  if (event.key !== deleteHoldKey) return;
  event.preventDefault();
  deleteHoldKey = null;
  finishDeleteHold();
});

window.addEventListener("blur", cancelDeleteHold);
document.addEventListener("visibilitychange", () => {
  if (document.hidden) cancelDeleteHold();
});

preview.addEventListener("cancel", (event) => {
  event.preventDefault();
  if (deletionInProgress) return;
  closePreviewDialog();
});
preview.addEventListener("click", (event) => {
  if (deletionInProgress) return;
  if (performance.now() - state.previewOpenedAt < PREVIEW_CLICK_GUARD_MS) return;
  if (event.target.closest(".preview__actions")) return;
  if (event.target === previewImage && clickHitsRenderedPreviewImage(event)) return;
  closePreviewDialog();
});

addButton.addEventListener("click", () => fileInput.click());

async function thumbnailBlob(drawable, sourceWidth, sourceHeight) {
  const longestSide = Math.max(sourceWidth, sourceHeight);
  const scale = Math.min(1, 1024 / longestSide);
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(sourceWidth * scale));
  canvas.height = Math.max(1, Math.round(sourceHeight * scale));
  const context = canvas.getContext("2d", { alpha: true });
  context.drawImage(drawable, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/webp", 0.82));
  if (!blob) throw new Error("thumbnail_failed");
  return blob;
}

async function createThumbnail(file) {
  const bitmap = await createImageBitmap(file);
  try {
    return {
      blob: await thumbnailBlob(bitmap, bitmap.width, bitmap.height),
      width: bitmap.width,
      height: bitmap.height,
    };
  } finally {
    bitmap.close();
  }
}

async function uploadThumbnail(image, thumbnail) {
  const payload = await api(`/api/images/${image.id}/thumbnail`, {
    method: "POST",
    headers: {
      "Content-Type": thumbnail.type,
      "X-CSRF-Token": state.csrf,
    },
    body: thumbnail,
  });
  image.thumbnailUrl = payload.thumbnailUrl;
  image.needsThumbnail = false;
}

async function backfillThumbnail(image, loadedImage) {
  if (thumbnailJobs.has(image.id)) return;
  thumbnailJobs.add(image.id);
  try {
    const thumbnail = await thumbnailBlob(loadedImage, loadedImage.naturalWidth, loadedImage.naturalHeight);
    await uploadThumbnail(image, thumbnail);
  } catch {
    // The original remains usable; a future page load can retry the backfill.
  }
}

async function uploadFile(file) {
  const thumbnailPromise = createThumbnail(file).catch(() => null);
  const payload = await api("/api/images", {
    method: "POST",
    headers: {
      "Content-Type": file.type,
      "X-Filename": encodeURIComponent(file.name),
      "X-CSRF-Token": state.csrf,
    },
    body: file,
  });
  const thumbnail = await thumbnailPromise;
  if (thumbnail) {
    payload.image.width = thumbnail.width;
    payload.image.height = thumbnail.height;
    await uploadThumbnail(payload.image, thumbnail.blob).catch(() => null);
  }
  return payload.image;
}

fileInput.addEventListener("change", async () => {
  const selectedFiles = Array.from(fileInput.files || []);
  if (!selectedFiles.length) return;

  const files = selectedFiles.filter((file) => ALLOWED_IMAGE_TYPES.has(file.type));
  const rejected = selectedFiles.length - files.length;
  if (!files.length) {
    showToast("Choose JPEG, PNG, WebP, or GIF files");
    fileInput.value = "";
    return;
  }

  addButton.classList.add("is-uploading");
  addButton.disabled = true;
  let uploaded = 0;
  let failed = rejected;

  try {
    for (const [index, file] of files.entries()) {
      if (files.length > 1) showToast(`Uploading ${index + 1} of ${files.length}`);
      try {
        const image = await uploadFile(file);
        state.images.unshift(image);
        uploaded += 1;
      } catch (error) {
        failed += 1;
        if (error.message === "invalid_csrf") break;
      }
    }

    if (uploaded) renderWorld(false);
    if (uploaded && !failed) {
      showToast(uploaded === 1 ? "Image added" : `${uploaded} images added`);
    } else if (uploaded) {
      showToast(`${uploaded} added, ${failed} failed`);
    } else {
      showToast("Upload failed");
    }
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
}

bootstrap();
