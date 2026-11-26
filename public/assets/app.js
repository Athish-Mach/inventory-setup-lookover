"use strict";

const loginView = document.querySelector("#login-view");
const appView = document.querySelector("#app-view");
const loginForm = document.querySelector("#login-form");
const loginError = document.querySelector("#login-error");
const tableBody = document.querySelector("#advisory-rows");
const searchInput = document.querySelector("#advisory-search");
const toast = document.querySelector("#toast");
const detailDialog = document.querySelector("#detail-dialog");
let allAdvisories = [];
let currentView = "overview";
let currentRole = "analyst";
let showAll = false;
let fixedOnly = false;
let toastTimer;
let operationsLoading = false;
let operationsInitialized = false;
let lastRunSnapshot = null;
let advisoriesLoading = false;
let scheduleDirty = false;
let sessionVersion = 0;

const escapeHTML = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[char]));

function notify(message) {
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2800);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  let body = {};
  try { body = await response.json(); } catch { /* empty response */ }
  if (!response.ok) {
    const error = new Error(body.detail || "Something went wrong. Please try again.");
    error.status = response.status;
    throw error;
  }
  return body;
}

function setView(isAuthenticated, username = "Admin", role = "analyst") {
  sessionVersion += 1;
  loginView.hidden = isAuthenticated;
  appView.hidden = !isAuthenticated;
  if (!isAuthenticated) {
    allAdvisories = [];
    advisoriesLoading = false;
    operationsLoading = false;
    operationsInitialized = false;
    lastRunSnapshot = null;
    scheduleDirty = false;
    fixedOnly = false;
    showAll = false;
    const filterButton = document.querySelector("#filter-button");
    filterButton.classList.remove("active");
    filterButton.setAttribute("aria-pressed", "false");
    filterButton.title = "Show advisories with fixed releases";
    document.querySelector("#refresh-button").classList.remove("loading");
    searchInput.value = "";
    if (detailDialog.open) detailDialog.close();
    document.querySelector("#detail-content").replaceChildren();
    tableBody.replaceChildren();
    document.querySelector("#overview-view").hidden = true;
    document.querySelector("#operations-view").hidden = true;
    document.querySelector("#password").value = "";
    setTimeout(() => document.querySelector("#username").focus(), 50);
    return;
  }
  currentRole = role;
  currentView = "overview";
  document.querySelector("#overview-view").hidden = false;
  document.querySelector("#operations-view").hidden = true;
  document.querySelector(".admin-nav").hidden = role !== "admin";
  document.querySelector(".profile-copy small").textContent = role === "admin" ? "Workspace admin" : "Security analyst";
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === "overview"));
  document.querySelector("#breadcrumb-current").textContent = "Overview";
  const displayName = username ? username.charAt(0).toUpperCase() + username.slice(1) : "Admin";
  document.querySelector("#welcome-name").textContent = displayName;
  document.querySelector("#profile-name").textContent = displayName;
  document.querySelector("#profile-avatar").textContent = displayName.charAt(0).toUpperCase();
  const now = new Date();
  document.querySelector("#today-date").textContent = now.toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" }).toUpperCase();
  renderFeedStatus("Checking feed", "Checking for a saved snapshot");
  loadAdvisories();
}

function advisoryProducts(advisory) {
  return Array.isArray(advisory.affected_products) ? advisory.affected_products : [];
}

function advisoryReleases(advisory) {
  return Array.isArray(advisory.fixed_releases) ? advisory.fixed_releases : [];
}

function formatDate(raw) {
  if (!raw) return "—";
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

function visibleAdvisories() {
  const query = searchInput.value.trim().toLocaleLowerCase();
  return allAdvisories.filter((item) => {
    const matchesText = !query || [item.name, item.summary, ...advisoryProducts(item)].join(" ").toLocaleLowerCase().includes(query);
    const matchesFixed = !fixedOnly || advisoryReleases(item).length > 0;
    return matchesText && matchesFixed;
  });
}

function renderProducts() {
  const counts = new Map();
  for (const advisory of allAdvisories) {
    for (const product of advisoryProducts(advisory)) {
      counts.set(product, (counts.get(product) || 0) + 1);
    }
  }
  const query = searchInput.value.trim().toLocaleLowerCase();
  const products = [...counts.entries()].filter(([name]) => name.toLocaleLowerCase().includes(query)).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  document.querySelector("#list-title").textContent = "Products in your feed";
  document.querySelector("#list-count").textContent = String(products.length);
  document.querySelector(".section-description").textContent = "Products mentioned across the latest Cisco advisories.";
  document.querySelector("thead").innerHTML = "<tr><th>PRODUCT</th><th>ADVISORY COVERAGE</th><th>STATUS</th><th>FETCHED</th><th></th></tr>";
  if (!products.length) {
    tableBody.innerHTML = '<tr><td colspan="5" class="empty-cell">No products match this search.</td></tr>';
  } else {
    tableBody.innerHTML = products.map(([name, count]) => {
      const lastSeen = allAdvisories.filter((item) => advisoryProducts(item).includes(name)).map((item) => item.created_at).filter(Boolean).sort().at(-1);
      return `<tr><td><div class="advisory-title">${escapeHTML(name)}</div><div class="advisory-meta">Cisco product</div></td><td><span class="product-coverage">${count} ${count === 1 ? "advisory" : "advisories"}</span></td><td><span class="simple-status">Affected product</span></td><td class="date-cell">${escapeHTML(formatDate(lastSeen))}</td><td><button class="row-action product-action" data-product="${escapeHTML(name)}" aria-label="Filter by ${escapeHTML(name)}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6"/></svg></button></td></tr>`;
    }).join("");
  }
  document.querySelector("#table-summary").textContent = `${products.length} ${products.length === 1 ? "product" : "products"} across ${allAdvisories.length} advisories`;
  document.querySelector("#view-all").hidden = true;
}

function renderAdvisories() {
  const items = visibleAdvisories();
  const shown = showAll || currentView === "advisories" ? items : items.slice(0, 8);
  document.querySelector("#list-title").textContent = currentView === "advisories" ? "All advisories" : "Latest advisories";
  document.querySelector("#list-count").textContent = String(items.length);
  document.querySelector(".section-description").textContent = "Stay informed on the latest Cisco security updates.";
  document.querySelector("thead").innerHTML = "<tr><th>ADVISORY</th><th>AFFECTED PRODUCTS</th><th>FIXED RELEASES</th><th>FETCHED</th><th></th></tr>";
  if (!shown.length) {
    const message = allAdvisories.length ? "No advisories match your search." : "No advisory snapshot is available yet.";
    tableBody.innerHTML = `<tr><td colspan="5" class="empty-cell">${message}</td></tr>`;
  } else {
    tableBody.innerHTML = shown.map((item) => {
      const products = advisoryProducts(item);
      const releases = advisoryReleases(item);
      const bubbles = products.slice(0, 3).map((product, index) => `<span class="product-bubble" title="${escapeHTML(product)}">${escapeHTML(productInitials(product))}</span>`).join("");
      const extra = products.length > 3 ? `<span class="product-more">+${products.length - 3} more</span>` : "";
      const releaseMarkup = releases.slice(0, 2).map((release) => `<span class="release-chip">${escapeHTML(release)}</span>`).join("") || '<span class="release-empty">Not listed</span>';
      return `<tr><td class="advisory-cell"><div class="advisory-title">${escapeHTML(item.name || "Cisco security advisory")}</div><div class="advisory-meta"><span>Security advisory</span><span class="cell-dot"></span><span>${products.length} ${products.length === 1 ? "product" : "products"}</span></div></td><td><div class="product-stack">${bubbles || '<span class="release-empty">—</span>'}${extra}</div></td><td>${releaseMarkup}</td><td class="date-cell">${escapeHTML(formatDate(item.created_at))}</td><td><button class="row-action detail-action" data-id="${Number(item.id) || 0}" aria-label="View advisory details"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6"/></svg></button></td></tr>`;
    }).join("");
  }
  document.querySelector("#table-summary").textContent = items.length ? `Showing ${shown.length} of ${items.length} advisories` : "No records to display";
  document.querySelector("#view-all").hidden = items.length <= 8 || currentView === "advisories";
  document.querySelector("#view-all").textContent = currentView === "advisories" ? "Showing all advisories" : "View all advisories →";
}

function productInitials(product) {
  const words = product.replace(/^Cisco\s+/i, "").split(/\s+/).filter(Boolean);
  return words.slice(0, 2).map((word) => word.replace(/[^a-z0-9]/gi, "").slice(0, 1)).join("").toUpperCase() || "C";
}

function runDate(raw) {
  if (!raw) return "Not started";
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function renderTrackedProducts(items) {
  document.querySelector("#tracked-product-count").textContent = String(items.length);
  const body = document.querySelector("#tracked-products");
  if (!items.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty-cell">Your watchlist is empty. Add a product above to get started.</td></tr>';
    return;
  }
  body.innerHTML = items.map((item) => `<tr><td><div class="admin-product-name">${escapeHTML(item.name)}</div><div class="advisory-meta">Added by ${escapeHTML(item.created_by || "workspace admin")}</div></td><td class="admin-product-notes">${escapeHTML(item.notes || "—")}</td><td><button class="product-state-button ${item.is_active ? "is-active" : "is-paused"}" data-product-state="${Number(item.id)}" data-next-state="${!item.is_active}">${item.is_active ? "Active" : "Paused"}</button></td><td class="date-cell">${escapeHTML(formatDate(item.created_at))}</td><td><button class="row-action delete-product-button" data-product-delete="${Number(item.id)}" aria-label="Remove ${escapeHTML(item.name)}" title="Remove product"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16m-10 4v6m4-6v6M6 7l1 14h10l1-14M9 7V4h6v3"/></svg></button></td></tr>`).join("");
}

function renderScraperRuns(runs) {
  const container = document.querySelector("#scraper-runs");
  if (!runs.length) {
    container.innerHTML = '<div class="ops-empty">No scraper runs recorded yet.</div>';
    return;
  }
  container.innerHTML = runs.map((run) => {
    const status = ["queued", "running", "succeeded", "failed"].includes(run.status) ? run.status : "failed";
    const title = status === "succeeded" ? `${Number(run.advisory_count) || 0} advisories saved` : status === "running" ? "Scrape in progress" : status === "queued" ? "Run queued" : "Scrape failed";
    const source = run.run_source === "manual" ? "Manual run" : "Scheduled run";
    return `<article class="run-row"><span class="run-mark ${status}"><i></i></span><div class="run-copy"><strong>${title}</strong><small>${source}${run.requested_by ? ` · by ${escapeHTML(run.requested_by)}` : ""}</small></div><div class="run-meta"><span class="run-status ${status}">${status}</span><time>${escapeHTML(runDate(run.finished_at || run.started_at || run.created_at))}</time></div></article>`;
  }).join("");
}

async function loadOperations(quiet = false) {
  if (operationsLoading || currentRole !== "admin") return;
  operationsLoading = true;
  const version = sessionVersion;
  try {
    const [products, scraper] = await Promise.all([
      api("/api/admin/products"),
      api("/api/admin/scraper/settings"),
    ]);
    if (version !== sessionVersion) return;
    renderTrackedProducts(products.items || []);
    renderScraperRuns(scraper.runs || []);
    const latestRun = scraper.latest_run;
    if (operationsInitialized && latestRun?.status === "succeeded" &&
        (lastRunSnapshot?.id !== latestRun.id || lastRunSnapshot?.status !== "succeeded")) {
      notify("Scrape finished. Advisory data is refreshing.");
      loadAdvisories();
    }
    lastRunSnapshot = latestRun ? { id: latestRun.id, status: latestRun.status } : lastRunSnapshot;
    operationsInitialized = true;
    if (scraper.settings) {
      if (!scheduleDirty) {
        document.querySelector("#schedule-enabled").checked = Boolean(scraper.settings.enabled);
        document.querySelector("#schedule-interval").value = String(scraper.settings.interval_minutes);
      }
      const state = document.querySelector("#schedule-state");
      state.textContent = scraper.settings.enabled ? "Automatic on" : "Paused";
      state.classList.toggle("paused", !scraper.settings.enabled);
    }
    const workerNote = document.querySelector("#worker-note-text");
    const runButton = document.querySelector("#run-scraper");
    if (workerNote) {
      if (scraper.runner === "local") {
        workerNote.textContent = "Manual runs start the local Playwright scraper on this server. Scheduled cadence still needs the GitHub Actions worker for hosted deployments.";
      } else if (scraper.runner === "github") {
        workerNote.textContent = "Manual and scheduled scrapes run in GitHub Actions outside the web request. Keep the repository secrets and dispatch token configured.";
      } else {
        workerNote.textContent = "Manual scraping is unavailable here. For local use, run python app.py on your machine. For hosted deployments, configure SCRAPER_GITHUB_REPOSITORY and SCRAPER_GITHUB_TOKEN.";
      }
    }
    if (runButton) {
      runButton.disabled = scraper.manual_runs_available === false;
      runButton.title = scraper.manual_runs_available === false
        ? "Configure a local app process or GitHub Actions dispatch to enable manual runs"
        : "Queue an immediate scrape";
    }
  } catch (error) {
    if (version !== sessionVersion) return;
    if (error.status === 401) {
      setView(false);
      return;
    }
    if (!quiet) notify(error.message);
    document.querySelector("#tracked-products").innerHTML = `<tr><td colspan="5" class="empty-cell">${escapeHTML(error.message)}</td></tr>`;
    document.querySelector("#scraper-runs").innerHTML = `<div class="ops-empty">${escapeHTML(error.message)}</div>`;
  } finally {
    if (version === sessionVersion) operationsLoading = false;
  }
}

function render() {
  if (currentView === "products") renderProducts();
  else renderAdvisories();
}

function renderFeedStatus(state, detail) {
  document.querySelector("#feed-state").textContent = state;
  document.querySelector("#last-sync").textContent = detail;
}

async function loadAdvisories(showToast = false) {
  if (advisoriesLoading) return;
  advisoriesLoading = true;
  const version = sessionVersion;
  const refreshButton = document.querySelector("#refresh-button");
  refreshButton.classList.add("loading");
  try {
    const data = await api("/api/advisories?limit=500");
    if (version !== sessionVersion) return;
    allAdvisories = Array.isArray(data.items) ? data.items : [];
    document.querySelector("#metric-advisories").textContent = String(data.total ?? allAdvisories.length);
    document.querySelector("#metric-products").textContent = String(data.products ?? "—");
    document.querySelector("#metric-releases").textContent = String(data.fixed_releases ?? "—");
    document.querySelector("#nav-count").textContent = String(data.total ?? allAdvisories.length);
    const fetchedAt = data.fetched_at ? new Date(data.fetched_at).toLocaleString() : "";
    let state = fetchedAt ? "Snapshot available" : "Awaiting first snapshot";
    if (data.schedule_enabled === false) state = "Schedule paused";
    if (data.stale) state = "Refresh overdue";
    if (data.latest_run_status === "failed") state = "Last scrape failed";
    renderFeedStatus(state, fetchedAt ? `Saved ${fetchedAt}` : "No snapshot saved yet");
    render();
    if (showToast) notify("Advisory feed refreshed.");
  } catch (error) {
    if (version !== sessionVersion) return;
    if (error.status === 401) {
      setView(false);
      return;
    }
    if (!allAdvisories.length) {
      tableBody.innerHTML = `<tr><td colspan="5" class="empty-cell">${escapeHTML(error.message)}</td></tr>`;
    }
    renderFeedStatus("Feed unavailable", allAdvisories.length ? "Showing the previously loaded snapshot" : "Unable to reach the data source");
    if (showToast) notify("Refresh failed. Please try again.");
  } finally {
    if (version === sessionVersion) {
      advisoriesLoading = false;
      refreshButton.classList.remove("loading");
    }
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = loginForm.querySelector("button[type=submit]");
  const buttonText = button.querySelector("span");
  button.disabled = true;
  buttonText.textContent = "Signing in…";
  loginError.hidden = true;
  try {
    const result = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username: loginForm.username.value, password: loginForm.password.value }),
    });
    loginForm.reset();
    setView(true, result.user.username, result.user.role);
  } catch (error) {
    loginError.textContent = error.message;
    loginError.hidden = false;
    document.querySelector("#password").value = "";
    document.querySelector("#password").focus();
  } finally {
    button.disabled = false;
    buttonText.textContent = "Sign in securely";
  }
});

document.querySelector(".password-toggle").addEventListener("click", (event) => {
  const input = document.querySelector("#password");
  const visible = input.type === "password";
  input.type = visible ? "text" : "password";
  event.currentTarget.textContent = visible ? "Hide" : "Show";
  event.currentTarget.setAttribute("aria-label", visible ? "Hide password" : "Show password");
});

document.querySelector("#sign-out").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await api("/api/auth/logout", { method: "POST" });
    setView(false);
  } catch (error) {
    if (error.status === 401) setView(false);
    else notify("Sign-out could not be confirmed. Try again.");
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#refresh-button").addEventListener("click", () => loadAdvisories(true));
searchInput.addEventListener("input", render);
document.querySelector("#filter-button").addEventListener("click", (event) => {
  fixedOnly = !fixedOnly;
  event.currentTarget.classList.toggle("active", fixedOnly);
  event.currentTarget.setAttribute("aria-pressed", String(fixedOnly));
  event.currentTarget.title = fixedOnly ? "Showing advisories with fixed releases" : "Show advisories with fixed releases";
  render();
});
document.querySelector("#view-all").addEventListener("click", () => {
  showAll = true;
  currentView = "advisories";
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === currentView));
  document.querySelector("#breadcrumb-current").textContent = "Advisories";
  render();
});
document.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", () => {
  if (item.dataset.view === "operations" && currentRole !== "admin") return;
  currentView = item.dataset.view;
  showAll = currentView === "advisories";
  document.querySelector("#overview-view").hidden = currentView === "operations";
  document.querySelector("#operations-view").hidden = currentView !== "operations";
  document.querySelectorAll(".nav-item").forEach((nav) => nav.classList.toggle("active", nav === item));
  document.querySelector("#breadcrumb-current").textContent = item.textContent.trim().replace(/\s+\d+$/, "");
  document.querySelector("#sidebar").classList.remove("open");
  if (currentView === "operations") loadOperations();
  else render();
}));
document.querySelector("#mobile-menu").addEventListener("click", () => document.querySelector("#sidebar").classList.toggle("open"));

tableBody.addEventListener("click", (event) => {
  const detailButton = event.target.closest(".detail-action");
  const productButton = event.target.closest(".product-action");
  if (detailButton) openAdvisory(Number(detailButton.dataset.id));
  if (productButton) {
    currentView = "advisories";
    searchInput.value = productButton.dataset.product;
    document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === "advisories"));
    document.querySelector("#breadcrumb-current").textContent = "Advisories";
    render();
  }
});

document.querySelector("#schedule-form").addEventListener("change", () => {
  scheduleDirty = true;
});

document.querySelector("#schedule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = document.querySelector("#save-schedule");
  button.disabled = true;
  try {
    await api("/api/admin/scraper/settings", {
      method: "PUT",
      body: JSON.stringify({
        enabled: document.querySelector("#schedule-enabled").checked,
        interval_minutes: Number(document.querySelector("#schedule-interval").value),
      }),
    });
    scheduleDirty = false;
    document.querySelector("#schedule-feedback").textContent = "Schedule saved.";
    document.querySelector("#schedule-feedback").hidden = false;
    await loadOperations(true);
  } catch (error) {
    document.querySelector("#schedule-feedback").textContent = error.message;
    document.querySelector("#schedule-feedback").hidden = false;
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#run-scraper").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const result = await api("/api/admin/scraper/run", { method: "POST" });
    notify(`Scraper queued${result.run_id ? ` · run #${result.run_id}` : ""}.`);
    await loadOperations(true);
  } catch (error) {
    document.querySelector("#schedule-feedback").textContent = error.message;
    document.querySelector("#schedule-feedback").hidden = false;
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#operations-refresh").addEventListener("click", () => loadOperations());
document.querySelector("#product-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const feedback = document.querySelector("#product-feedback");
  try {
    await api("/api/admin/products", {
      method: "POST",
      body: JSON.stringify({
        name: document.querySelector("#product-name").value,
        notes: document.querySelector("#product-notes").value,
      }),
    });
    event.currentTarget.reset();
    feedback.textContent = "Product added to the team watchlist.";
    feedback.hidden = false;
    await loadOperations(true);
  } catch (error) {
    feedback.textContent = error.message;
    feedback.hidden = false;
  }
});

document.querySelector("#tracked-products").addEventListener("click", async (event) => {
  const stateButton = event.target.closest("[data-product-state]");
  const deleteButton = event.target.closest("[data-product-delete]");
  try {
    if (stateButton) {
      await api(`/api/admin/products/${stateButton.dataset.productState}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: stateButton.dataset.nextState === "true" }),
      });
      await loadOperations(true);
    }
    if (deleteButton && window.confirm("Remove this product from the team watchlist?")) {
      await api(`/api/admin/products/${deleteButton.dataset.productDelete}`, { method: "DELETE" });
      await loadOperations(true);
      notify("Product removed from the watchlist.");
    }
  } catch (error) {
    notify(error.message);
  }
});

setInterval(() => {
  if (!appView.hidden && !document.hidden && currentView === "operations") loadOperations(true);
}, 20000);

setInterval(() => {
  if (!appView.hidden && !document.hidden) loadAdvisories();
}, 60000);

function ciscoSourceLink(raw) {
  try {
    const url = new URL(raw);
    if (url.protocol === "https:" && (url.hostname === "cisco.com" || url.hostname.endsWith(".cisco.com"))) {
      return `<p><a href="${escapeHTML(url.href)}" target="_blank" rel="noopener noreferrer">View original Cisco advisory</a></p>`;
    }
  } catch { /* Older snapshots may have no source link. */ }
  return "";
}

function openAdvisory(id) {
  const item = allAdvisories.find((advisory) => Number(advisory.id) === id);
  if (!item) return;
  const list = (items) => items.length ? `<ul>${items.map((value) => `<li>${escapeHTML(value)}</li>`).join("")}</ul>` : "<p>Not specified in this advisory.</p>";
  document.querySelector("#detail-content").innerHTML = `<div class="detail-eyebrow">CISCO SECURITY ADVISORY</div><h2>${escapeHTML(item.name || "Cisco security advisory")}</h2><div class="detail-meta">Fetched ${escapeHTML(formatDate(item.created_at))} <span class="cell-dot"></span> ${advisoryProducts(item).length} affected products</div>${ciscoSourceLink(item.source_url)}<section class="detail-block"><h3>Summary</h3><p>${escapeHTML(item.summary || "No summary was provided.")}</p></section><section class="detail-block"><h3>Affected products</h3>${list(advisoryProducts(item))}</section><section class="detail-block"><h3>Fixed releases</h3>${list(advisoryReleases(item))}</section><section class="detail-block"><h3>Workarounds</h3><p>${escapeHTML(item.workarounds || "No workaround details were provided.")}</p></section><section class="detail-block"><h3>Fixed software</h3><p>${escapeHTML(item.fixed_software || "No fixed software details were provided.")}</p></section>`;
  detailDialog.showModal();
}

async function start() {
  try {
    const data = await api("/api/auth/session");
    setView(true, data.user.username, data.user.role);
  } catch {
    setView(false);
  }
}

start();
