const BRAND = "MediaDrop"; // change the site name here
const $ = (s) => document.querySelector(s);
const el = (t, p = {}, ...k) => {
  const e = document.createElement(t);
  for (const [a, v] of Object.entries(p))
    a === "class"
      ? (e.className = v)
      : a === "text"
        ? (e.textContent = v)
        : e.setAttribute(a, v);
  e.append(...k.flat().filter(Boolean));
  return e;
};
document.title = BRAND;
document
  .querySelectorAll("[data-brand]")
  .forEach((n) => (n.textContent = BRAND));
const HOSTS = {
  YouTube: ["youtube.com", "youtu.be"],
  Instagram: ["instagram.com"],
  Facebook: ["facebook.com", "fb.watch"],
  X: ["x.com", "twitter.com"],
  TikTok: ["tiktok.com"],
  Reddit: ["reddit.com", "redd.it"],
  Vimeo: ["vimeo.com"],
};
const guess = (h) =>
  Object.keys(HOSTS).find((n) =>
    HOSTS[n].some((d) => h === d || h.endsWith("." + d)),
  );

function route() {
  const pages = [...document.querySelectorAll("[data-page]")],
    h = location.hash.slice(1),
    p = pages.some((s) => s.dataset.page === h) ? h : "home";
  pages.forEach((s) => (s.hidden = s.dataset.page !== p));
  document
    .querySelectorAll("header nav a")
    .forEach((a) =>
      a.setAttribute("aria-current", a.hash === "#" + p ? "page" : "false"),
    );
  scrollTo(0, 0);
}
addEventListener("hashchange", route);
route();

const status = (msg, busy) => {
  const s = $("#status");
  s.replaceChildren(busy ? el("span", { class: "spin" }) : "", msg);
};
const fmtSize = (n) =>
  n
    ? n >= 1e9
      ? (n / 1e9).toFixed(2) + " GB"
      : (n / 1e6).toFixed(1) + " MB"
    : "size unknown";
function clearAll() {
  $("#result").replaceChildren();
  status("");
  $("#url").value = "";
  $("#url").focus();
}

function showError(msg, extra) {
  $("#result").replaceChildren(
    el(
      "div",
      { class: "card err", role: "alert" },
      el("p", { text: msg }),
      extra &&
        el(
          "p",
          {},
          el("a", {
            class: "btn",
            href: extra,
            target: "_blank",
            rel: "noopener noreferrer",
            text: "Open on original platform",
          }),
        ),
      el(
        "p",
        {},
        el("button", {
          class: "ghost",
          onclick: clearAll,
          text: "Analyze another link",
        }),
      ),
    ),
  );
}
function showResult(d) {
  const info = el(
    "div",
    { class: "grow" },
    el("span", { class: "tag", text: d.platformName }),
    el("h2", { text: d.meta.title || "Untitled media" }),
    d.meta.author && el("p", { text: "By " + d.meta.author }),
  );
  const actions = el(
    "p",
    {},
    el("a", {
      class: "btn",
      href: d.officialUrl,
      target: "_blank",
      rel: "noopener noreferrer",
      text: "Open on original platform",
    }),
    " ",
    el("button", {
      class: "ghost",
      text: "Copy URL",
      onclick: (e) =>
        navigator.clipboard
          .writeText(d.officialUrl)
          .then(() => (e.target.textContent = "Copied")),
    }),
    " ",
    el("button", { class: "ghost", text: "Clear", onclick: clearAll }),
  );
  const card = el(
    "div",
    { class: "card" },
    el(
      "div",
      { class: "row" },
      d.meta.thumbnail &&
        el("img", {
          src: d.meta.thumbnail,
          alt: "Media thumbnail",
          referrerpolicy: "no-referrer",
        }),
      info,
    ),
  );
  if (d.formats.length) {
    for (const k of ["video", "audio"]) {
      const fs = d.formats.filter((f) => f.kind === k);
      if (!fs.length) continue;
      card.append(
        el("h3", { text: k === "video" ? "Video" : "Audio" }),
        ...fs.map((f) =>
          el(
            "div",
            { class: "fmt" },
            el("span", {
              text: `${f.label} · ${f.container} · ${fmtSize(f.size)}${f.original ? " · original quality" : ""}`,
            }),
            el("a", {
              class: "btn",
              href: f.href,
              download: "",
              text: "Download",
            }),
          ),
        ),
      );
    }
    card.append(
      el("p", {
        class: "fine",
        text: "The download starts in your browser. Links expire after 10 minutes.",
      }),
    );
  }
  card.append(el("div", { class: "note", text: d.notice }), actions);
  $("#result").replaceChildren(card);
  status("Results ready.");
}

async function analyze() {
  const raw = $("#url").value.trim(),
    btn = $("#go");
  $("#result").replaceChildren();
  let u;
  try {
    u = new URL(raw);
    if (!/^https?:$/.test(u.protocol)) throw 0;
  } catch {
    return showError("Please paste a full link starting with https://");
  }
  status("Validating link…", true);
  const g = guess(u.hostname.toLowerCase());
  status(
    g
      ? `Detected platform: ${g}. Retrieving media information and checking permitted options…`
      : "Retrieving media information and checking permitted options…",
    true,
  );
  btn.disabled = true;
  try {
    const r = await fetch("/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: raw }),
    });
    const d = await r.json();
    status("");
    d.ok
      ? showResult(d)
      : showError(d.message || "Something went wrong.", d.officialUrl);
  } catch {
    status("");
    showError(
      "Could not reach the server. Check your connection and try again.",
    );
  }
  btn.disabled = false;
}
$("#go").onclick = analyze;
$("#url").onkeydown = (e) => e.key === "Enter" && analyze();
$("#paste").onclick = async () => {
  try {
    $("#url").value = await navigator.clipboard.readText();
    $("#url").focus();
  } catch {
    status("Clipboard access was blocked. Paste with Ctrl/Cmd+V instead.");
  }
};
