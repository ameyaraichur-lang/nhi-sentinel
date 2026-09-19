// UAT driver: injected into the live portal page. DOM-dispatched interaction (fallback for
// IAB synthesized-input outage) — exercises the real views/handlers/fetch pipeline.
export function installUAT() {
  const w = window;
  w.uat = {
    log: [],
    rec(id, pass, detail) { w.uat.log.push({ id, pass, detail }); return { id, pass, detail }; },
    findButton(text) {
      const btns = Array.from(document.querySelectorAll("button, a"));
      return btns.find(b => (b.textContent || "").trim().toLowerCase().includes(text.toLowerCase()))
        || null;
    },
    clickButton(text) {
      const b = w.uat.findButton(text);
      if (!b) return false;
      b.click();
      return true;
    },
    clickLink(text) {
      const links = Array.from(document.querySelectorAll("a"));
      const a = links.find(x => (x.textContent || "").trim().toLowerCase().includes(text.toLowerCase()));
      if (!a) return false;
      a.click();
      return true;
    },
    setInput(kind, value) {
      const sel = kind === "password" ? "input[type=password]"
        : kind === "email" ? "input[type=email]"
        : `input[${kind}], textarea[${kind}], ${kind}`;
      const el = document.querySelector(sel);
      if (!el) return false;
      el.value = value;
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    },
    bodyText() { return document.body.innerText; },
    hash() { return location.hash || "#/overview"; },
    nav(hash) { location.hash = hash; },
    async wait(ms) { await new Promise(r => setTimeout(r, ms)); },
  };
  return "uat installed";
}
