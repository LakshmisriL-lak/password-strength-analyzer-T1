const $ = id => document.getElementById(id);
const input = $("pw");
let timer, latest = 0;

function color(score) {
  return score < 30 ? "#e5484d" : score < 50 ? "#f76b15" : score < 70 ? "#e5a50a" : "#30a46c";
}

function li(text, cls, icon) {
  const el = document.createElement("li");
  if (cls) el.className = cls;
  if (icon) {
    const i = document.createElement("span");
    i.className = "i";
    i.textContent = icon;
    el.append(i);
  }
  el.append(document.createTextNode(text));
  return el;
}

function render(d, hasText) {
  $("bar").style.width = d.score + "%";
  $("bar").style.background = color(d.score);
  $("label").textContent = hasText ? `${d.label} (${d.score}/100)` : "—";
  $("label").style.color = hasText ? color(d.score) : "";
  $("entropy").textContent = `Entropy: ${d.entropy} bits`;

  $("checks").replaceChildren(...d.checks.map(c =>
    li(c.name, hasText && c.ok ? "ok" : "no", hasText && c.ok ? "✔" : "✖")));

  $("tips").replaceChildren(...(hasText
    ? d.feedback.map(t => li("• " + t))
    : [li("Start typing…")]));

  $("sugs").replaceChildren(...d.suggestions.map(s => {
    const row = document.createElement("div");
    row.className = "sug";
    const code = document.createElement("code");
    code.textContent = s;
    const btn = document.createElement("button");
    btn.textContent = "Copy";
    btn.onclick = () => {
      navigator.clipboard.writeText(s);
      btn.textContent = "Copied ✔";
      setTimeout(() => (btn.textContent = "Copy"), 1200);
    };
    row.append(code, btn);
    return row;
  }));
}

async function check() {
  const id = ++latest;
  const res = await fetch("/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: input.value }),
  });
  const d = await res.json();
  if (id === latest) render(d, input.value.length > 0);   // ignore stale responses
}

// debounce: wait 200ms after the last keystroke
input.addEventListener("input", () => {
  clearTimeout(timer);
  timer = setTimeout(check, 200);
});

$("toggle").onclick = () => {
  const hidden = input.type === "password";
  input.type = hidden ? "text" : "password";
  $("toggle").textContent = hidden ? "Hide" : "Show";
};

$("save").onclick = async () => {
  const res = await fetch("/save", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: input.value, username: $("user").value }),
  });
  const d = await res.json();
  $("msg").textContent = d.message;
  $("msg").style.color = d.ok ? "#30a46c" : "#e5484d";
};

check();
