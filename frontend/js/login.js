(async function redirectIfAuthed() {
  const token = localStorage.getItem("token");
  if (!token) {
    document.documentElement.classList.remove("auth-pending");
    return;
  }
  const resp = await fetch("/api/auth/me", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (resp.ok) {
    location.replace("/dashboard");
    return;
  }
  localStorage.removeItem("token");
  document.documentElement.classList.remove("auth-pending");
})();

const output = document.getElementById("login-output");
const form = document.getElementById("login-form");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(form);
  const payload = {
    username: data.get("username"),
    password: data.get("password"),
  };
  const resp = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await resp.json();
  if (!resp.ok) {
    output.textContent = JSON.stringify(body, null, 2);
    return;
  }
  localStorage.setItem("token", body.access_token);
  window.location.href = "/dashboard";
});
