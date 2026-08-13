const token = new URLSearchParams(location.hash.slice(1)).get("token");
history.replaceState(null, "", location.pathname);

const status = document.getElementById("status");
const session = await fetch("/api/session", {
  method: "POST",
  headers: {"X-ArtifactDiff-Session": token},
}).then((response) => response.json());

status.textContent = session.csrf_token ? "Connected to the local review desk." : "Connection failed.";
