(() => {
  const status = document.getElementById("status");
  const fail = () => {
    status.textContent = "Unable to connect to the local review desk.";
  };
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null, "", location.pathname);

  if (token === null || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    fail();
    return;
  }

  void fetch("/api/session", {
    method: "POST",
    headers: {"X-ArtifactDiff-Session": token},
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error("session exchange failed");
      }
      return response.json();
    })
    .then((session) => {
      if (!session || typeof session.csrf_token !== "string") {
        throw new Error("invalid session response");
      }
      status.textContent = "Connected to the local review desk.";
    })
    .catch(fail);
})();
