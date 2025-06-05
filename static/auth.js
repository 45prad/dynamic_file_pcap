const PROXY_API = "http://localhost:5002";

window.onload = async () => {
  try {
    await ensureAuthenticated();

    const path = window.location.pathname;
    if (path.endsWith("/pcapdeepdive")) {
      await fetchPcapDeepDive();
    }
    else if (path.endsWith("/chatgptchallenge")) {
      await fetchChatGPTChallenge();
    }
     else if (path.endsWith("/procnetchallenge")) {
      await fetchProcnetChallenge();
    }
     else if (path.endsWith("/aiChallenge")) {
      await fetchAiChallenge();
    }
     else {
       await ensureAuthenticated();
    }

  } catch (err) {
    console.error("Authentication failed:", err);
  }
};

// Function to check and handle authentication
async function ensureAuthenticated() {
  let token = localStorage.getItem("Hactify-Auth-token");

  if (!token) {
    token = await handleLoginPrompt();
    if (!token) {
      throw new Error("Login required");
    }
  }
  return token;
}

// Prompt-based login handler
async function handleLoginPrompt() {
  try {
    const email = prompt("Enter your email:");
    if (!email) return null;

    const password = prompt("Enter your password:");
    if (!password) return null;

    const response = await fetch(`${PROXY_API}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (data.success) {
      localStorage.setItem("Hactify-Auth-token", data.authtoken);
      alert("Login successful!");
      return data.authtoken;
    } else {
      alert("Login failed: " + (data.error || "Unknown error"));
      return null;
    }
  } catch (err) {
    alert("Login error: " + err.message);
    return null;
  }
}

// Fetch regular PCAP
async function fetchPcap() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/get_pcap`, { token });
}

// Fetch PCAP Deep Dive (only token required)
async function fetchPcapDeepDive() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/pcapdeepdive`, { token });
}

async function fetchChatGPTChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/chatgptchallenge`, { token });
}

async function fetchProcnetChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/procnetchallenge`, { token });
}

async function fetchAiChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/aichallenge`, { token });
}

// Shared download logic
async function downloadZip(apiUrl, bodyData) {
   const statusDiv = document.getElementById("download-status");
  try {
      if (statusDiv) statusDiv.style.display = "block";

    const response = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(bodyData)
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = downloadUrl;

    let filename = "challenge.zip";
    const contentDisposition = response.headers.get("Content-Disposition");
    if (contentDisposition) {
      const match = contentDisposition.match(/filename="?(.+\.zip)"?/i);
      if (match) filename = match[1];
    }

    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(downloadUrl);
  } catch (err) {
    console.error("Error:", err);
    alert("Failed to download PCAP file: " + err.message);
    throw err;
  }
  finally {
    // Hide the message after a short delay
    if (statusDiv) {
      setTimeout(() => {
        statusDiv.style.display = "none";
      }, 2000);
    }
  }
}
