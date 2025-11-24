const PROXY_API = "http://localhost:5002";

window.onload = async () => {
  try {
    await ensureAuthenticated();

    const path = window.location.pathname;
    if (path.endsWith("/uav")) {
      await fetchUAV();
    }
      else if  (path.endsWith("/signalinvoid")) {
      await fetchsatcomm3();
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
  let token = localStorage.getItem("Auth-token");

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

    if (data.token) {
      localStorage.setItem("Auth-token", data.token);
      alert("Login successful!");
      return data.token;
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
async function fetchUAV() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/uav`, { token });
}

async function fetchsatcomm3() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/signalInVoid`, { token });
}



// Shared download logic for ZIP files
async function downloadZip(apiUrl, bodyData) {
  const statusDiv = document.getElementById("download-status");
  const downloadText = document.getElementById("download-text");
  
  try {
    if (statusDiv) {
      statusDiv.style.display = "block";
      downloadText.textContent = "Preparing challenge file...";
    }

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

    if (statusDiv) {
      downloadText.textContent = "challenge download complete!";
    }
  } catch (err) {
    console.error("Error:", err);
    if (statusDiv) {
      downloadText.textContent = "Download failed!";
    }
    alert("Failed to download ZIP file: " + err.message);
    throw err;
  } finally {
    if (statusDiv) {
      setTimeout(() => {
        statusDiv.style.display = "none";
        downloadText.textContent = "Downloading challenge file...";
      }, 3000);
    }
  }
}

// Shared download logic for 7Z files

