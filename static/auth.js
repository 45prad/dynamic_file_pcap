const PROXY_API = "http://localhost:5002";

window.onload = async () => {
  try {
    await ensureAuthenticated();

    const path = window.location.pathname;
    if (path.endsWith("/pcapdeepdive")) {
      await fetchPcapDeepDive();
    }
    else if (path.endsWith("/chatgptv2")) {
      await fetchChatGPTChallenge();
    }
     else if (path.endsWith("/c2Hunt")) {
      await fetchProcnetChallenge();
    }
     else if (path.endsWith("/socVsLlm")) {
      await fetchAiChallenge();
    }
      else if (path.endsWith("/operationBackDoor")) {
      await fetchBackDoorChallenge();
    }
     else if (path.endsWith("/springBoot")) {
      await fetchspringBootChallenge();
    }

     else if (path.endsWith("/shadowsInTheWeb")) {
      await fetchShadowsInTheWebChallenge();
    }

    else if (path.endsWith("/aiEvasion")) {
      await fetchAiEvasionChallenge();
    }

     else if (path.endsWith("/apiFootPrint")) {
      await fetchApiFootprintChallenge();
    }

     else if (path.endsWith("/maldocTrap")) {
      await fetchMalDocChallenge();
    }

     else if (path.endsWith("/lemonDuck")) {
      await fetchLemonDuckChallenge();
    }

     else if (path.endsWith("/jsploit")) {
      await fetchJsploitChallenge();
    }

    else if (path.endsWith("/cloudTrail")) {
      await fetchCloudTrailChallenge();
    }

    else if (path.endsWith("/timeSeriesTrap")) {
      await fetchTimeSeriesTrapChallenge();
    }

    else if (path.endsWith("/splitFiction")) {
      await fetchsplitFictionChallenge();
    }

    else if (path.endsWith("/encryptedLogForensics")) {
      await fetchEncryptedLogChallenge();
    }

     else if (path.endsWith("/bgpChallenge")) {
      await fetchBGPChallenge();
    }

    else if (path.endsWith("/mqtt")) {
      await fetchMqttChallenge();
    }


     else if (path.endsWith("/kubernetesCanaryBreach")) {
      await fetchkubernetesChallenge();
    }

      else if (path.endsWith("/shadowInCiMassive")) {
      await fetchshadowInCiMassiveChallenge();
    }

     else if (path.endsWith("/BeaconInTheDark")) {
      await fetchBeaconInTheDarkChallenge();
    }

    else if (path.endsWith("/supplychain")) {
      await fetchsupplyChainChallenge();
    }

    
    else if (path.endsWith("/goldenticket")) {
      await fetchgoldenTicketChallenge();
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

    if (data.success) {
      localStorage.setItem("Auth-token", data.authtoken);
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

async function fetchBackDoorChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/backdoor`, { token });
}

async function fetchspringBootChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/springboot`, { token });
}

async function fetchShadowsInTheWebChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/ShadowsInTheWeb`, { token });
}



async function fetchAiEvasionChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/AiEvasion`, { token });
}


async function fetchApiFootprintChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/ApiFootprint`, { token });
}


async function fetchMalDocChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/maldocchallenge`, { token });
}

async function fetchLemonDuckChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/lemondock`, { token });
}

async function fetchJsploitChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/jsploit`, { token });
}

async function fetchCloudTrailChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/cloudTrail`, { token });
}

async function fetchTimeSeriesTrapChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/timeseriestrap`, { token });
}


async function fetchsplitFictionChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/splitFiction`, { token });
}


async function fetchEncryptedLogChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/EncryptedLogForensics`, { token });
}


async function fetchBGPChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/bgp`, { token });
}


async function fetchMqttChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/mqtt`, { token });
}


async function fetchkubernetesChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/kubernetes`, { token });
}



async function fetchshadowInCiMassiveChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/shadowInCiMassive`, { token });
}

async function fetchBeaconInTheDarkChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/BeaconInTheDark`, { token });
}

async function fetchsupplyChainChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/supplychain`, { token });
}

async function fetchgoldenTicketChallenge() {
  const token = await ensureAuthenticated();
  return downloadZip(`${PROXY_API}/goldenticket`, { token });
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
async function download7z(apiUrl, bodyData) {
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

    let filename = "challenge.7z";
    const contentDisposition = response.headers.get("Content-Disposition");
    if (contentDisposition) {
      const match = contentDisposition.match(/filename="?(.+\.7z)"?/i);
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
    alert("Failed to download 7Z file: " + err.message);
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
