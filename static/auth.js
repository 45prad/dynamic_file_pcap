const PROXY_API = "http://localhost:5002";

window.onload = async () => {
  try {
    await ensureAuthenticated();
   
    await fetchPcap();
    
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


async function fetchPcap() {  
  const token = await ensureAuthenticated();

  try {
    const response = await fetch(`${PROXY_API}/get_pcap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token })
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    // Create a downloadable file from the blob
    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = downloadUrl;

    // Extract filename from content-disposition or use default
    const contentDisposition = response.headers.get("Content-Disposition");
    let filename = "challenge.zip";  // Default filename
    
    if (contentDisposition) {
      const match = contentDisposition.match(/filename="?(.+\.zip)"?/i);
      if (match) {
        filename = match[1];
      }
    }

    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(downloadUrl);
  } catch (err) {
    console.error("Error:", err);
    alert("Failed to download pcap file: " + err.message);
    throw err;
  }
}
