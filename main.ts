/* main.ts (Host: piyusboss-ai-server-22) - Database Manager */
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

const FIREBASE_API_KEY = "AIzaSyA5pQNoLixbthxXZ6pMBy_bgahiVxpRSR0"; 
const SERVICE_SECRET = Deno.env.get("NEXARI_SERVICE_SECRET") ?? "SUPER_SECRET_INTERNAL_KEY_999"; 

serve(async (req) => {
  const url = new URL(req.url);
  const headers = new Headers({
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Service-Key"
  });

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });

  // === 🚀 ROUTE: SUBMIT FEEDBACK (SECURE PROXY) ===
  if (url.pathname === "/submit-feedback" && req.method === "POST") {
      try {
        // 🔐 SECURITY CHECK 1: Must come from PHP Proxy (Service Key)
        const serviceKey = req.headers.get("X-Service-Key");
        if (serviceKey !== SERVICE_SECRET) {
            throw new Error("Access Denied: Direct Access Not Allowed. Use the App.");
        }

        // 🔐 SECURITY CHECK 2: Authenticate User
        const authHeader = req.headers.get("Authorization");
        if (!authHeader?.startsWith("Bearer ")) throw new Error("No token provided");
        const token = authHeader.split("Bearer ")[1];
        const userData = await verifyUserToken(token); // Verify Google Token
        const userId = userData.localId;
        const email = userData.email || "Anonymous";

        const body = await req.json(); // { message, type, rating, deviceInfo }

        // --- 🧠 LOGIC: RATE LIMITING (3/24 Hours) ---
        const serviceAccount = getServiceAccount();
        const accessToken = await getGoogleAccessToken(serviceAccount);
        const projectId = serviceAccount.project_id;

        // 1. User Stats fetch karo
        const userStats = await getFirestoreUserStats(projectId, accessToken, userId);
        
        const now = Date.now();
        const oneDayMs = 24 * 60 * 60 * 1000;
        let count = 0;
        let lastReset = now;

        if (userStats) {
            const lastResetTime = parseInt(userStats.lastReset?.integerValue || "0");
            const storedCount = parseInt(userStats.count?.integerValue || "0");

            if ((now - lastResetTime) < oneDayMs) {
                // Under 24 hours -> Count maintain karo
                count = storedCount;
                lastReset = lastResetTime;
            } else {
                // 24 hours passed -> Reset
                count = 0;
                lastReset = now;
            }
        }

        // 🛑 RULE: Limit Check
        if (count >= 3) {
             return new Response(JSON.stringify({ error: "Daily limit reached (3/3). Try again tomorrow!" }), { status: 429, headers });
        }

        // 2. Submit Feedback to 'app_feedback'
        await createFirestoreFeedback(projectId, accessToken, userId, email, body);

        // 3. Update User Stats (Count + 1)
        await updateFirestoreUserStats(projectId, accessToken, userId, count + 1, lastReset);

        console.log(`[Feedback] Success: ${userId} (Count: ${count + 1})`);
        return new Response(JSON.stringify({ success: true, count: count + 1 }), { status: 200, headers });

      } catch (e: any) { 
          console.error("Feedback Error:", e.message);
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers }); 
      }
  }

  // ... (Existing /create-chat and /report-violation routes remain here) ...
  // (Keep your previous logic for Create Chat and Report Violation exactly as is)
  
  if (url.pathname === "/create-chat" && req.method === "POST") {
       try {
        const authHeader = req.headers.get("Authorization");
        if (!authHeader?.startsWith("Bearer ")) throw new Error("No token provided");
        const token = authHeader.split("Bearer ")[1];
        const userData = await verifyUserToken(token);
        const userId = userData.localId;
        const body = await req.json();
        const serviceAccount = getServiceAccount();
        const accessToken = await getGoogleAccessToken(serviceAccount);
        const chatId = await createFirestoreChat(serviceAccount.project_id, accessToken, userId, body.title || "New Chat");
        return new Response(JSON.stringify({ success: true, chatId: chatId }), { status: 200, headers });
      } catch (e: any) { return new Response(JSON.stringify({ error: e.message }), { status: 500, headers }); }
  }

  return new Response("Nexari AI Backend Running", { status: 200 });
});

// === HELPER FUNCTIONS ===
function getServiceAccount() { const json = Deno.env.get("FIREBASE_SERVICE_ACCOUNT"); if (!json) throw new Error("Missing Env"); return JSON.parse(json); }
async function verifyUserToken(token: string) { const res = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ idToken: token }) }); const data = await res.json(); if (data.error) throw new Error("Invalid Token"); return data.users[0]; }
async function getGoogleAccessToken(serviceAccount: any) {
  const pem = serviceAccount.private_key; const clientEmail = serviceAccount.client_email;
  const pemContents = pem.substring(27, pem.length - 25).replace(/\s/g, "");
  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", binaryDer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: clientEmail, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", exp: now + 3600, iat: now };
  const sHead = btoa(JSON.stringify({ alg: "RS256", typ: "JWT" })); const sPay = btoa(JSON.stringify(payload));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${sHead}.${sPay}`));
  const sSig = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${sHead}.${sPay}.${sSig}` });
  return (await tokenRes.json()).access_token;
}

// --- FIRESTORE HELPERS (Updated) ---
// 1. Get User Stats
async function getFirestoreUserStats(projectId: string, accessToken: string, userId: string) {
    const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${userId}`;
    const res = await fetch(url, { headers: { "Authorization": `Bearer ${accessToken}` } });
    if (!res.ok) return null;
    const data = await res.json();
    if (data.fields && data.fields.feedback_stats) {
        return data.fields.feedback_stats.mapValue.fields;
    }
    return null;
}

// 2. Update User Stats
async function updateFirestoreUserStats(projectId: string, accessToken: string, userId: string, count: number, lastReset: number) {
    const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${userId}?updateMask.fieldPaths=feedback_stats`;
    const docData = { fields: { feedback_stats: { mapValue: { fields: { 
        count: { integerValue: count.toString() },
        lastReset: { integerValue: lastReset.toString() }
    }}}}};
    await fetch(url, { method: "PATCH", headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" }, body: JSON.stringify(docData) });
}

// 3. Create Feedback
async function createFirestoreFeedback(projectId: string, accessToken: string, userId: string, email: string, data: any) {
    const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/app_feedback`;
    const docData = { fields: { 
        userId: { stringValue: userId },
        userEmail: { stringValue: email },
        message: { stringValue: data.message || "" },
        category: { stringValue: data.type || "other" },
        rating: { stringValue: data.rating || "none" },
        deviceInfo: { stringValue: data.deviceInfo || "unknown" },
        timestamp: { timestampValue: new Date().toISOString() },
        status: { stringValue: "open" }
    }};
    await fetch(url, { method: "POST", headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" }, body: JSON.stringify(docData) });
}

// (Existing Helper: createFirestoreChat needed for existing routes)
async function createFirestoreChat(projectId: string, accessToken: string, userId: string, title: string) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${userId}/chats`;
  const docData = { fields: { title: { stringValue: title }, createdAt: { timestampValue: new Date().toISOString() }, violationCount: { integerValue: "0" }, isBanned: { booleanValue: false } } };
  const res = await fetch(url, { method: "POST", headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" }, body: JSON.stringify(docData) });
  const data = await res.json(); const parts = data.name.split("/"); return parts[parts.length - 1];
}
