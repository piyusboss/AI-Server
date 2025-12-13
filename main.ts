/* main.ts - Universal Server (Create + Ban) */
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

// --- CONFIGURATION ---
const FIREBASE_API_KEY = "AIzaSyA5pQNoLixbthxXZ6pMBy_bgahiVxpRSR0"; 

serve(async (req) => {
  const url = new URL(req.url);

  // 1. CORS Headers (Browser access allow karne ke liye)
  const headers = new Headers({
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  });

  // Preflight Request Handle
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  // Sirf POST requests allow karein
  if (req.method === "POST") {
    try {
        // 2. User Authentication (Common for all routes)
        const authHeader = req.headers.get("Authorization");
        if (!authHeader?.startsWith("Bearer ")) {
            return new Response(JSON.stringify({ error: "No token provided" }), { status: 401, headers });
        }
        const userToken = authHeader.split("Bearer ")[1];
        
        // Google se User Verify karein
        const userData = await verifyUserToken(userToken);
        const userId = userData.localId;

        // 3. Server Authentication (Service Account Access)
        const serviceAccount = getServiceAccount();
        const accessToken = await getGoogleAccessToken(serviceAccount);
        const projectId = serviceAccount.project_id;

        // --- ROUTING LOGIC ---

        // Route A: Create New Chat
        if (url.pathname === "/create-chat") {
            const body = await req.json();
            let title = body.title ? body.title.trim() : "New Chat";
            if (title.length > 50) title = title.substring(0, 50);

            const chatId = await createFirestoreChat(projectId, accessToken, userId, title);
            
            console.log(`[Create] Success: ${chatId}`);
            return new Response(JSON.stringify({ success: true, chatId, title }), { status: 200, headers });
        }

        // Route B: Report Violation (Ban Logic)
        if (url.pathname === "/report-violation") {
            const body = await req.json();
            const chatId = body.chatId;
            if (!chatId) throw new Error("Missing chatId");

            const result = await handleBanLogic(projectId, accessToken, userId, chatId);
            
            console.log(`[Violation] Chat: ${chatId}, Count: ${result.violationCount}, Banned: ${result.isBanned}`);
            return new Response(JSON.stringify(result), { status: 200, headers });
        }

        return new Response(JSON.stringify({ error: "Route not found" }), { status: 404, headers });

    } catch (error) {
        console.error("Server Error:", error.message);
        return new Response(JSON.stringify({ error: error.message || "Internal Error" }), { status: 500, headers });
    }
  }

  return new Response("Nexari AI Server Active", { status: 200 });
});

// --- HELPER FUNCTIONS ---

// 1. Env Variable Parser
function getServiceAccount() {
  const json = Deno.env.get("FIREBASE_SERVICE_ACCOUNT");
  if (!json) throw new Error("Missing FIREBASE_SERVICE_ACCOUNT env var");
  return JSON.parse(json);
}

// 2. User Token Verification
async function verifyUserToken(token: string) {
  const res = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ idToken: token })
  });
  const data = await res.json();
  if (data.error) throw new Error("Invalid User Token");
  return data.users[0];
}

// 3. Firestore: Create Chat
async function createFirestoreChat(projectId: string, accessToken: string, userId: string, title: string) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${userId}/chats`;
  const docData = {
    fields: {
      title: { stringValue: title },
      createdAt: { timestampValue: new Date().toISOString() },
      violationCount: { integerValue: "0" },
      isBanned: { booleanValue: false }
    }
  };
  const res = await fetch(url, {
    method: "POST",
    headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify(docData)
  });
  if (!res.ok) throw new Error(await res.text());
  const data = await res.json();
  return data.name.split("/").pop(); // Extract ID
}

// 4. Firestore: Ban Logic (Read -> Increment -> Update)
async function handleBanLogic(projectId: string, accessToken: string, userId: string, chatId: string) {
    const firestoreUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${userId}/chats/${chatId}`;
    
    // Step A: Get Current Data
    const getRes = await fetch(firestoreUrl, {
        headers: { "Authorization": `Bearer ${accessToken}` }
    });
    if (!getRes.ok) throw new Error("Chat not found");
    const chatDoc = await getRes.json();
    
    // Step B: Increment Count
    const currentCount = parseInt(chatDoc.fields?.violationCount?.integerValue || "0");
    const newCount = currentCount + 1;
    const BAN_THRESHOLD = 3; // 3 Strikes Rule
    const shouldBan = newCount >= BAN_THRESHOLD;

    // Step C: Update (PATCH)
    const updateData: any = {
        fields: {
            violationCount: { integerValue: newCount.toString() },
            isBanned: { booleanValue: shouldBan }
        }
    };
    if (shouldBan) {
        updateData.fields.bannedAt = { timestampValue: new Date().toISOString() };
    }

    // URL Param me fields batane padte hain jo update karne hain
    let patchUrl = `${firestoreUrl}?updateMask.fieldPaths=violationCount&updateMask.fieldPaths=isBanned`;
    if (shouldBan) patchUrl += `&updateMask.fieldPaths=bannedAt`;

    const patchRes = await fetch(patchUrl, {
        method: "PATCH",
        headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify(updateData)
    });

    if (!patchRes.ok) throw new Error(await patchRes.text());

    return { success: true, violationCount: newCount, isBanned: shouldBan };
}

// 5. Google Service Account Auth (Zero Dependency Crypto)
async function getGoogleAccessToken(serviceAccount: any) {
  const pem = serviceAccount.private_key;
  const clientEmail = serviceAccount.client_email;
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length - 1).replace(/\s/g, "");
  const binaryDerString = atob(pemContents);
  const binaryDer = new Uint8Array(binaryDerString.length);
  for (let i = 0; i < binaryDerString.length; i++) { binaryDer[i] = binaryDerString.charCodeAt(i); }
  const key = await crypto.subtle.importKey("pkcs8", binaryDer.buffer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const header = { alg: "RS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: clientEmail, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", exp: now + 3600, iat: now };
  const strHeader = btoa(JSON.stringify(header));
  const strPayload = btoa(JSON.stringify(payload));
  const unsignedToken = `${strHeader}.${strPayload}`;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsignedToken));
  const base64UrlSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const jwt = `${unsignedToken}.${base64UrlSignature}`;
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}` });
  const tokenData = await tokenRes.json();
  return tokenData.access_token;
}
