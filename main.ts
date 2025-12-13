import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

// --- CONFIGURATION ---
// Yeh wahi API Key hai jo aapke firebase_logic.js mein thi
const FIREBASE_API_KEY = "AIzaSyA5pQNoLixbthxXZ6pMBy_bgahiVxpRSR0"; 

// --- MAIN SERVER LOGIC ---
serve(async (req) => {
  const url = new URL(req.url);

  // CORS Headers (Browser ko allow karne ke liye)
  const headers = new Headers({
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  });

  // Preflight Request Handle karo
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  // Route: Create Chat
  if (url.pathname === "/create-chat" && req.method === "POST") {
    try {
      // 1. User ka Token nikalo
      const authHeader = req.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return new Response(JSON.stringify({ error: "No token provided" }), { status: 401, headers });
      }
      const userToken = authHeader.split("Bearer ")[1];

      // 2. User ko Verify karo (Using Google Identity API)
      const userData = await verifyUserToken(userToken);
      const userId = userData.localId;

      // 3. Request Body se Title lo
      const body = await req.json();
      let title = body.title ? body.title.trim() : "New Chat";
      if (title.length > 50) title = title.substring(0, 50);

      // 4. Server Authenticate karo (Get Service Account Access Token)
      const serviceAccount = getServiceAccount();
      const accessToken = await getGoogleAccessToken(serviceAccount);

      // 5. Firestore mein naya Chat banao (Using REST API)
      const chatId = await createFirestoreChat(serviceAccount.project_id, accessToken, userId, title);

      console.log(`[Success] Chat created: ${chatId} for user: ${userId}`);

      return new Response(JSON.stringify({ 
        success: true, 
        chatId: chatId, 
        title: title 
      }), { status: 200, headers });

    } catch (error) {
      console.error("Error:", error.message);
      return new Response(JSON.stringify({ error: error.message || "Server Error" }), { status: 500, headers });
    }
  }

  return new Response("Nexari AI Lightweight Server Running", { status: 200 });
});

// --- HELPER FUNCTIONS (MAGIC HAPPENS HERE) ---

// 1. Service Account Env Variable Parse karo
function getServiceAccount() {
  const json = Deno.env.get("FIREBASE_SERVICEACCOUNT");
  if (!json) throw new Error("Missing FIREBASE_SERVICE_ACCOUNT env var");
  return JSON.parse(json);
}

// 2. User Token Verify karo
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

// 3. Firestore mein Document Create karo
async function createFirestoreChat(projectId: string, accessToken: string, userId: string, title: string) {
  // Firestore REST API Endpoint
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${userId}/chats`;
  
  const docData = {
    fields: {
      title: { stringValue: title },
      createdAt: { timestampValue: new Date().toISOString() },
      violationCount: { integerValue: "0" }, // Secure Field
      isBanned: { booleanValue: false }      // Secure Field
    }
  };

  const res = await fetch(url, {
    method: "POST",
    headers: { 
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(docData)
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Firestore Error: ${err}`);
  }

  const data = await res.json();
  // Firestore returns full path, we need just the ID
  const pathParts = data.name.split("/");
  return pathParts[pathParts.length - 1];
}

// 4. Google Service Account Auth (Pure Web Crypto - No Libraries!)
async function getGoogleAccessToken(serviceAccount: any) {
  const pem = serviceAccount.private_key;
  const clientEmail = serviceAccount.client_email;
  
  // PEM Key ko Binary mein convert karo
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length - 1).replace(/\s/g, "");
  const binaryDerString = atob(pemContents);
  const binaryDer = new Uint8Array(binaryDerString.length);
  for (let i = 0; i < binaryDerString.length; i++) {
    binaryDer[i] = binaryDerString.charCodeAt(i);
  }

  // Key Import karo
  const key = await crypto.subtle.importKey(
    "pkcs8",
    binaryDer.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  // JWT Header & Payload banao
  const header = { alg: "RS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now
  };

  const strHeader = btoa(JSON.stringify(header));
  const strPayload = btoa(JSON.stringify(payload));
  const unsignedToken = `${strHeader}.${strPayload}`;

  // Sign karo
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsignedToken)
  );

  // JWT finalize karo
  // Deno ka btoa standard nahi hai URL safe ke liye, so replace karo
  const base64UrlSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    
  const jwt = `${unsignedToken}.${base64UrlSignature}`;

  // Google se Access Token mango
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });

  const tokenData = await tokenRes.json();
  return tokenData.access_token;
}
