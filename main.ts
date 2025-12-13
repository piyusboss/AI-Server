/* main.ts (Updated: Secure Ban Logic Added) */
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

const FIREBASE_API_KEY = "AIzaSyA5pQNoLixbthxXZ6pMBy_bgahiVxpRSR0"; 

serve(async (req) => {
  const url = new URL(req.url);

  const headers = new Headers({
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  });

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  // --- ROUTE 1: CREATE CHAT ---
  if (url.pathname === "/create-chat" && req.method === "POST") {
    try {
      const { userId } = await authenticateRequest(req);
      const body = await req.json();
      let title = body.title ? body.title.trim() : "New Chat";
      if (title.length > 50) title = title.substring(0, 50);

      const serviceAccount = getServiceAccount();
      const accessToken = await getGoogleAccessToken(serviceAccount);

      const chatId = await createFirestoreChat(serviceAccount.project_id, accessToken, userId, title);

      return new Response(JSON.stringify({ success: true, chatId: chatId, title: title }), { status: 200, headers });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
    }
  }

  // --- ROUTE 2: REPORT VIOLATION (SECURE BAN LOGIC) ---
  if (url.pathname === "/report-violation" && req.method === "POST") {
    try {
      // 1. Authenticate
      const { userId } = await authenticateRequest(req);
      const body = await req.json();
      const chatId = body.chatId;

      if (!chatId) throw new Error("Chat ID required");

      const serviceAccount = getServiceAccount();
      const accessToken = await getGoogleAccessToken(serviceAccount);
      const projectId = serviceAccount.project_id;

      // 2. Read Current Chat Data Securely
      const chatData = await getFirestoreChat(projectId, accessToken, userId, chatId);
      
      // 3. Logic: Increment Count & Check Ban
      let currentCount = parseInt(chatData.fields?.violationCount?.integerValue || "0");
      let isBanned = chatData.fields?.isBanned?.booleanValue || false;

      currentCount++;

      // BAN THRESHOLD (Server Side Config - Secure)
      const MAX_VIOLATIONS = 3; 
      if (currentCount >= MAX_VIOLATIONS) {
        isBanned = true;
      }

      // 4. Update Firestore securely
      await updateFirestoreBanStatus(projectId, accessToken, userId, chatId, currentCount, isBanned);

      console.log(`[Security] Violation logged for ${userId}. Count: ${currentCount}. Banned: ${isBanned}`);

      return new Response(JSON.stringify({ 
        success: true, 
        isBanned: isBanned,
        violationCount: currentCount
      }), { status: 200, headers });

    } catch (error) {
      console.error("Violation Report Error:", error.message);
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
    }
  }

  return new Response("Nexari AI Secure Server Running", { status: 200 });
});

// --- HELPER FUNCTIONS ---

async function authenticateRequest(req: Request) {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    throw new Error("No token provided");
  }
  const token = authHeader.split("Bearer ")[1];
  const userData = await verifyUserToken(token);
  return { userId: userData.localId };
}

function getServiceAccount() {
  const json = Deno.env.get("FIREBASE_SERVICE_ACCOUNT");
  if (!json) throw new Error("Missing FIREBASE_SERVICE_ACCOUNT env var");
  return JSON.parse(json);
}

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

// --- FIRESTORE REST HELPERS ---

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
  const pathParts = data.name.split("/");
  return pathParts[pathParts.length - 1];
}

async function getFirestoreChat(projectId: string, accessToken: string, userId: string, chatId: string) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${userId}/chats/${chatId}`;
  const res = await fetch(url, {
    headers: { "Authorization": `Bearer ${accessToken}` }
  });
  if (!res.ok) throw new Error("Chat not found");
  return await res.json();
}

async function updateFirestoreBanStatus(projectId: string, accessToken: string, userId: string, chatId: string, count: number, banned: boolean) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${userId}/chats/${chatId}?updateMask.fieldPaths=violationCount&updateMask.fieldPaths=isBanned`;
  
  const docData = {
    fields: {
      violationCount: { integerValue: count.toString() },
      isBanned: { booleanValue: banned }
    }
  };

  const res = await fetch(url, {
    method: "PATCH",
    headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify(docData)
  });
  
  if (!res.ok) throw new Error("Failed to update ban status");
  return await res.json();
}

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
