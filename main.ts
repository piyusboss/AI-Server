/* main.ts - Updated with Ban Route */
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { handleCreateChat } from "./New_chat.js"; // Note: .js extension for Deno imports
// 🔥 Import the new handler
import { handleReportViolation } from "./chat_ban.ts";

const FIREBASE_API_KEY = "AIzaSyA5pQNoLixbthxXZ6pMBy_bgahiVxpRSR0"; 

serve(async (req) => {
  const url = new URL(req.url);

  // CORS Headers
  const headers = new Headers({
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  });

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  // --- SHARED AUTH LOGIC (Extract User & Service Token) ---
  // Har request ke liye humein user verify karna hai aur service token chahiye
  // Isliye hum ise wrapper mein daal rahe hain taaki code clean rahe
  
  if (req.method === "POST") {
    try {
        // 1. Verify User
        const authHeader = req.headers.get("Authorization");
        if (!authHeader?.startsWith("Bearer ")) {
            return new Response(JSON.stringify({ error: "No token provided" }), { status: 401, headers });
        }
        const userToken = authHeader.split("Bearer ")[1];
        const userData = await verifyUserToken(userToken);
        const userId = userData.localId;

        // 2. Get Server Access
        const serviceAccount = getServiceAccount();
        const accessToken = await getGoogleAccessToken(serviceAccount);

        // --- ROUTING ---

        // Route 1: Create Chat
        if (url.pathname === "/create-chat") {
            // Note: Create chat logic abhi wahi purana wala use kar rahe hain jo main.ts mein integrated tha
            // ya agar aapne New_chat.js alag rakha hai toh use call karein.
            // Main yahan "Inline" logic use kar raha hoon consistency ke liye jo pichle step mein tha.
            // Agar aapne pichla code use kiya tha toh:
            return await createChatHandler(req, serviceAccount.project_id, accessToken, userId);
        }

        // Route 2: Report Violation (NEW) 🔥
        if (url.pathname === "/report-violation") {
            return await handleReportViolation(req, accessToken, serviceAccount.project_id, userId);
        }

    } catch (error) {
        console.error("Server Error:", error.message);
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
    }
  }

  return new Response("Nexari AI Secure Server Active", { status: 200 });
});

// --- HELPER FUNCTIONS ---

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

// Inline Handler for Create Chat (reusing previous logic)
async function createChatHandler(req: Request, projectId: string, accessToken: string, userId: string) {
    const body = await req.json();
    let title = body.title ? body.title.trim() : "New Chat";
    if (title.length > 50) title = title.substring(0, 50);

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
    return new Response(JSON.stringify({ success: true, chatId: pathParts[pathParts.length - 1], title }), { status: 200, headers: { "Content-Type": "application/json" } });
}

// Google Auth (Pure Crypto)
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
