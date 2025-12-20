/* main.ts (Updated for Nexari AI) - Database Manager */
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

// 🔥 NEW NEXARI AI API KEY
const FIREBASE_API_KEY = "AIzaSyB2de7u59F6fqBCbDDDt-c4gKFr5rs-IKw"; 

// 🔥 SERVICE SECRET (Keep this consistent in your Env Vars)
const SERVICE_SECRET = Deno.env.get("NEXARI_SERVICE_SECRET") ?? "SUPER_SECRET_INTERNAL_KEY_999"; 

serve(async (req) => {
  const url = new URL(req.url);
  const headers = new Headers({
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Service-Key"
  });

  // Handle CORS Preflight
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });

  // === 🚀 ROUTE: CREATE CHAT ===
  if (url.pathname === "/create-chat" && req.method === "POST") {
       try {
        const authHeader = req.headers.get("Authorization");
        if (!authHeader?.startsWith("Bearer ")) throw new Error("No token provided");
        
        const token = authHeader.split("Bearer ")[1];
        
        // Verify User using New API Key
        const userData = await verifyUserToken(token);
        const userId = userData.localId;
        
        const body = await req.json();
        
        // Get Service Account (Make sure Env Var is updated!)
        const serviceAccount = getServiceAccount();
        const accessToken = await getGoogleAccessToken(serviceAccount);
        
        const chatId = await createFirestoreChat(serviceAccount.project_id, accessToken, userId, body.title || "New Chat");
        
        return new Response(JSON.stringify({ success: true, chatId: chatId }), { status: 200, headers });
      } catch (e: any) { 
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers }); 
      }
  }

  // === 🔥 ROUTE: REPORT VIOLATION (DUAL AUTH) ===
  if (url.pathname === "/report-violation" && req.method === "POST") {
    try {
      let userId = "";
      let chatId = "";
      
      const body = await req.json();
      chatId = body.chatId;

      // 🔐 CHECK 1: IS IT SERVER A? (SERVICE SECRET)
      const serviceKey = req.headers.get("X-Service-Key");
      
      if (serviceKey === SERVICE_SECRET) {
          console.log("✅ Authenticated via Service Secret (Server A)");
          userId = body.userId; // Trust the request body because it comes from our server
      } 
      // 🔐 CHECK 2: IS IT THE USER? (FIREBASE TOKEN - Fallback)
      else {
          console.log("⚠️ Authenticated via User Token");
          const authHeader = req.headers.get("Authorization");
          if (!authHeader?.startsWith("Bearer ")) throw new Error("Unauthorized");
          const token = authHeader.split("Bearer ")[1];
          const userData = await verifyUserToken(token);
          userId = userData.localId;
      }

      if (!userId || !chatId) throw new Error("Missing ID");

      // --- LOGIC STARTS ---
      const serviceAccount = getServiceAccount();
      const accessToken = await getGoogleAccessToken(serviceAccount);
      const projectId = serviceAccount.project_id;

      // Read Chat
      const chatData = await getFirestoreChat(projectId, accessToken, userId, chatId);
      
      let currentCount = parseInt(chatData.fields?.violationCount?.integerValue || "0");
      let isBanned = chatData.fields?.isBanned?.booleanValue || false;

      currentCount++;
      const MAX_VIOLATIONS = 3; 
      if (currentCount >= MAX_VIOLATIONS) isBanned = true;

      await updateFirestoreBanStatus(projectId, accessToken, userId, chatId, currentCount, isBanned);

      console.log(`[Security] Violation logged via Server-Link. User: ${userId}, Banned: ${isBanned}`);

      return new Response(JSON.stringify({ success: true, isBanned, violationCount: currentCount }), { status: 200, headers });

    } catch (error: any) {
      console.error("Violation Report Error:", error.message);
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
    }
  }

  return new Response("Nexari AI Backend Running", { status: 200 });
});

// --- HELPER FUNCTIONS ---

function getServiceAccount() { 
    // ⚠️ IMPORTANT: Update 'FIREBASE_SERVICE_ACCOUNT' Env Var in Deno Deploy with NEW Project JSON
    const json = Deno.env.get("FIREBASE_SERVICE_ACCOUNT"); 
    if (!json) throw new Error("Missing Env: FIREBASE_SERVICE_ACCOUNT"); 
    return JSON.parse(json); 
}

async function verifyUserToken(token: string) { 
    // Verifies against the new NEXARI-AI project
    const res = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`, { 
        method: "POST", 
        headers: { "Content-Type": "application/json" }, 
        body: JSON.stringify({ idToken: token }) 
    }); 
    const data = await res.json(); 
    if (data.error) throw new Error("Invalid Token: " + data.error.message); 
    return data.users[0]; 
}

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
  const data = await res.json(); 
  if (data.error) throw new Error("Firestore Error: " + data.error.message);
  const parts = data.name.split("/"); 
  return parts[parts.length - 1];
}

async function getFirestoreChat(projectId: string, accessToken: string, userId: string, chatId: string) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${userId}/chats/${chatId}`;
  const res = await fetch(url, { headers: { "Authorization": `Bearer ${accessToken}` } });
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
  await fetch(url, { 
      method: "PATCH", 
      headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" }, 
      body: JSON.stringify(docData) 
  });
}

async function getGoogleAccessToken(serviceAccount: any) {
  const pem = serviceAccount.private_key; 
  const clientEmail = serviceAccount.client_email;
  
  // Format Private Key
  const pemContents = pem.substring(27, pem.length - 25).replace(/\s/g, "");
  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", binaryDer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  
  const now = Math.floor(Date.now() / 1000);
  const payload = { 
      iss: clientEmail, 
      scope: "https://www.googleapis.com/auth/datastore", 
      aud: "https://oauth2.googleapis.com/token", 
      exp: now + 3600, 
      iat: now 
  };
  
  const sHead = btoa(JSON.stringify({ alg: "RS256", typ: "JWT" })); 
  const sPay = btoa(JSON.stringify(payload));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${sHead}.${sPay}`));
  const sSig = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", { 
      method: "POST", 
      headers: { "Content-Type": "application/x-www-form-urlencoded" }, 
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${sHead}.${sPay}.${sSig}` 
  });
  
  return (await tokenRes.json()).access_token;
}
