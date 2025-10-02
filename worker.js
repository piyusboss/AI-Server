// Step 1: Updated Imports
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { initializeApp, cert } from "https://esm.sh/firebase-admin@11.10.1/app";
import { getAuth } from "https://esm.sh/firebase-admin@11.10.1/auth";
import { getFirestore, FieldValue } from "https://esm.sh/firebase-admin@11.10.1/firestore";
import { getStorage } from "https://esm.sh/firebase-admin@11.10.1/storage";

// Step 2: Read Service Account from Environment Variable
const serviceAccountJson = Deno.env.get("FIREBASE_SERVICE_ACCOUNT");
if (!serviceAccountJson) {
  throw new Error("FIREBASE_SERVICE_ACCOUNT environment variable not set!");
}
const serviceAccount = JSON.parse(serviceAccountJson);

// Initialize Firebase App
initializeApp({
  credential: cert(serviceAccount),
  storageBucket: "ai-model-9a473.appspot.com" // Replace with your storage bucket URL
});

const auth = getAuth();
const db = getFirestore();
const storage = getStorage();

console.log("Deno server running!");

// Main request handler
async function handler(req) {
    // Handle CORS preflight requests
    if (req.method === "OPTIONS") {
        return new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*", // Be more specific in production
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
        });
    }
    
    // Standard headers for all responses
    const headers = { 
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*" // Be more specific in production
    };

    try {
        const { action, payload, idToken } = await req.json();
        let user = null;

        // Verify ID token for protected actions
        if (idToken) {
            try {
                user = await auth.verifyIdToken(idToken);
            } catch (error) {
                return new Response(JSON.stringify({ error: "Invalid authentication token." }), { status: 401, headers });
            }
        }
        
        // --- ACTION ROUTER (The switch case logic remains the same) ---
        switch (action) {
            // ... Aapka poora switch case yahan aayega ...
            // (Maine ise yahan se hata diya hai taaki response lamba na ho,
            // lekin aapka pichla switch-case code bilkul sahi hai aur yahan paste hoga)
            
            case 'getUserLastChatId':
                if (!user) throw new Error("Authentication required.");
                const userDoc = await db.collection('users').doc(user.uid).get();
                const lastId = userDoc.exists ? userDoc.data().lastActiveChatId : null;
                return new Response(JSON.stringify({ lastActiveChatId: lastId }), { status: 200, headers });

            // ... Baaki saare cases bhi yahin rahenge ...

            default:
                return new Response(JSON.stringify({ error: "Unknown action" }), { status: 400, headers });
        }
    } catch (error) {
        console.error("Server Error:", error);
        return new Response(JSON.stringify({ error: error.message || "An internal server error occurred." }), { status: 500, headers });
    }
}

serve(handler);
