// Imports ab chote aur clean ho gaye hain
import { serve } from "std/http/server";
import { initializeApp, cert } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
import { getStorage } from "firebase-admin/storage";

// Environment Variable se key read karna (yeh aaisa hi rahega)
const serviceAccountJson = Deno.env.get("FIREBASE_SERVICE_ACCOUNT");
if (!serviceAccountJson) {
  throw new Error("FIREBASE_SERVICE_ACCOUNT environment variable not set!");
}
const serviceAccount = JSON.parse(serviceAccountJson);

// Firebase App Initialize karna (yeh aaisa hi rahega)
initializeApp({
  credential: cert(serviceAccount),
  storageBucket: "ai-model-9a473.appspot.com" // Apne storage bucket ka naam daalein
});

const auth = getAuth();
const db = getFirestore();
const storage = getStorage();

console.log("Deno server running!");

// Main request handler (yeh poora logic aaisa hi rahega)
async function handler(req) {
    // CORS preflight requests
    if (req.method === "OPTIONS") {
        return new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
        });
    }
    
    const headers = { 
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    };

    try {
        const { action, payload, idToken } = await req.json();
        let user = null;

        if (idToken) {
            try {
                user = await auth.verifyIdToken(idToken);
            } catch (error) {
                return new Response(JSON.stringify({ error: "Invalid authentication token." }), { status: 401, headers });
            }
        }
        
        // --- ACTION ROUTER ---
        switch (action) {
            // ...Aapke saare switch cases yahan aayenge...
            // (Pichle code se copy kar lein)
            
            case 'getUserLastChatId':
                if (!user) throw new Error("Authentication required.");
                const userDoc = await db.collection('users').doc(user.uid).get();
                const lastId = userDoc.exists ? userDoc.data().lastActiveChatId : null;
                return new Response(JSON.stringify({ lastActiveChatId: lastId }), { status: 200, headers });

            // ... Baaki saare cases ...

            default:
                return new Response(JSON.stringify({ error: `Action '${action}' not found.` }), { status: 400, headers });
        }
    } catch (error) {
        console.error("Server Error:", error);
        return new Response(JSON.stringify({ error: error.message || "An internal server error occurred." }), { status: 500, headers });
    }
}

serve(handler);
