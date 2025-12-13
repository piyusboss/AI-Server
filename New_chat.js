/* New_chat.js (Server-Side Logic for Deno) */

// Import Firebase Admin SDK (Ensure you have this configured in your Deno imports map or deps.ts)
// Example imports assumes you are using a CDM or local mapping
import { getAuth } from "npm:firebase-admin/auth";
import { getFirestore, FieldValue } from "npm:firebase-admin/firestore";

// Initialize Firestore (Assumes App is already initialized in your main server.ts)
const db = getFirestore();
const auth = getAuth();

/**
 * Handles the creation of a new chat document securely.
 * @param {Request} req - The incoming HTTP request
 * @returns {Response} - JSON response with chatId
 */
export async function handleCreateChat(req) {
    // 1. CORS Headers setup
    const headers = new Headers({
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*", // Production mein isko apne domain se replace karein
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    });

    // Handle Preflight (OPTIONS) request
    if (req.method === "OPTIONS") {
        return new Response(null, { status: 204, headers });
    }

    if (req.method !== "POST") {
        return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers });
    }

    try {
        // 2. Extract Authorization Token
        const authHeader = req.headers.get("Authorization");
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return new Response(JSON.stringify({ error: "Unauthorized: No token provided" }), { status: 401, headers });
        }

        const idToken = authHeader.split("Bearer ")[1];

        // 3. Verify Token using Firebase Admin (Server Side Verification)
        const decodedToken = await auth.verifyIdToken(idToken);
        const userId = decodedToken.uid;

        // 4. Parse Body (Get Title)
        const body = await req.json();
        // Title validation: Agar title nahi hai ya empty hai, toh default set karo
        let title = body.title ? body.title.trim() : "New Chat";
        if (title.length > 50) title = title.substring(0, 50); // Server-side truncation rule

        // 5. Create Chat Document in Firestore
        // Path: users/{userId}/chats/{chatId}
        const newChatRef = await db.collection("users").doc(userId).collection("chats").add({
            title: title,
            createdAt: FieldValue.serverTimestamp(),
            
            // --- SERVER SIDE RULES ---
            violationCount: 0, // Security rule: Server sets this to 0
            isBanned: false,   // Security rule: Server sets this to false
            
            // Optional: Add metadata like IP or User Agent if needed for security
            // createdByIp: req.headers.get("x-forwarded-for") || ...
        });

        console.log(`[NewChat] Created chat ${newChatRef.id} for user ${userId}`);

        // 6. Return the new Chat ID to the client
        return new Response(JSON.stringify({ 
            success: true, 
            chatId: newChatRef.id,
            title: title 
        }), { status: 200, headers });

    } catch (error) {
        console.error("Error creating chat:", error);
        
        // Specific handling for Token errors
        if (error.code === 'auth/id-token-expired' || error.code === 'auth/argument-error') {
            return new Response(JSON.stringify({ error: "Unauthorized: Invalid or expired token" }), { status: 401, headers });
        }

        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers });
    }
}
