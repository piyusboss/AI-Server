/* New_chat.js (Updated for Deno Deploy) */

import { getAuth } from "npm:firebase-admin/auth";
import { getFirestore, FieldValue } from "npm:firebase-admin/firestore";

// Note: initializeApp() ab main.ts mein ho raha hai.

export async function handleCreateChat(req) {
    // CORS Headers setup
    const headers = new Headers({
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    });

    if (req.method === "OPTIONS") {
        return new Response(null, { status: 204, headers });
    }

    // 🔥 Fix: Get Instances INSIDE the function 
    // This ensures initialization has finished in main.ts
    const db = getFirestore();
    const auth = getAuth();

    try {
        const authHeader = req.headers.get("Authorization");
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return new Response(JSON.stringify({ error: "Unauthorized: No token provided" }), { status: 401, headers });
        }

        const idToken = authHeader.split("Bearer ")[1];

        // Verify Token
        const decodedToken = await auth.verifyIdToken(idToken);
        const userId = decodedToken.uid;

        const body = await req.json();
        let title = body.title ? body.title.trim() : "New Chat";
        if (title.length > 50) title = title.substring(0, 50);

        // Create Chat
        const newChatRef = await db.collection("users").doc(userId).collection("chats").add({
            title: title,
            createdAt: FieldValue.serverTimestamp(),
            violationCount: 0,
            isBanned: false,
        });

        console.log(`[NewChat] Created chat ${newChatRef.id} for user ${userId}`);

        return new Response(JSON.stringify({ 
            success: true, 
            chatId: newChatRef.id,
            title: title 
        }), { status: 200, headers });

    } catch (error) {
        console.error("Error creating chat:", error);
        
        if (error.code === 'auth/id-token-expired' || error.code === 'auth/argument-error') {
            return new Response(JSON.stringify({ error: "Unauthorized: Invalid or expired token" }), { status: 401, headers });
        }

        return new Response(JSON.stringify({ error: error.message || "Internal Server Error" }), { status: 500, headers });
    }
}
