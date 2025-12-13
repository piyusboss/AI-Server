/* New_chat.js (Lazy Compatible) */

import { getAuth } from "npm:firebase-admin/auth";
import { getFirestore, FieldValue } from "npm:firebase-admin/firestore";

export async function handleCreateChat(req) {
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

    try {
        // 🔥 CRITICAL: Get instances INSIDE the function
        // Kyunki main.ts ne abhi-abhi initialize kiya hai
        const db = getFirestore();
        const auth = getAuth();

        const authHeader = req.headers.get("Authorization");
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return new Response(JSON.stringify({ error: "Unauthorized: No token provided" }), { status: 401, headers });
        }

        const idToken = authHeader.split("Bearer ")[1];
        const decodedToken = await auth.verifyIdToken(idToken);
        const userId = decodedToken.uid;

        const body = await req.json();
        let title = body.title ? body.title.trim() : "New Chat";
        if (title.length > 50) title = title.substring(0, 50);

        const newChatRef = await db.collection("users").doc(userId).collection("chats").add({
            title: title,
            createdAt: FieldValue.serverTimestamp(),
            violationCount: 0,
            isBanned: false,
        });

        return new Response(JSON.stringify({ 
            success: true, 
            chatId: newChatRef.id,
            title: title 
        }), { status: 200, headers });

    } catch (error) {
        console.error("Error inside handleCreateChat:", error);
        return new Response(JSON.stringify({ error: error.message || "Internal Server Error" }), { status: 500, headers });
    }
}
