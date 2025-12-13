/* main.ts - Lazy Entry Point */
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { initializeApp, cert, getApps } from "npm:firebase-admin/app";
import { handleCreateChat } from "./New_chat.js";

// Global status check
let isFirebaseInitialized = false;

// 🔥 Helper Function: Initialize only when needed
function ensureFirebaseInitialized() {
    // Agar pehle se initialized hai, toh wapas mat karo (Crash bachega)
    if (isFirebaseInitialized || getApps().length > 0) {
        isFirebaseInitialized = true;
        return;
    }

    console.log("Starting Firebase Initialization...");
    
    const serviceAccountJson = Deno.env.get("FIREBASE_SERVICE_ACCOUNT");
    if (!serviceAccountJson) {
        throw new Error("Missing FIREBASE_SERVICE_ACCOUNT environment variable");
    }

    try {
        // Parse JSON safely
        const serviceAccount = JSON.parse(serviceAccountJson);
        
        initializeApp({
            credential: cert(serviceAccount)
        });
        
        isFirebaseInitialized = true;
        console.log("Firebase Initialized Successfully!");
    } catch (error) {
        console.error("Firebase Init Failed:", error);
        throw error; // Request fail hoga, par pura server crash nahi hoga
    }
}

// Start Server
serve(async (req) => {
    const url = new URL(req.url);

    // 1. Initialize Firebase on first request (Lazy Load)
    try {
        ensureFirebaseInitialized();
    } catch (e) {
        return new Response(JSON.stringify({ error: "Server Initialization Failed", details: e.message }), { 
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }

    // 2. Routing
    if (url.pathname === "/create-chat" && req.method === "POST") {
        return await handleCreateChat(req);
    }

    // Default Route
    return new Response("Nexari AI Server is Running (Lazy Mode)", { status: 200 });
});
