/* main.ts - Entry Point */
import { serve } from "https://deno.land/std@0.177.0/http/server.ts"; // Or standard Deno.serve
import { initializeApp, cert } from "npm:firebase-admin/app";
import { handleCreateChat } from "./New_chat.js";

// 1. Initialize Firebase (Sabse pehle ye chalna chahiye)
try {
    const serviceAccountJson = Deno.env.get("FIREBASE_SERVICE_ACCOUNT");
    
    if (!serviceAccountJson) {
        throw new Error("Missing FIREBASE_SERVICE_ACCOUNT environment variable");
    }

    const serviceAccount = JSON.parse(serviceAccountJson);

    initializeApp({
        credential: cert(serviceAccount)
    });
    
    console.log("Firebase Admin Initialized successfully!");
} catch (error) {
    console.error("Firebase Initialization Failed:", error);
}

// 2. Start the Server
Deno.serve(async (req) => {
    const url = new URL(req.url);

    // Route for Creating Chat
    if (url.pathname === "/create-chat" && req.method === "POST") {
        return await handleCreateChat(req);
    }

    // Default Route
    return new Response("Nexari AI Server is Running", { status: 200 });
});
