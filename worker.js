import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { initializeApp, cert } from "https://esm.sh/firebase-admin@11.10.1/app";
import { getAuth } from "https://esm.sh/firebase-admin@11.10.1/auth";
import { getFirestore, FieldValue } from "https://esm.sh/firebase-admin@11.10.1/firestore";
import { getStorage } from "https://esm.sh/firebase-admin@11.10.1/storage";

// IMPORTANT: Create a serviceAccountKey.json file from your Firebase project settings
// and place it in the same directory as this worker.js file.
const serviceAccount = JSON.parse(await Deno.readTextFile("./serviceAccountKey.json"));

initializeApp({
  credential: cert(serviceAccount),
  storageBucket: "ai-model-9a473.appspot.com" // Replace with your storage bucket URL
});

const auth = getAuth();
const db = getFirestore();
const storage = getStorage();

console.log("Deno server running on http://localhost:8000");

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
        
        // --- ACTION ROUTER ---
        switch (action) {
            // --- Unprotected actions (like login/signup) ---
            case 'createAnonymousUser': {
                 const anonUser = await auth.createUser({});
                 const customToken = await auth.createCustomToken(anonUser.uid);
                 return new Response(JSON.stringify({ token: customToken, uid: anonUser.uid }), { status: 200, headers });
            }
            
            // --- Protected actions (require valid idToken) ---
            case 'getUserLastChatId':
                if (!user) throw new Error("Authentication required.");
                const userDoc = await db.collection('users').doc(user.uid).get();
                const lastId = userDoc.exists ? userDoc.data().lastActiveChatId : null;
                return new Response(JSON.stringify({ lastActiveChatId: lastId }), { status: 200, headers });

            case 'updateUserLastChatId':
                if (!user) throw new Error("Authentication required.");
                await db.collection('users').doc(user.uid).set({ lastActiveChatId: payload.chatId }, { merge: true });
                return new Response(JSON.stringify({ success: true }), { status: 200, headers });

            case 'clearUserLastChatId':
                if (!user) throw new Error("Authentication required.");
                await db.collection('users').doc(user.uid).update({ lastActiveChatId: FieldValue.delete() });
                return new Response(JSON.stringify({ success: true }), { status: 200, headers });

            case 'loadMessagesForChat':
                if (!user) throw new Error("Authentication required.");
                const messagesSnapshot = await db.collection('users').doc(user.uid).collection('chats').doc(payload.chatId).collection('messages').orderBy('timestamp').get();
                const messages = messagesSnapshot.docs.map(doc => doc.data());
                return new Response(JSON.stringify(messages), { status: 200, headers });

            case 'createNewChatInDb':
                 if (!user) throw new Error("Authentication required.");
                 const newChatRef = await db.collection('users').doc(user.uid).collection('chats').add({
                    title: payload.title,
                    createdAt: FieldValue.serverTimestamp()
                 });
                 return new Response(JSON.stringify({ id: newChatRef.id }), { status: 200, headers });

            case 'saveMessageToDb':
                 if (!user) throw new Error("Authentication required.");
                 await db.collection('users').doc(user.uid).collection('chats').doc(payload.chatId).collection('messages').add({
                    ...payload.messageObject,
                    timestamp: FieldValue.serverTimestamp() // Ensure server timestamp
                 });
                 return new Response(JSON.stringify({ success: true }), { status: 200, headers });
            
            case 'loadChatHistory':
                if (!user) throw new Error("Authentication required.");
                const chatsRef = db.collection('users').doc(user.uid).collection('chats').orderBy('createdAt', 'desc');
                const chatsSnapshot = await chatsRef.get();
                const chats = chatsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
                return new Response(JSON.stringify(chats), { status: 200, headers });

            case 'deleteAllChatsFromDb':
                if (!user) throw new Error("Authentication required.");
                const allChatsSnapshot = await db.collection('users').doc(user.uid).collection('chats').get();
                if (allChatsSnapshot.empty) throw new Error("Chat history is already empty.");
                const batchDelete = db.batch();
                allChatsSnapshot.docs.forEach(doc => batchDelete.delete(doc.ref));
                await batchDelete.commit();
                await db.collection('users').doc(user.uid).update({ lastActiveChatId: FieldValue.delete() });
                return new Response(JSON.stringify({ success: true }), { status: 200, headers });
            
            case 'deleteSingleChatFromDb':
                if (!user) throw new Error("Authentication required.");
                const singleChatRef = db.collection('users').doc(user.uid).collection('chats').doc(payload.chatId);
                // Also delete subcollection messages
                const singleChatMessages = await singleChatRef.collection('messages').get();
                const batchSingle = db.batch();
                singleChatMessages.docs.forEach(doc => batchSingle.delete(doc.ref));
                await batchSingle.commit();
                // Delete the chat doc itself
                await singleChatRef.delete();
                return new Response(JSON.stringify({ success: true }), { status: 200, headers });

            case 'updateUserProfile':
                if (!user) throw new Error("Authentication required.");
                await auth.updateUser(user.uid, payload.updateData);
                return new Response(JSON.stringify({ success: true }), { status: 200, headers });

            // Note: File upload is more complex and would ideally be a direct upload to a signed URL.
            // This implementation is a simplified proxy and not recommended for large files.
            case 'uploadProfileImage':
                 if (!user) throw new Error("Authentication required.");
                 const { fileDataUrl, fileName } = payload;
                 const base64Data = fileDataUrl.split(',')[1];
                 const buffer = new Uint8Array(atob(base64Data).split('').map(char => char.charCodeAt(0)));
                 
                 const filePath = `profile_pictures/${user.uid}/${fileName}`;
                 const fileRef = storage.bucket().file(filePath);
                 
                 await fileRef.save(buffer, {
                    metadata: { contentType: 'image/jpeg' }, // Adjust content type as needed
                 });
                 const [downloadURL] = await fileRef.getSignedUrl({ action: 'read', expires: '03-09-2491' });
                 return new Response(JSON.stringify({ downloadURL }), { status: 200, headers });

            default:
                return new Response(JSON.stringify({ error: "Unknown action" }), { status: 400, headers });
        }
    } catch (error) {
        console.error("Server Error:", error);
        return new Response(JSON.stringify({ error: error.message || "An internal server error occurred." }), { status: 500, headers });
    }
}

serve(handler, { port: 8000 });
