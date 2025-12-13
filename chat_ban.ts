/* chat_ban.ts - Secure Ban Logic */

export async function handleReportViolation(req: Request, accessToken: string, projectId: string, userId: string) {
    try {
        const body = await req.json();
        const chatId = body.chatId;

        if (!chatId) {
            return new Response(JSON.stringify({ error: "Missing chatId" }), { status: 400 });
        }

        // 1. Current Chat Data Fetch karo (REST API)
        const firestoreUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${userId}/chats/${chatId}`;
        
        const getRes = await fetch(firestoreUrl, {
            method: "GET",
            headers: { "Authorization": `Bearer ${accessToken}` }
        });

        if (!getRes.ok) {
            return new Response(JSON.stringify({ error: "Chat not found" }), { status: 404 });
        }

        const chatDoc = await getRes.json();
        
        // 2. Violation Count Calculate karo
        // Firestore integers strings ke roop mein aate hain inside specific structure
        const currentCount = parseInt(chatDoc.fields?.violationCount?.integerValue || "0");
        const newCount = currentCount + 1;
        
        // 3. Check Threshold (e.g., 3 strikes = BAN)
        const BAN_THRESHOLD = 3;
        const shouldBan = newCount >= BAN_THRESHOLD;

        // 4. Update Data Prepare karo
        const updateData = {
            fields: {
                violationCount: { integerValue: newCount.toString() },
                // Agar ban ho raha hai toh true set karo, warna purana status rakho (ya false)
                isBanned: { booleanValue: shouldBan } 
            }
        };
        
        // Agar ban hua hai toh timestamp bhi add kar sakte hain
        if (shouldBan) {
            // @ts-ignore
            updateData.fields.bannedAt = { timestampValue: new Date().toISOString() };
        }

        // 5. Patch (Update) Request bhejo
        // updateMask zaroori hai taaki baaki fields (title, createdAt) delete na ho jayein
        const patchUrl = `${firestoreUrl}?updateMask.fieldPaths=violationCount&updateMask.fieldPaths=isBanned${shouldBan ? '&updateMask.fieldPaths=bannedAt' : ''}`;

        const patchRes = await fetch(patchUrl, {
            method: "PATCH",
            headers: { 
                "Authorization": `Bearer ${accessToken}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify(updateData)
        });

        if (!patchRes.ok) {
            const errText = await patchRes.text();
            throw new Error("Failed to update ban status: " + errText);
        }

        console.log(`[Security] Violation reported for chat ${chatId}. New Count: ${newCount}. Banned: ${shouldBan}`);

        return new Response(JSON.stringify({ 
            success: true, 
            violationCount: newCount,
            isBanned: shouldBan
        }), { status: 200, headers: { "Content-Type": "application/json" } });

    } catch (error) {
        console.error("Ban Logic Error:", error);
        return new Response(JSON.stringify({ error: error.message }), { status: 500 });
    }
}
