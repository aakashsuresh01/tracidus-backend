document.getElementById("predictionForm").addEventListener("submit", async function (e) {
    e.preventDefault();

    let inputText = document.getElementById("inputText").value.trim();

    if (!inputText) {
        document.getElementById("result").innerText = "⚠️ Please enter some text.";
        return;
    }

    try {
        // ✅ Match backend route (your server.js uses /api/analyze)
        let response = await fetch("/api/analyze", {  
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text: inputText })
        });

        if (!response.ok) {
            throw new Error("Server error: " + response.status);
        }

        let result = await response.json();

        // ✅ Check if backend actually sent "prediction"
        if (result.prediction) {
            document.getElementById("result").innerText = "Prediction: " + result.prediction;
        } else {
            document.getElementById("result").innerText = "⚠️ No prediction received.";
        }
    } catch (error) {
        console.error("Error:", error);
        document.getElementById("result").innerText = "❌ Failed to get prediction. Check server logs.";
    }
});
