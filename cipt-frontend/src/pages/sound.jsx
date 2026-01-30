import React, { useState } from "react";

export default function SoundAnalyzer() {
  const [output, setOutput] = useState("");

  const startAnalysis = async () => {
    setOutput("Recording for 3 seconds...");

    try {
      const response = await fetch("/analyze/sound");
      const { success, data, rawOutput } = await response.json();

      if (success && data) {
        setOutput(`
          🗣️ You said: ${data.text}
          ${data.pitch_volume_feedback}
          ${data.speech_rate_feedback}
        `);
      } else {
        setOutput("⚠️ Analysis failed.");
        console.log(rawOutput);
      }
    } catch (err) {
      setOutput("⚠️ Error connecting to server.");
    }
  };

  return (
    <div
      style={{
        background: "#111",
        color: "white",
        fontFamily: "Arial",
        textAlign: "center",
        paddingTop: "60px",
        height: "100vh"
      }}
    >
      <h1>🎧 Real-Time Sound Analyzer</h1>

      <button
        onClick={startAnalysis}
        style={{
          padding: "10px 20px",
          background: "#00eaff",
          color: "#111",
          fontSize: "18px",
          border: "none",
          borderRadius: "10px",
          cursor: "pointer"
        }}
        onMouseOver={(e) => (e.target.style.background = "#00bcd4")}
        onMouseOut={(e) => (e.target.style.background = "#00eaff")}
      >
        🎙️ Analyze Sound
      </button>

      <div
        className="result"
        style={{ marginTop: "40px", fontSize: "18px", whiteSpace: "pre-line" }}
      >
        {output}
      </div>
    </div>
  );
}
