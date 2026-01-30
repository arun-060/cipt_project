import React, { useEffect } from "react";

export default function EmotionDetection() {
  useEffect(() => {
    const video = document.getElementById("webcam");
    const canvas = document.getElementById("output");
    const ctx = canvas.getContext("2d");
    const emotionDiv = document.getElementById("emotion");

    let model;
    const emotions = [
      "Happy 😀",
      "Sad 😔",
      "Angry 😡",
      "Surprised 😲",
      "Neutral 😐",
    ];

    async function setupCamera() {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true });
      video.srcObject = stream;
      return new Promise((resolve) => {
        video.onloadedmetadata = () => resolve(video);
      });
    }

    async function run() {
      model = await window.blazeface.load();
      const webcam = await setupCamera();
      webcam.play();
      detect();
    }

    async function detect() {
      if (!model) return;

      const predictions = await model.estimateFaces(video, false);
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

      if (predictions.length > 0) {
        predictions.forEach((pred) => {
          ctx.beginPath();
          ctx.rect(
            pred.topLeft[0],
            pred.topLeft[1],
            pred.bottomRight[0] - pred.topLeft[0],
            pred.bottomRight[1] - pred.topLeft[1]
          );
          ctx.strokeStyle = "#6A0572";
          ctx.lineWidth = 2;
          ctx.stroke();
        });

        // random emotion (same as your demo)
        const detected =
          emotions[Math.floor(Math.random() * emotions.length)];
        emotionDiv.innerText = "Emotion: " + detected;
      } else {
        emotionDiv.innerText = "No face detected";
      }

      requestAnimationFrame(detect);
    }

    run();
  }, []);

  return (
    <div style={{ textAlign: "center", background: "#f9f9f9", fontFamily: "Arial" }}>
      {/* Load TF.js and BlazeFace */}
      <script src="https://cdn.jsdelivr.net/npm/@tensorflow/tfjs"></script>
      <script src="https://cdn.jsdelivr.net/npm/@tensorflow-models/blazeface"></script>

      <style>{`
        video, canvas {
          width: 640px;
          height: 480px;
          border: 2px solid #6A0572;
          border-radius: 8px;
        }
        #emotion {
          margin-top: 15px;
          font-size: 20px;
          font-weight: bold;
          color: #6A0572;
        }
      `}</style>

      <h2>😊 Emotion Detection</h2>

      <video id="webcam" autoPlay playsInline></video>
      <canvas id="output"></canvas>

      <div id="emotion">Detecting...</div>
    </div>
  );
}
