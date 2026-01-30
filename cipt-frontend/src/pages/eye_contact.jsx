import React, { useEffect } from "react";

export default function EyeContact() {
  useEffect(() => {
    const videoElement = document.getElementById("webcam");
    const canvasElement = document.getElementById("output");
    const canvasCtx = canvasElement.getContext("2d");
    const eyeStatus = document.getElementById("eyeStatus");

    function onResults(results) {
      canvasCtx.clearRect(0, 0, canvasElement.width, canvasElement.height);
      canvasCtx.drawImage(
        results.image,
        0,
        0,
        canvasElement.width,
        canvasElement.height
      );

      if (
        results.multiFaceLandmarks &&
        results.multiFaceLandmarks.length > 0
      ) {
        for (const landmarks of results.multiFaceLandmarks) {
          window.drawConnectors(
            canvasCtx,
            landmarks,
            window.FACEMESH_TESSELATION,
            { color: "#6A0572", lineWidth: 1 }
          );

          // Eye open-close logic
          const leftEyeTop = landmarks[159];
          const leftEyeBottom = landmarks[145];
          const eyeOpen = Math.abs(leftEyeTop.y - leftEyeBottom.y);

          if (eyeOpen < 0.01) {
            eyeStatus.innerText = "😴 Eyes closed (blinking)";
          } else {
            eyeStatus.innerText = "👀 Eyes open - good contact";
          }
        }
      }
    }

    // Initialize FaceMesh
    const faceMesh = new window.FaceMesh.FaceMesh({
      locateFile: (file) =>
        `https://cdn.jsdelivr.net/npm/@mediapipe/face_mesh/${file}`,
    });

    faceMesh.setOptions({
      maxNumFaces: 1,
      refineLandmarks: true,
      minDetectionConfidence: 0.5,
      minTrackingConfidence: 0.5,
    });

    faceMesh.onResults(onResults);

    // Camera feed
    const camera = new window.Camera(videoElement, {
      onFrame: async () => {
        await faceMesh.send({ image: videoElement });
      },
      width: 640,
      height: 480,
    });

    camera.start();
  }, []);

  return (
    <div
      style={{
        textAlign: "center",
        background: "#f9f9f9",
        fontFamily: "Arial",
      }}
    >
      {/* Mediapipe scripts */}
      <script src="https://cdn.jsdelivr.net/npm/@mediapipe/face_mesh"></script>
      <script src="https://cdn.jsdelivr.net/npm/@mediapipe/camera_utils"></script>
      <script src="https://cdn.jsdelivr.net/npm/@mediapipe/drawing_utils"></script>

      <style>{`
        video, canvas {
          width: 640px;
          height: 480px;
          border: 2px solid #6A0572;
          border-radius: 8px;
        }
        #eyeStatus {
          margin-top: 15px;
          font-size: 20px;
          font-weight: bold;
          color: #6A0572;
        }
      `}</style>

      <h2>👀 Eye Contact Analysis</h2>

      <video id="webcam" autoPlay playsInline></video>
      <canvas id="output"></canvas>

      <div id="eyeStatus">Analyzing eye contact...</div>
    </div>
  );
}
