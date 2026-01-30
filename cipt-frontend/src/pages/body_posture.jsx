import React, { useEffect, useRef } from "react";

export default function BodyPosture() {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const statusRef = useRef(null);

  useEffect(() => {
    // Load Mediapipe scripts dynamically
    const poseScript = document.createElement("script");
    poseScript.src = "https://cdn.jsdelivr.net/npm/@mediapipe/pose";
    document.body.appendChild(poseScript);

    const cameraScript = document.createElement("script");
    cameraScript.src = "https://cdn.jsdelivr.net/npm/@mediapipe/camera_utils";
    document.body.appendChild(cameraScript);

    const drawingsScript = document.createElement("script");
    drawingsScript.src = "https://cdn.jsdelivr.net/npm/@mediapipe/drawing_utils";
    document.body.appendChild(drawingsScript);

    poseScript.onload = cameraScript.onload = drawingsScript.onload = () => {
      if (!window.Pose || !window.Camera) return;

      const videoElement = videoRef.current;
      const canvasElement = canvasRef.current;
      const canvasCtx = canvasElement.getContext("2d");

      function onResults(results) {
        canvasCtx.clearRect(0, 0, canvasElement.width, canvasElement.height);
        canvasCtx.drawImage(
          results.image,
          0,
          0,
          canvasElement.width,
          canvasElement.height
        );

        if (results.poseLandmarks) {
          window.drawConnectors(
            canvasCtx,
            results.poseLandmarks,
            window.POSE_CONNECTIONS,
            { color: "#6A0572", lineWidth: 3 }
          );

          window.drawLandmarks(canvasCtx, results.poseLandmarks, {
            color: "#FF0000",
            lineWidth: 1,
          });

          // Posture check
          const leftShoulder = results.poseLandmarks[11];
          const rightShoulder = results.poseLandmarks[12];

          if (Math.abs(leftShoulder.y - rightShoulder.y) > 0.05) {
            statusRef.current.innerText = "⚠️ Bad posture detected!";
          } else {
            statusRef.current.innerText = "✅ Good posture";
          }
        }
      }

      const pose = new window.Pose.Pose({
        locateFile: (file) =>
          `https://cdn.jsdelivr.net/npm/@mediapipe/pose/${file}`,
      });

      pose.setOptions({
        modelComplexity: 1,
        smoothLandmarks: true,
        enableSegmentation: false,
        minDetectionConfidence: 0.5,
        minTrackingConfidence: 0.5,
      });

      pose.onResults(onResults);

      const camera = new window.Camera(videoElement, {
        onFrame: async () => {
          await pose.send({ image: videoElement });
        },
        width: 640,
        height: 480,
      });

      camera.start();
    };
  }, []);

  return (
    <div style={{ textAlign: "center", fontFamily: "Arial", background: "#f9f9f9", minHeight: "100vh" }}>
      <h2>🧍 Body Posture Detection</h2>

      <video
        ref={videoRef}
        id="webcam"
        autoPlay
        playsInline
        style={{
          width: "640px",
          height: "480px",
          border: "2px solid #6A0572",
          borderRadius: "8px",
        }}
      ></video>

      <canvas
        ref={canvasRef}
        id="output"
        width="640"
        height="480"
        style={{
          width: "640px",
          height: "480px",
          border: "2px solid #6A0572",
          borderRadius: "8px",
          marginTop: "10px",
        }}
      ></canvas>

      <div
        id="status"
        ref={statusRef}
        style={{
          marginTop: "15px",
          fontSize: "20px",
          fontWeight: "bold",
          color: "#6A0572",
        }}
      >
        Analyzing posture...
      </div>
    </div>
  );
}
