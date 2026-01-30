import React, { useEffect, useRef } from "react";

export default function CameraTest() {
  const videoRef = useRef(null);

  useEffect(() => {
    navigator.mediaDevices
      .getUserMedia({ video: true })
      .then((stream) => {
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
        }
      })
      .catch((err) => {
        alert("Camera error: " + err.message);
        console.error(err);
      });
  }, []);

  return (
    <div>
      <h2>Camera Test</h2>
      <video ref={videoRef} autoPlay muted width="640" height="480"></video>
    </div>
  );
}
