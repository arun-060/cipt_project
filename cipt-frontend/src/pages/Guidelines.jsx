import React from "react";
import { useNavigate } from "react-router-dom";
import "../styles/style.css";

export default function Guidelines() {
  const navigate = useNavigate();

  const startAssessment = () => {
    navigate("/timeslot");
  };

  const guidelines = [
    "Maintain a stable internet connection throughout the assessment.",
    "Use a laptop or desktop with a functioning camera and microphone.",
    "Work in a quiet, well-lit environment for better video analysis.",
    "Each question will be presented as a video — record your answers clearly.",
    "Questions can be skipped, and you may end the assessment early.",
    "A performance report will be generated automatically after submission.",
  ];

  return (
    <div className="guidelines-page">
      <div className="guidelines-container">
        <div className="guidelines-content compact">
          <div className="guidelines-header">
            <div className="guidelines-icon compact">
              <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" viewBox="0 0 16 16">
                <path d="M14.5 3a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-9a.5.5 0 0 1 .5-.5h13zm-13-1A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2h-13z"/>
                <path d="M7 5.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zm-1.496-.854a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0l-.5-.5a.5.5 0 1 1 .708-.708l.146.147 1.146-1.147a.5.5 0 0 1 .708 0zM7 9.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zm-1.496-.854a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0l-.5-.5a.5.5 0 0 1 .708-.708l.146.147 1.146-1.147a.5.5 0 0 1 .708 0z"/>
              </svg>
            </div>
            <h2 className="guidelines-title compact">Assessment Guidelines</h2>
            <p className="guidelines-subtitle compact">
              Please read these guidelines carefully before starting your assessment
            </p>
          </div>

          <div className="guidelines-list-container compact">
            <ul className="guidelines-list compact">
              {guidelines.map((item, index) => (
                <li key={index} className="guidelines-list-item compact">
                  <div className="guidelines-checkmark compact">
                    <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16">
                      <path d="M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z"/>
                    </svg>
                  </div>
                  <span className="guidelines-item-text compact">{item}</span>
                </li>
              ))}
            </ul>
          </div>
          
          {/* Buttons only - no checkbox */}
          <div className="guidelines-buttons-container">
            <div className="guidelines-buttons compact">
              <button className="btn-tertiary guidelines-back-btn compact" onClick={() => navigate(-1)}>
                ← Back
              </button>
              <button className="btn-primary guidelines-start-btn compact" onClick={startAssessment}>
                Start Assessment →
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}