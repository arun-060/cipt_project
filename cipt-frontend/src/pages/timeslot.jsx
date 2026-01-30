import React from "react";
import { useNavigate } from "react-router-dom";
import "../styles/style.css";

export default function TimeSlot() {
  const navigate = useNavigate();

  const selectSlot = (duration) => {
    navigate(`/select-domain?duration=${duration}`);
  };

  const durations = [
    { label: "10 Minutes", value: 10 },
    { label: "15 Minutes", value: 15 },
    { label: "20 Minutes", value: 20 },
  ];

  return (
    <div className="timeslot-page">
      <div className="timeslot-container">
        <div className="timeslot-content compact small">
          <div className="timeslot-header small">
            <div className="timeslot-icon small">
              <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" viewBox="0 0 16 16">
                <path d="M8 3.5a.5.5 0 0 0-1 0V9a.5.5 0 0 0 .252.434l3.5 2a.5.5 0 0 0 .496-.868L8 8.71V3.5z"/>
                <path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm7-8A7 7 0 1 1 1 8a7 7 0 0 1 14 0z"/>
              </svg>
            </div>
            <h2 className="timeslot-title small">Select Time Slot</h2>
            <p className="timeslot-subtitle small">
              Choose how long you want for the assessment
            </p>
          </div>

          <div className="timeslot-options small">
            {durations.map((slot) => (
              <button
                key={slot.value}
                className="timeslot-card small"
                onClick={() => selectSlot(slot.value)}
              >
                <div className="timeslot-card-icon small">
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 16 16">
                    <path d="M8 3.5a.5.5 0 0 0-1 0V9a.5.5 0 0 0 .252.434l3.5 2a.5.5 0 0 0 .496-.868L8 8.71V3.5z"/>
                  </svg>
                </div>
                <div className="timeslot-card-content small">
                  <h3 className="timeslot-card-title small">{slot.label}</h3>
                  <p className="timeslot-card-desc small">Quick assessment</p>
                </div>
              </button>
            ))}
          </div>

          {/* Back button inside box */}
          <div className="timeslot-buttons-container">
            <button className="btn-tertiary timeslot-back-btn small" onClick={() => navigate(-1)}>
              ← Back
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}