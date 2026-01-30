import React from "react";
import { useNavigate, useLocation } from "react-router-dom";
import "../styles/style.css";

export default function Domains() {
  const navigate = useNavigate();
  const location = useLocation();

  // Get duration from query params
  const params = new URLSearchParams(location.search);
  const duration = params.get("duration");

  // Navigate directly without backend API call
  const chooseDomain = (domain) => {
    navigate(`/video?domain=${domain}&duration=${duration}`);
  };

  const domains = [
    { id: "1_Python", label: "Python" },
    { id: "2_Data Structures", label: "Data Structures" },
    { id: "3_DBMS", label: "DBMS" },
    { id: "4_OS", label: "Operating System" },
    { id: "5_CN", label: "Computer Networks" },
  ];

  return (
    <div className="domains-page">
      <div className="domains-container">
        <div className="domains-content compact small">
          <div className="domains-header small">
            <div className="domains-icon small">
              <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" viewBox="0 0 16 16">
                <path d="M8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 1.5 7.5v7a.5.5 0 0 0 .5.5h4.5a.5.5 0 0 0 .5-.5v-4h2v4a.5.5 0 0 0 .5.5H14a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.146-.354L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.354 1.146zM2.5 14V7.707l5.5-5.5 5.5 5.5V14H10v-4a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5v4H2.5z"/>
              </svg>
            </div>
            <h2 className="domains-title small">Select Your Domain</h2>
            {duration && (
              <p className="domains-duration small">
                ⏰ Assessment Duration: <strong>{duration} minutes</strong>
              </p>
            )}
            <p className="domains-subtitle small">
              Choose your technical domain for the assessment
            </p>
          </div>

          <div className="domains-grid small">
            {domains.map((domain) => (
              <button
                key={domain.id}
                onClick={() => chooseDomain(domain.id)}
                className="domain-card small"
              >
                <div className="domain-icon small">
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 16 16">
                    <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>
                    <path d="M8 13A5 5 0 1 1 8 3a5 5 0 0 1 0 10zm0-1A4 4 0 1 0 8 4a4 4 0 0 0 0 8z"/>
                  </svg>
                </div>
                <span className="domain-label small">{domain.label}</span>
              </button>
            ))}
          </div>

          {/* Back button inside box */}
          <div className="domains-buttons-container">
            <button className="btn-tertiary domains-back-btn small" onClick={() => navigate(-1)}>
              ← Back
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}