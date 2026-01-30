import React from "react";
import { useNavigate } from "react-router-dom";
import "../styles/style.css";

export default function SelectSkill() {
  const navigate = useNavigate();

  return (
    <div className="select-skill-page">
      {/* Navbar will be shown automatically (not hidden) */}
      
      <div className="select-skill-container">
        <div className="skill-content compact">
          <h2 className="skill-title">Choose Your Skill Track</h2>
          <p className="skill-subtitle">Select a category to begin your interview preparation</p>
          
          <div className="skill-cards compact">
            {/* Technical Skills Card */}
            <div className="skill-card compact">
              <div className="skill-icon compact">
                <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="currentColor" viewBox="0 0 16 16">
                  <path d="M0 4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V4zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1H2z"/>
                  <path d="M4.5 7a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h7a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 0-.5-.5h-7z"/>
                </svg>
              </div>
              <h3 className="skill-card-title compact">Technical Skills</h3>
              <p className="skill-card-desc compact">
                Practice coding interviews, system design, and technical questions
              </p>
              <button
                className="btn-primary skill-btn compact"
                onClick={() => navigate("/guidelines")}
              >
                Start Technical Interview
              </button>
            </div>

            {/* Soft Skills Card */}
            <div className="skill-card compact">
              <div className="skill-icon compact">
                <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="currentColor" viewBox="0 0 16 16">
                  <path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zM7 6.5C7 7.328 6.552 8 6 8s-1-.672-1-1.5S5.448 5 6 5s1 .672 1 1.5zM4.285 9.567a.5.5 0 0 1 .683.183A3.498 3.498 0 0 0 8 11.5a3.498 3.498 0 0 0 3.032-1.75.5.5 0 1 1 .866.5A4.498 4.498 0 0 1 8 12.5a4.498 4.498 0 0 1-3.898-2.25.5.5 0 0 1 .183-.683zM10 8c-.552 0-1-.672-1-1.5S9.448 5 10 5s1 .672 1 1.5S10.552 8 10 8z"/>
                </svg>
              </div>
              <h3 className="skill-card-title compact">Soft Skills</h3>
              <p className="skill-card-desc compact">
                Practice communication, leadership, and behavioral interview questions
              </p>
              <button
                className="btn-secondary skill-btn compact"
                onClick={() => navigate("/softskills")}
              >
                Start Soft Skills Interview
              </button>
            </div>
          </div>

          <div className="skill-footer compact">
            <button className="btn-tertiary back-btn" onClick={() => navigate(-1)}>
              ← Go Back
            </button>
            <p className="skill-hint compact">
              You can switch tracks anytime. Your progress will be saved.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}