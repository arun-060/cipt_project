import React from "react";
import { useNavigate } from "react-router-dom";

export default function SoftSkills() {
  const navigate = useNavigate();

  const skillCards = [
    {
      id: 'posture',
      title: 'Posture Detection',
      description: 'Analyze body posture and positioning',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" fill="currentColor" viewBox="0 0 16 16">
          <path d="M8.5 2a.5.5 0 0 0-1 0v5.5H3a.5.5 0 0 0 0 1h5.5V14a.5.5 0 0 0 1 0V8.5H13a.5.5 0 0 0 0-1H8.5V2z"/>
        </svg>
      )
    },
    {
      id: 'eye',
      title: 'Eye Contact Analysis',
      description: 'Evaluate eye contact patterns and engagement',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" fill="currentColor" viewBox="0 0 16 16">
          <path d="M16 8s-3-5.5-8-5.5S0 8 0 8s3 5.5 8 5.5S16 8 16 8zM1.173 8a13.133 13.133 0 0 1 1.66-2.043C4.12 4.668 5.88 3.5 8 3.5c2.12 0 3.879 1.168 5.168 2.457A13.133 13.133 0 0 1 14.828 8c-.058.087-.122.183-.195.288-.335.48-.83 1.12-1.465 1.755C11.879 11.332 10.119 12.5 8 12.5c-2.12 0-3.879-1.168-5.168-2.457A13.134 13.134 0 0 1 1.172 8z"/>
          <path d="M8 5.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM4.5 8a3.5 3.5 0 1 1 7 0 3.5 3.5 0 0 1-7 0z"/>
        </svg>
      )
    },
    {
      id: 'fer',
      title: 'Emotion Detection',
      description: 'Detect facial expressions and emotional responses',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" fill="currentColor" viewBox="0 0 16 16">
          <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>
          <path d="M4.285 9.567a.5.5 0 0 1 .683.183A3.498 3.498 0 0 0 8 11.5a3.498 3.498 0 0 0 3.032-1.75.5.5 0 1 1 .866.5A4.498 4.498 0 0 1 8 12.5a4.498 4.498 0 0 1-3.898-2.25.5.5 0 0 1 .183-.683zM7 6.5C7 7.328 6.552 8 6 8s-1-.672-1-1.5S5.448 5 6 5s1 .672 1 1.5zm4 0c0 .828-.448 1.5-1 1.5s-1-.672-1-1.5S9.448 5 10 5s1 .672 1 1.5z"/>
        </svg>
      )
    },
    {
      id: 'sound',
      title: 'Voice Analysis',
      description: 'Analyze voice tone, pitch, and speech patterns',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" fill="currentColor" viewBox="0 0 16 16">
          <path d="M11.536 14.01A8.473 8.473 0 0 0 14.026 8a8.473 8.473 0 0 0-2.49-6.01l-.708.707A7.476 7.476 0 0 1 13.025 8c0 2.071-.84 3.946-2.197 5.303l.708.707z"/>
          <path d="M10.121 12.596A6.48 6.48 0 0 0 12.025 8a6.48 6.48 0 0 0-1.904-4.596l-.707.707A5.483 5.483 0 0 1 11.025 8a5.483 5.483 0 0 1-1.61 3.89l.706.706z"/>
          <path d="M8.707 11.182A4.486 4.486 0 0 0 10.025 8a4.486 4.486 0 0 0-1.318-3.182L8 5.525A3.489 3.489 0 0 1 9.025 8 3.49 3.49 0 0 1 8 10.475l.707.707zM6.717 3.55A.5.5 0 0 1 7 4v8a.5.5 0 0 1-.812.39L3.825 10.5H1.5A.5.5 0 0 1 1 10V6a.5.5 0 0 1 .5-.5h2.325l2.363-1.89a.5.5 0 0 1 .529-.06z"/>
        </svg>
      )
    }
  ];

  return (
    <div className="softskills-page">
      <div className="softskills-container">
        <div className="softskills-content compact fit-all" style={{
          maxWidth: '680px',
          padding: '30px',
          marginTop: '0',
          maxHeight: '620px',
          minHeight: '620px',
          display: 'flex',
          flexDirection: 'column',
          background: 'rgba(255, 255, 255, 0.98)',
          boxShadow: '0 12px 35px rgba(0, 0, 0, 0.18)',
          overflow: 'hidden'
        }}>
          
          {/* Header - Smaller to leave more space for cards */}
          <div className="softskills-header fit-all" style={{
            textAlign: 'center',
            marginBottom: '15px',
            paddingBottom: '12px',
            borderBottom: '2px solid rgba(108, 18, 205, 0.15)',
            flexShrink: '0'
          }}>
            <div className="softskills-icon fit-all" style={{
              background: 'linear-gradient(135deg, rgba(108, 18, 205, 0.1), rgba(37, 106, 225, 0.1))',
              width: '60px',
              height: '60px',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 12px',
              color: '#6c12cde1'
            }}>
              <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" fill="currentColor" viewBox="0 0 16 16">
                <path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zM7 6.5C7 7.328 6.552 8 6 8s-1-.672-1-1.5S5.448 5 6 5s1 .672 1 1.5zM4.285 9.567a.5.5 0 0 1 .683.183A3.498 3.498 0 0 0 8 11.5a3.498 3.498 0 0 0 3.032-1.75.5.5 0 1 1 .866.5A4.498 4.498 0 0 1 8 12.5a4.498 4.498 0 0 1-3.898-2.25.5.5 0 0 1 .183-.683zM10 8c-.552 0-1-.672-1-1.5S9.448 5 10 5s1 .672 1 1.5S10.552 8 10 8z"/>
              </svg>
            </div>
            <h2 className="softskills-title fit-all" style={{
              color: '#222',
              fontSize: '1.8rem',
              marginBottom: '6px',
              fontWeight: '700',
              background: 'none',
              WebkitBackgroundClip: 'initial',
              WebkitTextFillColor: '#222',
              textShadow: 'none'
            }}>
              Soft Skill Assessment
            </h2>
            <p className="softskills-subtitle fit-all" style={{
              color: '#444',
              fontSize: '1rem',
              lineHeight: '1.3',
              margin: '0',
              fontWeight: '500'
            }}>
              Select an analysis tool to improve your communication skills
            </p>
          </div>

          {/* Skills Grid - Smaller cards so all 4 fit */}
          <div className="softskills-grid fit-all" style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(2, 1fr)',
            gap: '16px',
            marginBottom: '20px',
            flex: '1',
            overflowY: 'hidden',
            padding: '5px'
          }}>
            {skillCards.map((skill) => (
              <button
                key={skill.id}
                className="softskills-card fit-all"
                onClick={() => navigate(`/analyze/${skill.id}`)}
                onMouseOver={(e) => {
                  e.currentTarget.style.transform = 'translateY(-3px)';
                  e.currentTarget.style.boxShadow = '0 6px 15px rgba(108, 18, 205, 0.2)';
                  e.currentTarget.style.borderColor = '#6c12cde1';
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.boxShadow = '0 3px 8px rgba(0, 0, 0, 0.1)';
                  e.currentTarget.style.borderColor = 'rgba(108, 18, 205, 0.2)';
                }}
                style={{
                  background: 'white',
                  border: '2px solid rgba(108, 18, 205, 0.2)',
                  borderRadius: '12px',
                  padding: '18px 15px',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  textAlign: 'center',
                  boxShadow: '0 3px 8px rgba(0, 0, 0, 0.1)',
                  minHeight: '130px',
                  maxHeight: '130px',
                  justifyContent: 'center',
                  outline: 'none'
                }}
              >
                <div className="softskills-card-icon fit-all" style={{
                  background: 'linear-gradient(135deg, #6c12cde1, #256ae1)',
                  width: '48px',
                  height: '48px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginBottom: '12px',
                  color: 'white'
                }}>
                  {skill.icon}
                </div>
                <h3 className="softskills-card-title fit-all" style={{
                  color: '#222',
                  fontSize: '1.1rem',
                  fontWeight: '600',
                  lineHeight: '1.2',
                  margin: '0',
                  padding: '0 5px'
                }}>
                  {skill.title}
                </h3>
              </button>
            ))}
          </div>

          {/* Back Button */}
          <div className="softskills-buttons-container fit-all" style={{
            flexShrink: '0',
            marginTop: 'auto',
            paddingTop: '15px',
            borderTop: '1px solid rgba(0, 0, 0, 0.1)',
            display: 'flex',
            justifyContent: 'center'
          }}>
            <button 
              className="softskills-back-btn fit-all"
              onClick={() => navigate(-1)}
              onMouseOver={(e) => {
                e.currentTarget.style.background = '#7f8c8d';
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = '0 4px 10px rgba(0, 0, 0, 0.15)';
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.background = '#95a5a6';
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
              style={{
                background: '#95a5a6',
                color: 'white',
                border: 'none',
                padding: '12px 30px',
                borderRadius: '8px',
                fontSize: '15px',
                fontWeight: '600',
                cursor: 'pointer',
                transition: 'all 0.2s',
                minWidth: '150px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px'
              }}
            >
              ← Back
            </button>
          </div>
          
        </div>
      </div>
    </div>
  );
}