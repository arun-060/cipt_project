import React from "react";
import { Link } from "react-router-dom";
import "../styles/Home.css";

export default function Home() {
  return (
    <div className="home-container">
      <header className="home-header">
        <h2>Pick Up Tool</h2>
      </header>

      <div className="home-hero">
        <h1 className="home-hero-title">Bridging the Gap</h1>
        <p className="home-hero-text">
          Prepare for real interviews with AI-powered video questions and instant performance feedback.
        </p>

        <Link to="/login" className="home-get-started-btn">
          Get Started
        </Link>
      </div>

      {/* Key Features */}
      <section className="home-section">
        <h2 className="home-section-title">Key Features</h2>
        <div className="home-grid">
          <div className="home-card">
            <strong className="home-card-title">🎥 AI Interviews</strong>
            <p className="home-card-text">Simulated real-time video-based Q&A sessions.</p>
          </div>

          <div className="home-card">
            <strong className="home-card-title">📊 Smart Feedback</strong>
            <p className="home-card-text">Posture, grammar, emotion, and accuracy analyzed.</p>
          </div>

          <div className="home-card">
            <strong className="home-card-title">⚡ Instant Insights</strong>
            <p className="home-card-text">Real-time clarity and eye contact evaluation.</p>
          </div>

          <div className="home-card">
            <strong className="home-card-title">📈 Reports</strong>
            <p className="home-card-text">Visual summary of your performance trends.</p>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="home-section">
        <h2 className="home-section-title">How It Works</h2>
        <div className="home-grid">
          <div className="home-card">
            <div className="home-step-number">1</div>
            <p className="home-card-text">Sign up and log in</p>
          </div>

          <div className="home-card">
            <div className="home-step-number">2</div>
            <p className="home-card-text">Select domain and time</p>
          </div>

          <div className="home-card">
            <div className="home-step-number">3</div>
            <p className="home-card-text">Answer video questions</p>
          </div>

          <div className="home-card">
            <div className="home-step-number">4</div>
            <p className="home-card-text">Receive performance report</p>
          </div>
        </div>
      </section>

      <footer className="home-footer">
        © 2025 CIPT. All rights reserved.
      </footer>
    </div>
  );
}