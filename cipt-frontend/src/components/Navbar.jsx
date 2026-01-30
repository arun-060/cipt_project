import React from "react";
import { Link, useLocation } from "react-router-dom";
import "../styles/style.css";

const Navbar = () => {
  const location = useLocation();

  // Hide navbar ONLY on Home, Login and Video pages
  const hideOnPaths = ["/", "/login", "/video", "/analyze/eye", "/analyze/fer", "/analyze/posture", "/analyze/sound"];
  
  if (hideOnPaths.includes(location.pathname)) {
    return null;
  }

  // Show navbar on ALL other pages including SelectSkill

  return (
    <nav className="navbar">
      <h2 className="navbar-logo">Pick Up Tool</h2>

      <ul className="navbar-links">
        <li><Link to="/" className="navbar-link">🏠 Home</Link></li>
        <li><Link to="/about" className="navbar-link">About</Link></li>
        <li><Link to="/guidelines" className="navbar-link">Guidelines</Link></li>
        <li><Link to="/results" className="navbar-link">Results</Link></li>
        <li><Link to="/login" className="navbar-link">Logout</Link></li>
      </ul>
    </nav>
  );
};

export default Navbar;