// UserProfile.jsx
import React, { useState, useEffect } from 'react';
import "../styles/userProfile.css";
import { API_BASE_URL } from "../config";

const UserProfile = () => {
  const [user, setUser] = useState(null);
  const [showDropdown, setShowDropdown] = useState(false);

  useEffect(() => {
    // Check if user is logged in
    const checkUser = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/check-session`, {
          credentials: 'include'
        });
        const data = await response.json();
        if (data.loggedIn) {
          setUser({
            username: data.username,
            domain: data.domain
          });
        } else {
          setUser(null);
        }
      } catch (error) {
        console.error('Error checking session:', error);
      }
    };

    checkUser();
    // Check every 30 seconds
    const interval = setInterval(checkUser, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = async () => {
    try {
      await fetch(`${API_BASE_URL}/logout`, {
        method: 'POST',
        credentials: 'include'
      });
      setUser(null);
      window.location.href = '/login';
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  if (!user) {
    return (
      <div className="user-profile">
        <a href="/login" className="login-link">Login</a>
        <a href="/register" className="register-link">Register</a>
      </div>
    );
  }

  return (
    <div className="user-profile">
      <div
        className="profile-button"
        onClick={() => setShowDropdown(!showDropdown)}
      >
        <div className="avatar">
          {user.username.charAt(0).toUpperCase()}
        </div>
        <span className="username">{user.username}</span>
        <span className="dropdown-arrow">▼</span>
      </div>

      {showDropdown && (
        <div className="profile-dropdown">
          <div className="dropdown-header">
            <div className="dropdown-avatar">
              {user.username.charAt(0).toUpperCase()}
            </div>
            <div className="dropdown-info">
              <div className="dropdown-username">{user.username}</div>
              {user.domain && (
                <div className="dropdown-domain">Domain: {user.domain}</div>
              )}
            </div>
          </div>

          <div className="dropdown-menu">
            <a href="/dashboard" className="dropdown-item">
              📊 Dashboard
            </a>
            <a href="/profile" className="dropdown-item">
              👤 My Profile
            </a>
            <a href="/my-answers" className="dropdown-item">
              🎬 My Answers
            </a>
            <div className="dropdown-divider"></div>
            <button onClick={handleLogout} className="dropdown-item logout">
              🚪 Logout
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserProfile;