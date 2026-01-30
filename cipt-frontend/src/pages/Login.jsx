import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/login.css";
import { API_BASE_URL } from "../config";

export default function AuthPage() {
  const navigate = useNavigate();
  const [isRegister, setIsRegister] = useState(false);

  // --- LOGIN STATE ---
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  // --- REGISTER STATE ---
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newEmail, setNewEmail] = useState("");

  // --- LOGIN HANDLER ---
  const handleLogin = async (e) => {
    e.preventDefault();
    if (!loginUsername || !loginPassword) {
      alert("Please enter both username and password");
      return;
    }
    try {
      const res = await fetch(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: loginUsername,
          password: loginPassword,
        }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`HTTP error! status: ${res.status}, message: ${text}`);
      }
      const data = await res.json();
      if (data.success) {
        navigate("/skills");
      }
      else alert("Login failed. Please check your credentials.");
    } catch (err) {
      console.error("Login fetch failed:", err);
      alert("Login failed. Could not reach server.");
    }
  };

  // --- REGISTER HANDLER ---
  const handleRegister = async (e) => {
    e.preventDefault();
    if (!newUsername || !newPassword || !newEmail) {
      alert("Please fill all fields");
      return;
    }
    try {
      const res = await fetch(`${API_BASE_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: newUsername,
          password: newPassword,
          email: newEmail,
        }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`HTTP error! status: ${res.status}, message: ${text}`);
      }
      const data = await res.json();
      alert(data.message || "Registration successful!");
    } catch (err) {
      console.error("Register fetch failed:", err);
      alert("Registration failed. Could not reach server.");
    }
  };

  return (
    <>
      <style>{`
        :root {
          --accent1: #6a11cb;
          --accent2: #2575fc;
        }

        body, html, #root {
          height: 100%;
          margin: 0;
          font-family: "Segoe UI", sans-serif;
          background: linear-gradient(135deg, var(--accent1), var(--accent2));
        }

        .auth-page {
          height: 100vh;
          display: flex;
          justify-content: center;
          align-items: center;
          padding: 20px;
        }

        .auth-box {
          width: 480px;
          height: 560px;
          background: rgba(255,255,255,0.97);
          border-radius: 25px;
          padding: 0;
          box-shadow: 0 22px 50px rgba(0,0,0,0.28);
          overflow: hidden;
          position: relative;
        }

        .slider {
          width: 960px; /* double the panel width */
          height: 100%;
          display: flex;
          transition: transform 0.55s ease;
        }

        .slider.move-left {
          transform: translateX(-480px); /* slide by one panel */
        }


        h2 {
          margin-bottom: 10px;
          font-size: 28px;
          color: #5807afff;
        }

        .sub {
          margin-top: 0;
          margin-bottom: 22px;
          font-size: 15px;
          color: #444;
        }

.panel {
  width: 480px;
  padding: 40px;   /* keep padding same for both panels */
  box-sizing: border-box;  /* include padding in width calculations */
}

.field, .btn {
  width: 100%;                /* fills the panel width */
  box-sizing: border-box;     /* includes padding in width */
}

.field {
  width: calc(100% - 0px);  /* make it exactly same as button */
  padding: 10px 16px;
  margin-bottom: 18px;
  font-size: 17px;
  border-radius: 10px;
  border: 1px solid #6a11cb; /* permanent thin border */
  background: #fff;
  outline: none;
  color: var(--accent1);
  box-sizing: border-box;   /* include padding in width */
}




        .btn {
          width: 100%;
          padding: 14px;
          border: none;
          border-radius: 14px;
          background: linear-gradient(135deg, var(--accent1), var(--accent2));
          color: white;
          font-size: 17px;
          font-weight: 600;
          cursor: pointer;
          margin-top: 10px;
          box-sizing: border-box;
        }

        .switch {
          text-align: center;
          margin-top: 20px;
          font-size: 15px;
          color: #333;
        }

        .switch span {
          color: var(--accent1);
          cursor: pointer;
          font-weight: 700;
          margin-left: 5px;
        }
      `}</style>

      <div className="auth-page">
        <div className="auth-box">
          <div className={`slider ${isRegister ? "move-left" : ""}`}>

            {/* LOGIN PANEL */}
            <div className="panel">
              <h2>Welcome Back</h2>
              <p className="sub">Sign in to your account</p>

              <input
                className="field"
                type="text"
                placeholder="Username"
                value={loginUsername}
                onChange={(e) => setLoginUsername(e.target.value)}
              />
              <input
                className="field"
                type="password"
                placeholder="Password"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
              />

              <button className="btn" onClick={handleLogin}>Login</button>

              <p className="switch">
                New here? <span onClick={() => setIsRegister(true)}>Create account</span>
              </p>
            </div>

            {/* REGISTER PANEL */}
            <div className="panel">
              <h2>Create Account</h2>
              <p className="sub">Join us — it's quick!</p>

              <input
                className="field"
                type="text"
                placeholder="Full Name"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
              />
              <input
                className="field"
                type="email"
                placeholder="Email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
              />
              <input
                className="field"
                type="password"
                placeholder="Password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />

              <button className="btn" onClick={handleRegister}>Register</button>

              <p className="switch">
                Already have an account? <span onClick={() => setIsRegister(false)}>Sign in</span>
              </p>
            </div>

          </div>
        </div>
      </div>
    </>
  );
}
