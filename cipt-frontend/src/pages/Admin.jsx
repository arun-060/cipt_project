import { useEffect, useState } from "react";

export default function Admin() {
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState("");
  const [answers, setAnswers] = useState([]);

  useEffect(() => {
    loadUsers();
  }, []);

  async function loadUsers() {
    const res = await fetch("/admin/users");
    const users = await res.json();
    setUsers(users);
  }

  async function loadAnswers(username) {
    if (!username) return;
    const res = await fetch("/admin/answers/" + username);
    const data = await res.json();
    setAnswers(data);
  }

  return (
    <div className="login-page">
      {/* INLINE CSS EXACT FROM HTML */}
      <style>{`
        body, html {
          margin: 0;
          padding: 0;
        }
        .login-page {
          background: #f8f8f8;
          min-height: 100vh;
          padding: 40px;
          font-family: Arial, sans-serif;
        }
        .container {
          width: 450px;
          margin: auto;
          background: white;
          padding: 25px;
          border-radius: 10px;
          box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h2, h3 {
          text-align: center;
        }
        select, button {
          padding: 10px;
          margin-top: 10px;
          width: 100%;
        }
      `}</style>

      <div className="container">
        <h2>Admin Dashboard</h2>

        <h3>All Registered Users</h3>
        <ul>
          {users.length === 0 ? (
            <li>Loading...</li>
          ) : (
            users.map((user, i) => <li key={i}>{user.username}</li>)
          )}
        </ul>

        <h3>User Answers</h3>
        <select
          value={selectedUser}
          onChange={(e) => {
            setSelectedUser(e.target.value);
            loadAnswers(e.target.value);
          }}
        >
          <option value="">-- Select a user --</option>
          {users.map((u, i) => (
            <option key={i} value={u.username}>
              {u.username}
            </option>
          ))}
        </select>

        <ol>
          {answers.map((ans, i) => (
            <li key={i}>
              Q{ans.question}: {ans.answer} (Session:{" "}
              {new Date(ans.timestamp).toLocaleString()})
            </li>
          ))}
        </ol>

        <div style={{ marginTop: "20px" }}>
          <button onClick={() => (window.location.href = "/")}>
            Go to Homepage
          </button>
        </div>
      </div>
    </div>
  );
}
