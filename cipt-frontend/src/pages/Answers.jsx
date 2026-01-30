import React, { useEffect, useState } from "react";

export default function YourAnswers() {
  const [answers, setAnswers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/my-answers")
      .then((res) => {
        if (!res.ok) throw new Error("Failed to load answers.");
        return res.json();
      })
      .then((data) => {
        setAnswers(data);
        setLoading(false);
      })
      .catch((err) => {
        alert(err.message);
        setLoading(false);
      });
  }, []);

  return (
    <div className="login-page">
      {/* keep using style.css */}
      <link rel="stylesheet" href="/styles/style.css" />

      <div className="container">
        <h2>Your Recorded Answers</h2>

        <ol id="answerList">
          {loading ? (
            <li>Loading...</li>
          ) : answers.length === 0 ? (
            <li>No answers recorded this session.</li>
          ) : (
            answers.map((row, index) => (
              <li key={index}>
                {`Q${row.question}: ${row.answer}`}
              </li>
            ))
          )}
        </ol>

        <button onClick={() => (window.location.href = "/logout")}>
          Logout
        </button>
      </div>

      <div style={{ marginTop: "20px" }}>
        <button onClick={() => (window.location.href = "/")}>
          Go to Homepage
        </button>

        <button onClick={() => (window.location.href = "/logout")}>
          Logout
        </button>
      </div>
    </div>
  );
}
