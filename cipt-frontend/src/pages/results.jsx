import { useEffect, useState } from "react";

export default function TechnicalAssessment() {
  const [results, setResults] = useState([]);

  useEffect(() => {
    fetch("/analyze-answers", { method: "POST" })
      .then((res) => res.json())
      .then((data) => setResults(data))
      .catch((err) => console.error(err));
  }, []);

  return (
    <div className="assessment-container">
      <h2 className="page-title">Your Technical Skill Assessment</h2>

      <ul id="resultsList" className="results-list">
        {results.map((r, index) => (
          <li key={index} className="result-item">
            Q{r.question}: {r.percentage}% correctness
          </li>
        ))}
      </ul>
    </div>
  );
}
