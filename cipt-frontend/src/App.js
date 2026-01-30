import { HashRouter, Routes, Route, useLocation } from "react-router-dom";

import Home from "./pages/Home";
import Login from "./pages/Login";
import Admin from "./pages/Admin";
import Results from "./pages/results";
import Skills from "./pages/skills";
import SoftSkills from "./pages/softskills";
import EyeContact from "./pages/eye_contact";
import Emotion from "./pages/emotion";
import BodyPosture from "./pages/body_posture";
import Guidelines from "./pages/Guidelines";
import Sound from "./pages/sound";
import TestCam from "./pages/testcam";
import TimeSlot from "./pages/timeslot";
import Video from "./pages/video";
import Answers from "./pages/Answers";
import SelectDomain from "./pages/domains";
import Navbar from "./components/Navbar";
import SoftskillAnalyzer from "./pages/SoftSkillAnalyzer";
import FinalReport from "./pages/FinalReport";

function AppWrapper() {
  const location = useLocation();

  // Hide navbar on HOME page AND LOGIN page
  const hideNavbar = location.pathname === "/" || location.pathname === "/login";

  return (
    <>
      {!hideNavbar && <Navbar />}

      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/admin" element={<Admin />} />
        <Route path="/results" element={<Results />} />
        <Route path="/skills" element={<Skills />} />
        <Route path="/softskills" element={<SoftSkills />} />
        <Route path="/eye-contact" element={<EyeContact />} />
        <Route path="/emotion" element={<Emotion />} />
        <Route path="/body-posture" element={<BodyPosture />} />
        <Route path="/guidelines" element={<Guidelines />} />
        <Route path="/sound" element={<Sound />} />
        <Route path="/testcam" element={<TestCam />} />
        <Route path="/timeslot" element={<TimeSlot />} />
        <Route path="/select-domain" element={<SelectDomain />} />
        <Route path="/video" element={<Video />} />
        <Route path="/answers" element={<Answers />} />
        {/* In your main App.js or routing file */}
        <Route path="/analyze/:type" element={<SoftskillAnalyzer />} />
        <Route path="/final-report" element={<FinalReport />} />
      </Routes>
    </>
  );
}

function App() {
  return (
    <HashRouter>
      <AppWrapper />
    </HashRouter>
  );
}

export default App;