import React, { useRef, useState, useEffect } from "react";
import "../styles/video.css";
import { API_BASE_URL } from "../config";

const VideoPage = () => {
  const questionVideoRef = useRef(null);
  const userCamRef = useRef(null);

  const [videos, setVideos] = useState([]);
  const [questionIndex, setQuestionIndex] = useState(0);
  const [recording, setRecording] = useState(false);
  const [timeLeft, setTimeLeft] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [isMuted, setIsMuted] = useState(true);
  const [error, setError] = useState("");

  const timerRef = useRef(null);
  const mediaRecorderRef = useRef(null);
  const streamRef = useRef(null);
  const chunksRef = useRef([]);

  // Check session on component mount
  useEffect(() => {
    const checkSession = async () => {
      try {
        console.log("🔍 Checking session...");
        const response = await fetch(`${API_BASE_URL}/check-session`, {
          method: 'GET',
          credentials: 'include'
        });

        const data = await response.json();
        console.log("Session check result:", data);

        if (!response.ok || !data.loggedIn) {
          console.warn("⚠️ Session not valid, redirecting to login...");
          window.location.href = '/login';
        }
      } catch (err) {
        console.error("❌ Session check failed:", err);
      }
    };

    checkSession();
  }, []);

  useEffect(() => {
    // Get URL parameters
    const params = new URLSearchParams(window.location.search);
    const domain = params.get("domain");
    const dur = parseInt(params.get("duration") || 0) * 60;

    console.log("📌 URL Parameters - Domain:", domain, "Duration:", dur);

    if (!domain) {
      setError("No domain selected. Please select a domain first.");
      setIsLoading(false);
      return;
    }

    setTimeLeft(dur);

    const getSetNumberFromDomain = (domain) => {
      const match = domain.match(/^(\d+)_/);
      return match ? parseInt(match[1]) : 1;
    };

    const processAndSetVideos = (videoList, domain, setNumber) => {
      console.log(`🔄 Processing videos for ${domain} (Set ${setNumber})...`);

      const uniqueVideos = new Map();

      videoList.forEach(video => {
        if (!video || typeof video !== 'string') return;

        const videoStr = String(video).trim();
        const lower = videoStr.toLowerCase();

        const isVideoFile = lower.endsWith('.mp4') ||
          lower.endsWith('.mov') ||
          lower.endsWith('.webm') ||
          lower.endsWith('.avi') ||
          lower.endsWith('.mkv') ||
          lower.endsWith('.wmv');

        if (isVideoFile) {
          const filename = videoStr.split('/').pop();
          const filenameLower = filename.toLowerCase();

          if (!uniqueVideos.has(filenameLower)) {
            let finalPath;
            if (!videoStr.includes('/') && !videoStr.startsWith('http')) {
              finalPath = `/videos/${domain}/${videoStr}`;
            } else if (!videoStr.startsWith('http') && !videoStr.startsWith('/videos/')) {
              finalPath = `/videos/${domain}/${videoStr}`;
            } else {
              finalPath = videoStr;
            }

            uniqueVideos.set(filenameLower, {
              original: videoStr,
              final: finalPath,
              filename: filename
            });
          }
        }
      });

      console.log(`✅ Found ${uniqueVideos.size} unique videos`);

      const filteredVideos = Array.from(uniqueVideos.values())
        .map(item => item.final)
        .sort((a, b) => {
          const getQuestionNumber = (str) => {
            const filename = str.split('/').pop();
            const match = filename.match(/(\d+)_(\d+)\./i);
            if (match) {
              return parseInt(match[2]);
            }
            const fallbackMatch = filename.match(/(\d+)\./i);
            return fallbackMatch ? parseInt(fallbackMatch[1]) : 0;
          };

          return getQuestionNumber(a) - getQuestionNumber(b);
        });

      console.log("✅ Sorted videos:", filteredVideos.map(v => v.split('/').pop()));

      if (filteredVideos.length === 0) {
        setError(`No playable video files found for domain: ${domain}`);
        return false;
      } else {
        setVideos(filteredVideos);
        setError("");
        alert(`✅ Found ${filteredVideos.length} video(s) for ${domain}`);
        return true;
      }
    };

    const discoverVideosForDomain = async (domain, setNumber) => {
      console.log(`🔍 Discovering videos for ${domain} (Set ${setNumber})...`);

      const existingVideos = [];
      const extensions = ['.mp4', '.mov', '.MOV', '.webm', '.avi'];

      for (let q = 1; q <= 50; q++) {
        for (const ext of extensions) {
          const patterns = [
            `${setNumber}_${q}${ext}`,
            `${setNumber}_${q}${ext.toLowerCase()}`,
            `${setNumber}_${q}${ext.toUpperCase()}`,
            `question_${setNumber}_${q}${ext}`,
            `q${setNumber}_${q}${ext}`,
          ];

          for (const pattern of patterns) {
            const testUrl = `${API_BASE_URL}/videos/${domain}/${pattern}`;
            try {
              const response = await fetch(testUrl, { method: 'HEAD' });
              if (response.ok) {
                existingVideos.push(`/videos/${domain}/${pattern}`);
                console.log(`✅ Found: ${pattern}`);
                break;
              }
            } catch (err) {
              // Skip errors
            }
          }

          if (q % 10 === 0) {
            console.log(`🔍 Checked ${q} questions, found ${existingVideos.length} videos...`);
          }

          if (q >= 20 && existingVideos.length === 0) {
            console.log("🔄 No videos found with set pattern, trying generic patterns...");
            break;
          }
        }

        if (existingVideos.length === 0) {
          console.log("🔄 Trying generic patterns...");

          for (let q = 1; q <= 30; q++) {
            for (const ext of extensions) {
              const patterns = [
                `${q}${ext}`,
                `question_${q}${ext}`,
                `q${q}${ext}`,
                `video${q}${ext}`,
              ];

              for (const pattern of patterns) {
                const testUrl = `${API_BASE_URL}/videos/${domain}/${pattern}`;
                try {
                  const response = await fetch(testUrl, { method: 'HEAD' });
                  if (response.ok) {
                    existingVideos.push(`/videos/${domain}/${pattern}`);
                    console.log(`✅ Found: ${pattern}`);
                    break;
                  }
                } catch (err) {
                  // Skip errors
                }
              }
            }
          }

          try {
            const apiUrl = `${API_BASE_URL}/get-videos?domain=${encodeURIComponent(domain)}`;
            console.log("🌐 Trying API:", apiUrl);

            const response = await fetch(apiUrl, {
              method: 'GET',
              credentials: 'include',
              headers: { 'Accept': 'application/json' }
            });

            if (response.ok) {
              const data = await response.json();
              console.log("✅ API response received");

              let apiVideos = [];
              if (Array.isArray(data)) {
                apiVideos = data;
              } else if (data && typeof data === 'object') {
                if (data.videos && Array.isArray(data.videos)) {
                  apiVideos = data.videos;
                } else if (data.files && Array.isArray(data.files)) {
                  apiVideos = data.files;
                } else if (data.data && Array.isArray(data.data)) {
                  apiVideos = data.data;
                } else if (data.message && Array.isArray(data.message)) {
                  apiVideos = data.message;
                }
              }

              if (apiVideos.length > 0) {
                console.log(`✅ Found ${apiVideos.length} videos via API`);
                apiVideos.forEach(video => {
                  const videoStr = String(video).trim();
                  if (!existingVideos.includes(videoStr)) {
                    existingVideos.push(videoStr);
                  }
                });
              }
            }
          } catch (apiError) {
            console.log("❌ API call failed:", apiError.message);
          }

          if (existingVideos.length > 0) {
            console.log(`✅ Total found: ${existingVideos.length} videos`);
            return existingVideos;
          }

          return [];
        };

        const fetchVideos = async () => {
          try {
            setIsLoading(true);
            setError("");

            const setNumber = getSetNumberFromDomain(domain);
            console.log(`🚀 Fetching videos for ${domain} (Set ${setNumber})`);

            const discoveredVideos = await discoverVideosForDomain(domain, setNumber);

            if (discoveredVideos.length > 0) {
              const success = processAndSetVideos(discoveredVideos, domain, setNumber);
              if (success) {
                setIsLoading(false);
                return;
              }
            }

            console.log("🔄 No videos found, creating set-based fallback...");

            const fallbackVideos = [];
            const subjectName = domain.replace(/^\d+_/, '');

            for (let q = 1; q <= 15; q++) {
              fallbackVideos.push(`/videos/${domain}/${setNumber}_${q}.mp4`);
              fallbackVideos.push(`/videos/${domain}/${setNumber}_${q}.mov`);
              fallbackVideos.push(`/videos/${domain}/${setNumber}_${q}.MOV`);
            }

            console.log(`🔄 Created ${fallbackVideos.length} fallback videos for ${subjectName} (Set ${setNumber})`);

            setVideos(fallbackVideos);
            setError(`No videos found. Using fallback patterns for ${subjectName}.`);

          } catch (err) {
            console.error("❌ Error:", err);
            setError(`Error: ${err.message}`);

            const setNumber = getSetNumberFromDomain(domain);
            const fallbackVideos = [];
            for (let q = 1; q <= 10; q++) {
              fallbackVideos.push(`/videos/${domain}/${setNumber}_${q}.mp4`);
            }
            setVideos(fallbackVideos);

          } finally {
            setIsLoading(false);
          }
        };

        fetchVideos();

        return () => {
          if (timerRef.current) {
            clearInterval(timerRef.current);
            timerRef.current = null;
          }
          const stream = streamRef.current;
          if (stream) {
            stream.getTracks().forEach(track => track.stop());
          }
        };
      }, []);

  useEffect(() => {
    if (videos.length > 0 && timeLeft > 0) {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }

      timerRef.current = setInterval(() => {
        setTimeLeft(prev => {
          if (prev <= 1) {
            clearInterval(timerRef.current);
            timerRef.current = null;
            alert("Time's up!");
            window.location.href = "/final-report";
            return 0;
          }
          return prev - 1;
        });
      }, 1000);

      return () => {
        if (timerRef.current) {
          clearInterval(timerRef.current);
          timerRef.current = null;
        }
      };
    }
  }, [videos, timeLeft]);

  useEffect(() => {
    if (videos.length === 0 || !questionVideoRef.current) return;

    const video = questionVideoRef.current;
    const currentVideoPath = videos[questionIndex];

    if (!currentVideoPath) {
      console.error("❌ No video path for index:", questionIndex);
      return;
    }

    let videoPath;
    if (currentVideoPath.startsWith('http')) {
      videoPath = currentVideoPath;
    } else {
      videoPath = `${API_BASE_URL}${currentVideoPath}`;
    }

    console.log(`🎥 Loading video ${questionIndex + 1}/${videos.length}: ${currentVideoPath}`);

    video.onloadeddata = null;
    video.onerror = null;
    video.oncanplay = null;

    video.muted = isMuted;
    video.src = "";

    setTimeout(() => {
      video.src = videoPath;

      const handleCanPlay = () => {
        console.log("✅ Video can play");
        video.play().then(() => {
          console.log("✅ Video playback started");
          const overlay = document.querySelector('.video-overlay');
          if (overlay) overlay.style.display = 'none';
        }).catch(playError => {
          console.log("⚠️ Autoplay blocked:", playError.message);
          const overlay = document.querySelector('.video-overlay');
          if (overlay) overlay.style.display = 'flex';
        });
      };

      const handleError = (e) => {
        console.error("❌ Video error:", e.target.error);
        alert(`Cannot load video: ${currentVideoPath.split('/').pop()}`);
      };

      const handleEnded = () => {
        console.log("✅ Video ended");
        const overlay = document.querySelector('.video-overlay');
        if (overlay) overlay.style.display = 'flex';
      };

      video.addEventListener('canplay', handleCanPlay);
      video.addEventListener('error', handleError);
      video.addEventListener('ended', handleEnded);

      video.load();

      return () => {
        video.removeEventListener('canplay', handleCanPlay);
        video.removeEventListener('error', handleError);
        video.removeEventListener('ended', handleEnded);
        video.pause();
      };
    }, 100);

  }, [videos, questionIndex, isMuted]);

  const startRecording = async () => {
    try {
      console.log("🎬 Starting recording...");
      setRecording(true);
      chunksRef.current = [];

      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          width: { ideal: 1280 },
          height: { ideal: 720 }
        },
        audio: true
      });

      console.log("📹 Camera stream obtained");
      streamRef.current = stream;
      userCamRef.current.srcObject = stream;

      const mediaRecorder = new MediaRecorder(stream, {
        mimeType: 'video/webm;codecs=vp8,opus'
      });
      mediaRecorderRef.current = mediaRecorder;

      mediaRecorder.ondataavailable = (e) => {
        console.log(`📦 Data chunk: ${e.data.size} bytes`);
        if (e.data.size > 0) {
          chunksRef.current.push(e.data);
        }
      };

      mediaRecorder.onstop = async () => {
        console.log("🛑 Recording stopped, processing video...");

        if (chunksRef.current.length === 0) {
          console.error("❌ No video data collected!");
          setError("No video recorded. Please try again.");
          return;
        }

        const blob = new Blob(chunksRef.current, { type: 'video/webm' });
        console.log(`📊 Video blob created: ${blob.size} bytes`);

        const formData = new FormData();
        const params = new URLSearchParams(window.location.search);
        const domain = params.get('domain') || 'unknown';

        // Create filename
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `${domain}_q${questionIndex + 1}_${timestamp}.webm`;

        formData.append('video', blob, filename);
        formData.append('question', questionIndex + 1);
        formData.append('domain', domain);

        // Show uploading state
        const uploadStatusDiv = document.createElement('div');
        uploadStatusDiv.className = 'upload-status-toast';
        uploadStatusDiv.innerHTML = `
          <div class="spinner-small"></div>
          <span>Uploading to AWS cloud...</span>
        `;
        document.body.appendChild(uploadStatusDiv);

        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 60000);

          const response = await fetch(`${API_BASE_URL}/upload-answer`, {
            method: 'POST',
            body: formData,
            credentials: 'include', // IMPORTANT: Send cookies
            signal: controller.signal
          });

          clearTimeout(timeoutId);

          if (response.ok) {
            const result = await response.json();
            console.log("✅ Upload successful:", result);

            // Success Message
            uploadStatusDiv.className = 'upload-status-toast success';
            uploadStatusDiv.innerHTML = `
              <span class="icon">✅</span>
              <div>
                <strong>Upload Successful!</strong>
                <p>Answer saved to AWS Secure Storage.</p>
              </div>
            `;

            // Auto hide after 3 seconds
            setTimeout(() => {
              if (uploadStatusDiv.parentNode) document.body.removeChild(uploadStatusDiv);
            }, 3000);

          } else {
            const errorText = await response.json();
            console.error("❌ Server error:", response.status, errorText);
            throw new Error(errorText.error || "Upload failed");
          }
        } catch (error) {
          console.error("❌ Upload failed:", error);

          // Error Message
          uploadStatusDiv.className = 'upload-status-toast error';
          uploadStatusDiv.innerHTML = `
            <span class="icon">❌</span>
            <div>
              <strong>Upload Failed</strong>
              <p>${error.message}</p>
            </div>
          `;

          // Save locally as fallback
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = filename;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);

          setTimeout(() => {
            if (uploadStatusDiv.parentNode) document.body.removeChild(uploadStatusDiv);
          }, 5000);
        } finally {
          chunksRef.current = [];
        }
      };

      mediaRecorder.onerror = (event) => {
        console.error("❌ MediaRecorder error:", event.error);
        alert(`Recording error: ${event.error?.message || 'Unknown error'}`);
      };

      mediaRecorder.start(1000);
      console.log("🎥 Recording started");

      // Auto-stop after 5 minutes
      setTimeout(() => {
        if (recording) {
          console.log("⏰ Auto-stopping recording after 5 minutes");
          stopRecording();
        }
      }, 300000);

    } catch (err) {
      console.error("❌ Recording setup error:", err);

      let errorMessage = `Cannot access camera/microphone: ${err.message}`;
      if (err.name === 'NotAllowedError') {
        errorMessage = "❌ Camera/microphone access was denied. Please allow access and try again.";
      } else if (err.name === 'NotFoundError') {
        errorMessage = "❌ No camera/microphone found.";
      } else if (err.name === 'NotReadableError') {
        errorMessage = "❌ Camera/microphone is in use by another application.";
      }

      alert(errorMessage);
      setRecording(false);
    }
  };

  const stopRecording = () => {
    console.log("🛑 Stop recording called");

    if (mediaRecorderRef.current && recording) {
      console.log("⏸️ Stopping MediaRecorder...");
      mediaRecorderRef.current.stop();
    }

    const stream = streamRef.current;
    if (stream) {
      console.log("📹 Stopping camera stream...");
      stream.getTracks().forEach(track => track.stop());
      streamRef.current = null;
      if (userCamRef.current) {
        userCamRef.current.srcObject = null;
      }
    }

    setRecording(false);
    console.log("✅ Recording stopped");
  };

  const nextQuestion = () => {
    if (recording) {
      if (!window.confirm("You are recording. Stop recording and move to next question?")) {
        return;
      }
      stopRecording();
    }

    const next = questionIndex + 1;
    if (next >= videos.length) {
      alert("All questions completed!");
      window.location.href = "/final-report";
      return;
    }

    setQuestionIndex(next);
  };

  const prevQuestion = () => {
    if (questionIndex === 0) return;

    if (recording) {
      if (!window.confirm("You are recording. Stop recording and go back to previous question?")) {
        return;
      }
      stopRecording();
    }

    const prev = questionIndex - 1;
    setQuestionIndex(prev);
  };

  const quitAssessment = () => {
    if (window.confirm("Are you sure you want to quit?")) {
      if (recording) stopRecording();
      window.location.href = "/final-report";
    }
  };

  const restartVideo = () => {
    if (questionVideoRef.current) {
      questionVideoRef.current.currentTime = 0;
      questionVideoRef.current.play().then(() => {
        const overlay = document.querySelector('.video-overlay');
        if (overlay) overlay.style.display = 'none';
      }).catch(err => {
        console.log("❌ Restart play blocked:", err);
      });
    }
  };

  const handlePlayClick = () => {
    if (questionVideoRef.current) {
      questionVideoRef.current.play().then(() => {
        const overlay = document.querySelector('.video-overlay');
        if (overlay) overlay.style.display = 'none';
      }).catch(err => {
        console.log("❌ Play click blocked:", err);
      });
    }
  };

  const toggleMute = () => {
    if (questionVideoRef.current) {
      const newMuted = !questionVideoRef.current.muted;
      questionVideoRef.current.muted = newMuted;
      setIsMuted(newMuted);
    }
  };

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  // Test server connection
  const testServer = async () => {
    try {
      console.log("🔌 Testing server connection...");
      const response = await fetch(`${API_BASE_URL}/test`, {
        credentials: 'include'
      });
      const data = await response.json();
      console.log("Server test result:", data);
      alert(`Server: ${data.status}\nAnswers folder: ${data.folderExists ? '✅ Exists' : '❌ Missing'}`);
    } catch (error) {
      console.error("Server test failed:", error);
      alert("❌ Cannot connect to server. Make sure backend is running on port 5000.");
    }
  };

  if (isLoading) {
    return (
      <div className="loading-state">
        <div className="loading-content">
          <div className="spinner"></div>
          <h2>Loading Assessment...</h2>
          <p>Domain: {new URLSearchParams(window.location.search).get("domain")}</p>
          <p>Searching for videos...</p>
          <button onClick={testServer} style={{ marginTop: '20px', padding: '10px' }}>
            Test Server Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="video-container">

      <div className="status-bar">
        <div className="status-center">
          Question {questionIndex + 1} of {videos.length}
        </div>
        <div className="status-right">
          <span className="timer-display">⏰ {formatTime(timeLeft)}</span>
          <button
            onClick={testServer}
            className="test-btn"
            title="Test server connection"
          >
            🔌
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          ⚠️ {error}
        </div>
      )}

      <div className="main-content">

        <div className="left-panel">
          <div className="panel-header">
            <h3>Watch the Question</h3>
            <div className="audio-controls">
              <button
                onClick={toggleMute}
                className={`mute-btn ${isMuted ? 'muted' : 'unmuted'}`}
              >
                {isMuted ? '🔇 Unmute Audio' : '🔊 Mute Audio'}
              </button>
              <span className="audio-hint">
                {isMuted ? 'Audio is muted. Click "Unmute" to hear.' : 'Audio is playing.'}
              </span>
            </div>
          </div>

          <div className="video-wrapper">
            <video
              ref={questionVideoRef}
              controls
              muted={isMuted}
              className="question-video"
              playsInline
              preload="auto"
              key={`video-${questionIndex}`}
            />
            <div className="video-overlay">
              <button
                onClick={handlePlayClick}
                className="play-overlay-btn"
              >
                ▶ Click to Play
              </button>
            </div>
          </div>

          <div className="video-controls">
            <button
              onClick={handlePlayClick}
              className="control-btn play-btn"
            >
              ▶ Play Video
            </button>
            <button
              onClick={() => questionVideoRef.current?.pause()}
              className="control-btn pause-btn"
            >
              ⏸ Pause
            </button>
            <button
              onClick={restartVideo}
              className="control-btn restart-btn"
            >
              ↺ Restart
            </button>
            <button
              onClick={prevQuestion}
              disabled={questionIndex === 0}
              className="control-btn prev-btn"
            >
              ← Previous
            </button>
            <button
              onClick={nextQuestion}
              disabled={questionIndex >= videos.length - 1}
              className="control-btn next-btn"
            >
              Next Question →
            </button>
          </div>
        </div>

        <div className="right-panel">
          <div className="panel-header">
            <h3>Record Your Answer</h3>
            {recording && (
              <div className="recording-status">
                <span className="recording-dot"></span>
                RECORDING
              </div>
            )}
          </div>

          <div className="camera-wrapper">
            <video
              ref={userCamRef}
              autoPlay
              muted
              playsInline
              className="camera-video"
            />
            {recording && (
              <div className="recording-overlay">
                <div className="recording-pulse"></div>
                <div className="recording-text">
                  ● RECORDING
                </div>
              </div>
            )}
          </div>

          <div className="recording-controls">
            {!recording ? (
              <button
                onClick={startRecording}
                className="record-btn start-btn"
                disabled={recording}
              >
                🎤 Start Recording
              </button>
            ) : (
              <button
                onClick={stopRecording}
                className="record-btn stop-btn"
              >
                ⏹ Stop Recording
              </button>
            )}
          </div>

          <div className="assessment-controls">
            <button
              onClick={quitAssessment}
              className="quit-btn"
            >
              🏁 Quit Assessment
            </button>
          </div>

          <div className="debug-info">
            <small>
              📁 Videos: {videos.length} |
              🎥 Index: {questionIndex + 1} |
              ⏱ Time: {formatTime(timeLeft)}
            </small>
          </div>
        </div>
      </div>

      <div className="progress-container">
        <div className="progress-bar">
          <div
            className="progress-fill"
            style={{ width: `${((questionIndex + 1) / videos.length) * 100}%` }}
          ></div>
        </div>
        <div className="progress-text">
          Progress: {questionIndex + 1} of {videos.length} questions |
          Time remaining: {formatTime(timeLeft)}
        </div>
      </div>
    </div>
  );
};

export default VideoPage;