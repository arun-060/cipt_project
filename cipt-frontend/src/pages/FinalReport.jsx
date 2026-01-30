import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL } from "../config";
import '../index.css';

const FinalReport = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [pdfPath, setPdfPath] = useState('');
    const [loadingStep, setLoadingStep] = useState(0);

    // Simulated loading steps for animation
    useEffect(() => {
        if (!loading) return;
        const interval = setInterval(() => {
            setLoadingStep(prev => (prev < 3 ? prev + 1 : prev));
        }, 1500);
        return () => clearInterval(interval);
    }, [loading]);

    useEffect(() => {
        const generateReport = async () => {
            try {
                setLoading(true);
                setError('');

                // 1. Get Latest Video
                console.log("Fetching latest uploaded video from session...");

                // 1. Get user & latest video info from session
                const sessionResponse = await fetch(`${API_BASE_URL}/api/get-latest-video`, {
                    method: 'GET',
                    credentials: 'include',
                });

                if (!sessionResponse.ok) {
                    throw new Error("No video found. Please complete the interview first.");
                }

                const videoData = await sessionResponse.json();

                if (!videoData.localPath) {
                    throw new Error("No video available for analysis");
                }

                // 2. Generate Report
                console.log("Starting report generation...");

                // 2. Trigger analysis with found video
                const response = await fetch(`${API_BASE_URL}/analyze/generate-report`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({
                        videoPath: videoData.localPath,
                        candidateName: videoData.username || "Candidate",
                        role: videoData.domain || "Applicant"
                    }),
                });

                const data = await response.json();

                if (data.success && data.pdfUrl) {
                    // Reduce zoom to 60-75% and hide toolbars
                    setPdfPath(`${data.pdfUrl} #toolbar = 0 & navpanes=0 & view=Fit & zoom=75`);
                } else {
                    setError(data.error || "Failed to generate report");
                }
            } catch (err) {
                console.error("Error generating report:", err);
                setError(err.message || "Network error or server unavailable");
            } finally {
                setLoading(false);
            }
        };

        generateReport();
    }, []);

    // --- LOADING STATE ---
    if (loading) {
        const steps = [
            "Connecting to assessment server...",
            "Analyzing facial expressions & posture...",
            "Generating performance metrics...",
            "Finalizing your professional report..."
        ];

        return (
            <div style={styles.loadingContainer}>
                <div style={styles.spinner}></div>
                <h2 style={styles.loadingTitle}>Analyzing Interview</h2>
                <div style={styles.loadingStep}>{steps[loadingStep]}</div>
                <div style={styles.progressBar}>
                    <div style={{ ...styles.progressFill, width: `${(loadingStep + 1) * 25}% ` }}></div>
                </div>
            </div>
        );
    }

    // --- ERROR STATE ---
    if (error) {
        return (
            <div style={styles.errorContainer}>
                <div style={styles.errorCard}>
                    <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>⚠️</div>
                    <h3>Analysis Failed</h3>
                    <p>{error}</p>
                    <div style={styles.buttonGroup}>
                        <button onClick={() => window.location.reload()} style={styles.retryBtn}>Retry Analysis</button>
                        <button onClick={() => navigate('/')} style={styles.homeBtn}>Return Home</button>
                    </div>
                </div>
            </div>
        );
    }

    // --- PDF VIEW STATE ---
    return (
        <div style={styles.pageContainer}>
            <div style={styles.pdfWrapper}>
                <iframe
                    src={pdfPath}
                    style={styles.iframe}
                    title="Interview Analysis Report"
                    type="application/pdf"
                />
            </div>

            {/* Action Bar at bottom */}
            <div style={styles.actionBar}>
                <button onClick={() => navigate('/')} style={styles.secondaryBtn}>
                    Back to Dashboard
                </button>
                <a href={pdfPath} download style={styles.downloadBtn}>
                    Download PDF
                </a>
            </div>
        </div>
    );
};

// Styles
const styles = {
    pageContainer: {
        height: '100vh',
        width: '100%',
        paddingTop: '80px', // Clear navbar
        display: 'flex',
        flexDirection: 'column',
        // White/Light background instead of dark gray
        background: '#f8f9fa',
        boxSizing: 'border-box'
    },
    pdfWrapper: {
        flex: 1,
        width: '100%',
        position: 'relative',
        display: 'flex',
        justifyContent: 'center',
        // Also light background
        background: '#f8f9fa',
        padding: '20px 0' // Add some spacing
    },
    iframe: {
        width: '100%', // Occupy full width
        height: '100%',
        border: 'none',
        display: 'block'
    },
    actionBar: {
        height: '60px',
        background: 'white',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '20px',
        borderTop: '1px solid #e5e7eb',
        zIndex: 10
    },
    downloadBtn: {
        padding: '10px 24px',
        background: '#3b82f6',
        color: 'white',
        textDecoration: 'none',
        borderRadius: '8px',
        fontWeight: '600',
        fontSize: '0.95rem',
        transition: 'background 0.2s'
    },
    secondaryBtn: {
        padding: '10px 24px',
        background: 'transparent',
        color: '#4b5563',
        border: '1px solid #d1d5db',
        borderRadius: '8px',
        fontWeight: '600',
        fontSize: '0.95rem',
        cursor: 'pointer'
    },

    // Loading State
    loadingContainer: {
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#fff',
        color: '#1e293b'
    },
    spinner: {
        width: '50px',
        height: '50px',
        border: '4px solid #e2e8f0',
        borderTopColor: '#3b82f6',
        borderRadius: '50%',
        animation: 'spin 1s linear infinite'
    },
    loadingTitle: {
        marginTop: '20px',
        fontSize: '1.5rem',
        color: '#334155'
    },
    loadingStep: {
        marginTop: '10px',
        color: '#64748b',
        fontSize: '0.9rem'
    },
    progressBar: {
        width: '300px',
        height: '6px',
        background: '#e2e8f0',
        borderRadius: '3px',
        marginTop: '20px',
        overflow: 'hidden'
    },
    progressFill: {
        height: '100%',
        background: '#3b82f6',
        transition: 'width 0.5s ease'
    },
    errorContainer: {
        height: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#fff'
    },
    errorCard: {
        padding: '2rem',
        textAlign: 'center'
    },
    retryBtn: {
        padding: '10px 20px',
        background: '#3b82f6',
        color: 'white',
        border: 'none',
        borderRadius: '8px',
        cursor: 'pointer',
        marginRight: '10px'
    }
};

export default FinalReport;
