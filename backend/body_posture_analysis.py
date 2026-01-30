import cv2
import mediapipe as mp
import numpy as np
import math

# Initialize Mediapipe pose
mp_pose = mp.solutions.pose
pose = mp_pose.Pose()

def calculate_angle(a, b, c):
    """Returns angle (in degrees) between three points a-b-c with b as vertex."""
    a, b, c = np.array(a), np.array(b), np.array(c)
    ba, bc = a - b, c - b
    cosine_angle = np.dot(ba, bc) / (np.linalg.norm(ba) * np.linalg.norm(bc) + 1e-6)
    angle = np.degrees(np.arccos(np.clip(cosine_angle, -1.0, 1.0)))
    return angle

def get_body_posture_report(video_path):
    cap = cv2.VideoCapture(video_path)

    pitch_vals, yaw_vals, roll_vals = [], [], []
    spine_vals, shoulder_vals = [], []

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        results = pose.process(frame_rgb)

        if results.pose_landmarks:
            lm = results.pose_landmarks.landmark

            # Extract relevant landmarks
            nose = [lm[mp_pose.PoseLandmark.NOSE.value].x,
                    lm[mp_pose.PoseLandmark.NOSE.value].y]
            left_eye = [lm[mp_pose.PoseLandmark.LEFT_EYE.value].x,
                        lm[mp_pose.PoseLandmark.LEFT_EYE.value].y]
            right_eye = [lm[mp_pose.PoseLandmark.RIGHT_EYE.value].x,
                         lm[mp_pose.PoseLandmark.RIGHT_EYE.value].y]
            left_shoulder = [lm[mp_pose.PoseLandmark.LEFT_SHOULDER.value].x,
                             lm[mp_pose.PoseLandmark.LEFT_SHOULDER.value].y]
            right_shoulder = [lm[mp_pose.PoseLandmark.RIGHT_SHOULDER.value].x,
                              lm[mp_pose.PoseLandmark.RIGHT_SHOULDER.value].y]
            left_hip = [lm[mp_pose.PoseLandmark.LEFT_HIP.value].x,
                        lm[mp_pose.PoseLandmark.LEFT_HIP.value].y]
            right_hip = [lm[mp_pose.PoseLandmark.RIGHT_HIP.value].x,
                         lm[mp_pose.PoseLandmark.RIGHT_HIP.value].y]

            # Head pitch (vertical tilt)
            pitch = math.degrees(math.atan2(nose[1] - ((left_eye[1]+right_eye[1])/2),
                                            nose[0] - ((left_eye[0]+right_eye[0])/2)))
            pitch = np.clip(pitch, -90, 90)
            pitch_vals.append(pitch)

            # Head yaw (horizontal turn) - diff between eyes
            yaw = math.degrees(math.atan2(left_eye[0] - right_eye[0],
                                          left_eye[1] - right_eye[1]))
            yaw = np.clip(yaw, -90, 90)
            yaw_vals.append(yaw)

            # Head roll (side tilt)
            roll = math.degrees(math.atan2(left_eye[1] - right_eye[1],
                                           left_eye[0] - right_eye[0]))
            roll = np.clip(roll, -90, 90)
            roll_vals.append(roll)

            # Spine inclination (vertical vs line from shoulders to hips)
            mid_shoulder = np.mean([left_shoulder, right_shoulder], axis=0)
            mid_hip = np.mean([left_hip, right_hip], axis=0)
            spine_vec = np.array(mid_shoulder) - np.array(mid_hip)
            vertical_vec = np.array([0, -1])
            spine_angle = math.degrees(math.acos(
                np.dot(spine_vec, vertical_vec) /
                (np.linalg.norm(spine_vec) * np.linalg.norm(vertical_vec) + 1e-6)))
            spine_angle = spine_angle if spine_angle <= 90 else 180 - spine_angle
            spine_vals.append(spine_angle)

            # Shoulder symmetry (tilt)
            shoulder_diff = abs(left_shoulder[1] - right_shoulder[1]) * 100
            shoulder_vals.append(shoulder_diff)

    cap.release()

    # Mean values across frames
    pitch = np.mean(pitch_vals) if pitch_vals else 0
    yaw = np.mean(yaw_vals) if yaw_vals else 0
    roll = np.mean(roll_vals) if roll_vals else 0
    spine = np.mean(spine_vals) if spine_vals else 0
    shoulder = np.mean(shoulder_vals) if shoulder_vals else 0

    # Threshold checks
    report = []
    poor_count = 0

    def check_param(name, value, threshold, condition, interpretation):
        nonlocal poor_count
        status = "✅ Acceptable" if condition else "❌ Poor"
        if not condition:
            poor_count += 1
        report.append(f"{name:<15} {value:>7.2f}°   {threshold:<15}   {status} – {interpretation}")

    check_param("Head Pitch", pitch, ">= -5°", pitch >= -5, "Vertical tilt")
    check_param("Head Yaw", abs(yaw), "<= 15°", abs(yaw) <= 15, "Horizontal turn")
    check_param("Spine Lean", spine, "≤ 10° forward/back", spine <= 10, "Spine inclination")
    check_param("Shoulder Tilt", shoulder, "<= 5°", shoulder <= 5, "Shoulder symmetry")
    check_param("Head Roll", abs(roll), "<= 5°", abs(roll) <= 5, "Side tilt")

    verdict = "Acceptable Posture" if poor_count < 3 else "Poor Posture"

    # Final formatted report
    output = "\n📂 Body Posture Analyzer\n\n"
    output += f"✅ Final Verdict: {verdict}\n\n"
    output += "🧾 Interpretation Summary (based on thresholds):\n"
    output += "Parameter        Value      Threshold         Interpretation\n"
    output += "--------------------------------------------------------------------------\n"
    output += "\n".join(report)

    return output

# Example usage:
video_path = "D:/My Projects/cipttry/cipt_done/media/recordings/WIN_20250917_22_58_33_Pro.mp4"  # <-- Replace with your file path
print(get_body_posture_report(video_path))
