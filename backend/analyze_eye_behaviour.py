import cv2
import numpy as np
import mediapipe as mp
import math
import os
from datetime import datetime

VIDEO_PATH = "D:/My Projects/cipttry/cipt_done/media/recordings/WIN_20250917_20_53_27_Pro.mp4"

# --- MediaPipe setup ---
mp_face = mp.solutions.face_mesh
face_mesh = mp_face.FaceMesh(
    static_image_mode=False,
    max_num_faces=1,
    refine_landmarks=True,
    min_detection_confidence=0.5,
    min_tracking_confidence=0.5
)

# Eye & iris landmarks for gaze
LEFT_EYE_IDX  = [33, 160, 158, 133, 153, 144]
RIGHT_EYE_IDX = [362, 385, 387, 263, 373, 380]
LEFT_IRIS_C  = 468
RIGHT_IRIS_C = 473

# Blink detection indices
LEFT_EYE = [362, 382, 381, 380, 374, 373, 390, 249, 263, 466, 388, 387, 386, 385, 384, 398]
RIGHT_EYE = [33, 7, 163, 144, 145, 153, 154, 155, 133, 173, 157, 158, 159, 160, 161, 246]

# Constants
CLOSED_EYES_FRAME = 3
center_thresh = 0.03  # for gaze
FPS_DEFAULT = 30.0
CALIBRATION_FRAMES = 30  # number of frames to auto-calibrate straight gaze

# --- Helper functions ---
def euclideanDistance(p1, p2):
    return math.sqrt((p1[0]-p2[0])**2 + (p1[1]-p2[1])**2)

def blinkRatio(lms, right_indices, left_indices, w, h):
    def xy(idx):
        return np.array([lms[idx].x*w, lms[idx].y*h])
    
    # Right eye
    rh_right = xy(right_indices[0])
    rh_left = xy(right_indices[8])
    rv_top = xy(right_indices[12])
    rv_bottom = xy(right_indices[4])
    reRatio = euclideanDistance(rh_right, rh_left) / (euclideanDistance(rv_top, rv_bottom)+1e-6)
    
    # Left eye
    lh_right = xy(left_indices[0])
    lh_left = xy(left_indices[8])
    lv_top = xy(left_indices[12])
    lv_bottom = xy(left_indices[4])
    leRatio = euclideanDistance(lh_right, lh_left) / (euclideanDistance(lv_top, lv_bottom)+1e-6)
    
    return (reRatio + leRatio)/2

def get_landmarks(lms, idx_list, w, h):
    return [np.array([lms[i].x*w, lms[i].y*h], dtype=np.float32) for i in idx_list]

def normalize_gaze(eye_pts, iris_xy):
    xs, ys = eye_pts[:,0], eye_pts[:,1]
    x_c, y_c = (xs.min()+xs.max())/2.0, (ys.min()+ys.max())/2.0
    w, h = xs.max()-xs.min()+1e-6, ys.max()-ys.min()+1e-6
    gx = (iris_xy[0]-x_c)/w
    gy = (iris_xy[1]-y_c)/h
    return gx, gy

# --- Video read ---
cap = cv2.VideoCapture(VIDEO_PATH)
fps = cap.get(cv2.CAP_PROP_FPS) or FPS_DEFAULT
frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
duration_sec = frame_count/fps
minutes = max(1e-6, duration_sec/60)

# --- Buffers ---
direction_counts = {"left":0,"right":0,"center":0,"up":0,"down":0}
gx_list, gy_list = [], []
focus_frames = 0
valid_frames = 0

# Blink detection variables
CEF_COUNTER = 0
TOTAL_BLINKS = 0

# Calibration
calib_gy_values = []
gy_offset = 0.0

# --- Main loop ---
frame_idx = 0
while True:
    ret, frame = cap.read()
    if not ret: break
    h, w = frame.shape[:2]
    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    res = face_mesh.process(rgb)
    frame_idx += 1
    
    if not res.multi_face_landmarks: continue
    lms = res.multi_face_landmarks[0].landmark
    valid_frames += 1
    
    # --- Gaze ---
    left_pts = np.stack(get_landmarks(lms, LEFT_EYE_IDX, w, h))
    right_pts = np.stack(get_landmarks(lms, RIGHT_EYE_IDX, w, h))
    left_iris = np.array([lms[LEFT_IRIS_C].x*w, lms[LEFT_IRIS_C].y*h])
    right_iris = np.array([lms[RIGHT_IRIS_C].x*w, lms[RIGHT_IRIS_C].y*h])
    gx_l, gy_l = normalize_gaze(left_pts, left_iris)
    gx_r, gy_r = normalize_gaze(right_pts, right_iris)
    gx, gy = (gx_l+gx_r)/2, (gy_l+gy_r)/2
    
    # --- Auto calibration in first few frames ---
    if frame_idx <= CALIBRATION_FRAMES:
        calib_gy_values.append(gy)
        if frame_idx == CALIBRATION_FRAMES:
            gy_offset = np.mean(calib_gy_values)  # set offset
            print(f"[CALIBRATION] gy_offset set to {gy_offset:.3f}")
    gy -= gy_offset
    
    gx_list.append(gx)
    gy_list.append(gy)
    
    # Focus detection (both eyes open & center gaze)
    ratio = blinkRatio(lms, RIGHT_EYE, LEFT_EYE,w,h) 
    eyes_open = ratio <= 4.1
    if eyes_open and abs(gx)<=center_thresh and abs(gy)<=center_thresh:
        focus_frames += 1
    
    # Blink detection
    if ratio > 4.1:
        CEF_COUNTER += 1
    else:
        if CEF_COUNTER >= CLOSED_EYES_FRAME:
            TOTAL_BLINKS += 1
        CEF_COUNTER = 0
    
    # Gaze direction
    if eyes_open:
        if gx < -center_thresh:
            direction = "left"
        elif gx > center_thresh:
            direction = "right"
        else:
            direction = "center"
    
        # Vertical adjustments
        if direction == "center":
            if gy < -center_thresh:
                direction = "up"
            elif gy > center_thresh:
                direction = "down"
    
        direction_counts[direction] += 1


cap.release()
face_mesh.close()

# --- Metrics ---
total_eye_frames = sum(direction_counts.values())
gaze_percent = {k:v/total_eye_frames*100 for k,v in direction_counts.items()}
blink_rate = TOTAL_BLINKS/minutes
focus_percent = focus_frames/valid_frames*100
stability = 100*(1 - np.std(gx_list + gy_list))
stability = max(0,min(100,stability))

# Blink intervals
if TOTAL_BLINKS>1:
    blink_intervals = [duration_sec/(TOTAL_BLINKS) for _ in range(TOTAL_BLINKS-1)]
    avg_blink_interval = np.mean(blink_intervals)
else:
    blink_intervals = []
    avg_blink_interval = 0

# Blink score
if 15 <= blink_rate <= 20:
    blink_score = 20
elif 20 < blink_rate <= 30:
    blink_score = 15
elif 10 <= blink_rate < 15:
    blink_score = 15
else:
    blink_score = max(0, 10 - abs(blink_rate-20)/2)

# Total score (weighted)
total_score = round(0.1*focus_percent + 0.2*blink_score + 0.7*stability,1)

# --- Report ---
report_lines = [
    f"\n📊 EYE ATTENTION & GAZE REPORT",
    "="*50,
    f"🎥 Video: {os.path.basename(VIDEO_PATH)}",
    f"⏱ Duration: {duration_sec:.1f}s",
    f"📊 Total frames: {frame_count}",
    "="*50,
    f"👁 Blink Analysis",
    f"Total blinks: {TOTAL_BLINKS}",
    f"Blink rate: {blink_rate:.2f}/min",
]
if avg_blink_interval>0:
    report_lines.append(f"Avg blink interval: {avg_blink_interval:.2f}s")
report_lines.append(f"Blink score: {blink_score}/20")
report_lines += ["="*50, f"👀 Gaze Distribution (%)"]
for k,v in gaze_percent.items():
    report_lines.append(f"{k.capitalize():<7}: {v:.1f}%")
report_lines += [
    "="*50,
    f"📌 Focus Percent: {focus_percent:.1f}%",
    f"📌 Gaze Stability: {stability:.1f}%",
    "="*50,
    f"🏆 Total Score: {total_score}/100",
    "="*50
]

report = "\n".join(report_lines)
print(report)
with open("eye_attention_gaze_report.txt","w",encoding="utf-8") as f:
    f.write(report)
print("\n✅ Report saved to eye_attention_gaze_report.txt")
