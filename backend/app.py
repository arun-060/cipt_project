from flask import Flask, request, jsonify
from flask_cors import CORS
import cv2
import mediapipe as mp
import numpy as np
import math
import base64
import io
from PIL import Image
import threading
import queue

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

# ------------------ Body Posture Logic ------------------
mp_pose = mp.solutions.pose
mp_drawing = mp.solutions.drawing_utils

def calculate_angle(a, b, c):
    a = np.array(a)
    b = np.array(b)
    c = np.array(c)
    
    radians = np.arctan2(c[1]-b[1], c[0]-b[0]) - np.arctan2(a[1]-b[1], a[0]-b[0])
    angle = np.abs(radians*180.0/np.pi)
    
    if angle > 180.0:
        angle = 360 - angle
    return angle

def analyze_body_posture(image_data):
    try:
        # Decode base64 image
        image_bytes = base64.b64decode(image_data.split(',')[1])
        image = Image.open(io.BytesIO(image_bytes))
        frame = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        
        with mp_pose.Pose(min_detection_confidence=0.5, min_tracking_confidence=0.5) as pose:
            # Convert to RGB
            image_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            results = pose.process(image_rgb)
            
            if results.pose_landmarks:
                landmarks = results.pose_landmarks.landmark
                
                # Get coordinates
                elbow = [landmarks[mp_pose.PoseLandmark.LEFT_ELBOW.value].x,
                        landmarks[mp_pose.PoseLandmark.LEFT_ELBOW.value].y]
                lt_shoulder = [landmarks[mp_pose.PoseLandmark.LEFT_SHOULDER.value].x,
                              landmarks[mp_pose.PoseLandmark.LEFT_SHOULDER.value].y]
                rt_shoulder = [landmarks[mp_pose.PoseLandmark.RIGHT_SHOULDER.value].x,
                              landmarks[mp_pose.PoseLandmark.RIGHT_SHOULDER.value].y]
                
                # Calculate angle
                angle = calculate_angle(elbow, lt_shoulder, rt_shoulder)
                
                # Determine posture status
                movement = "Optimal"
                if angle > 110:
                    movement = "Over Extended"
                elif angle < 90:
                    movement = "Crossed Arms"
                
                return {
                    "shoulder_angle": round(angle, 1),
                    "posture_status": movement,
                    "posture_score": min(100, max(0, 100 - abs(angle - 100))),
                    "confidence": 85,
                    "success": True
                }
    except Exception as e:
        print(f"Body posture error: {e}")
    
    return {"success": False, "error": "No pose detected"}

# ------------------ Eye Contact Logic ------------------
LEFT_EYE = [362, 382, 381, 380, 374, 373, 390, 249, 263, 466, 388, 387, 386, 385, 384, 398]
RIGHT_EYE = [33, 7, 163, 144, 145, 153, 154, 155, 133, 173, 157, 158, 159, 160, 161, 246]

def euclidean_distance(point, point1):
    x, y = point
    x1, y1 = point1
    return math.sqrt((x1 - x)**2 + (y1 - y)**2)

def analyze_eye_contact(image_data):
    try:
        # Decode base64 image
        image_bytes = base64.b64decode(image_data.split(',')[1])
        image = Image.open(io.BytesIO(image_bytes))
        frame = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        
        map_face_mesh = mp.solutions.face_mesh
        with map_face_mesh.FaceMesh(min_detection_confidence=0.5, min_tracking_confidence=0.5) as face_mesh:
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            results = face_mesh.process(frame_rgb)
            
            if results.multi_face_landmarks:
                img_height, img_width = frame.shape[:2]
                mesh_coords = [(int(point.x * img_width), int(point.y * img_height))
                             for point in results.multi_face_landmarks[0].landmark]
                
                # Calculate blink ratio
                rh_right = mesh_coords[RIGHT_EYE[0]]
                rh_left = mesh_coords[RIGHT_EYE[8]]
                rv_top = mesh_coords[RIGHT_EYE[12]]
                rv_bottom = mesh_coords[RIGHT_EYE[4]]
                
                lh_right = mesh_coords[LEFT_EYE[0]]
                lh_left = mesh_coords[LEFT_EYE[8]]
                lv_top = mesh_coords[LEFT_EYE[12]]
                lv_bottom = mesh_coords[LEFT_EYE[4]]
                
                rh_distance = euclidean_distance(rh_right, rh_left)
                rv_distance = euclidean_distance(rv_top, rv_bottom)
                lv_distance = euclidean_distance(lv_top, lv_bottom)
                lh_distance = euclidean_distance(lh_right, lh_left)
                
                re_ratio = rh_distance / rv_distance if rv_distance > 0 else 0
                le_ratio = lh_distance / lv_distance if lv_distance > 0 else 0
                ratio = (re_ratio + le_ratio) / 2 if (re_ratio + le_ratio) > 0 else 0
                
                # Simple gaze detection (simplified)
                eye_center_x = (mesh_coords[LEFT_EYE[0]][0] + mesh_coords[RIGHT_EYE[8]][0]) / 2
                face_center_x = img_width / 2
                
                gaze = "Center"
                if eye_center_x < face_center_x - 50:
                    gaze = "Left"
                elif eye_center_x > face_center_x + 50:
                    gaze = "Right"
                
                # Estimate eye contact percentage
                eye_contact = 75  # Base value
                if gaze == "Center":
                    eye_contact = 85
                elif ratio > 4:  # Blinking
                    eye_contact = 60
                
                return {
                    "gaze_direction": gaze,
                    "eye_contact_percentage": eye_contact,
                    "blink_ratio": round(ratio, 2),
                    "engagement_score": min(100, eye_contact + 10),
                    "success": True
                }
    except Exception as e:
        print(f"Eye contact error: {e}")
    
    return {"success": False, "error": "No face detected"}

# ------------------ Emotion Detection Logic ------------------
def analyze_emotion(image_data):
    try:
        # Decode base64 image
        image_bytes = base64.b64decode(image_data.split(',')[1])
        image = Image.open(io.BytesIO(image_bytes))
        frame = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        
        # Load cascades
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
        mouth_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_smile.xml')
        
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, 1.3, 5)
        
        if len(faces) > 0:
            (x, y, w, h) = faces[0]
            roi_gray = gray[y:y+h, x:x+w]
            
            eyes = eye_cascade.detectMultiScale(roi_gray, 1.1, 5)
            mouth = mouth_cascade.detectMultiScale(roi_gray, 1.7, 20)
            
            # Heuristic emotion detection
            emotion = "Neutral"
            if len(eyes) >= 2 and len(mouth) > 0:
                emotion = "Happy"
            elif len(eyes) >= 2 and len(mouth) == 0:
                emotion = "Fear"
            elif len(eyes) < 2 and len(mouth) == 0:
                emotion = "Sad"
            elif len(eyes) < 2 and len(mouth) > 0:
                emotion = "Angry"
            
            # Calculate confidence based on detections
            confidence = min(95, 70 + (len(eyes) * 10) + (len(mouth) * 5))
            
            return {
                "dominant_emotion": emotion,
                "confidence": round(confidence),
                "eyes_detected": len(eyes),
                "mouth_detected": len(mouth) > 0,
                "success": True
            }
    except Exception as e:
        print(f"Emotion detection error: {e}")
    
    return {"success": False, "error": "No face detected"}

# ------------------ API Routes ------------------
@app.route('/api/analyze/posture', methods=['POST'])
def analyze_posture():
    data = request.json
    if not data or 'image' not in data:
        return jsonify({"error": "No image data provided"}), 400
    
    result = analyze_body_posture(data['image'])
    return jsonify(result)

@app.route('/api/analyze/eye', methods=['POST'])
def analyze_eye():
    data = request.json
    if not data or 'image' not in data:
        return jsonify({"error": "No image data provided"}), 400
    
    result = analyze_eye_contact(data['image'])
    return jsonify(result)

@app.route('/api/analyze/emotion', methods=['POST'])
def analyze_emotion_route():
    data = request.json
    if not data or 'image' not in data:
        return jsonify({"error": "No image data provided"}), 400
    
    result = analyze_emotion(data['image'])
    return jsonify(result)

@app.route('/api/analyze/voice', methods=['POST'])
def analyze_voice():
    # For voice analysis, you'd need audio data
    # This is a simplified version
    data = request.json
    if not data or 'audio' not in data:
        return jsonify({"error": "No audio data provided"}), 400
    
    # Simulate voice analysis
    return jsonify({
        "pitch": 180 + np.random.randint(-20, 20),
        "clarity": 85 + np.random.randint(-10, 10),
        "speech_rate": 150 + np.random.randint(-30, 30),
        "volume": 75 + np.random.randint(-15, 15),
        "success": True
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "message": "Python backend is running"})

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')