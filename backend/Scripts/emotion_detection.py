import cv2
import sys
import numpy as np

# Load cascades
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
mouth_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_smile.xml')

print("Starting Emotion Detection...")
sys.stdout.flush()

cap = cv2.VideoCapture(0)
if not cap.isOpened():
    print("Error: Cannot access webcam.")
    sys.stdout.flush()
    sys.exit()

def detect_emotion(eyes, mouth):
    """
    Heuristic emotion detection:
    - Sad: eyes down + mouth closed
    - Angry: eyebrows down (approx by eyes proximity) + mouth tight
    - Fear: eyes wide + mouth open
    - Surprised: eyes wide + mouth wide open
    """
    if len(eyes) >= 2 and len(mouth) > 0:
        # Eyes open, mouth open
        return "happy"
    elif len(eyes) >= 2 and len(mouth) == 0:
        # Eyes open, mouth closed
        return "Fear"
    elif len(eyes) < 2 and len(mouth) == 0:
        return "Sad"
    elif len(eyes) < 2 and len(mouth) > 0:
        return "Angry"
    else:
        return "Neutral"

while True:
    ret, frame = cap.read()
    if not ret:
        print("Error reading frame.")
        break

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, 1.3, 5)

    for (x, y, w, h) in faces:
        cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)

        roi_gray = gray[y:y+h, x:x+w]

        eyes = eye_cascade.detectMultiScale(roi_gray, 1.1, 5)
        mouth = mouth_cascade.detectMultiScale(roi_gray, 1.7, 20)

        emotion = detect_emotion(eyes, mouth)

        cv2.putText(frame, f"Emotion: {emotion}", (x, y-10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255,0,0), 2)
        print(emotion)
        sys.stdout.flush()

    cv2.imshow('Emotion Detection', frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()
print("Emotion Detection ended.")
sys.stdout.flush()
