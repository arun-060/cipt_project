# body_posture.py

import cv2
import mediapipe as mp
import numpy as np

# ------------------ Setup Mediapipe ------------------
mp_pose = mp.solutions.pose
mp_drawing = mp.solutions.drawing_utils

# ------------------ Utility Function ------------------
def calculate_angle(a, b, c):
    a = np.array(a)  # First
    b = np.array(b)  # Mid
    c = np.array(c)  # End

    radians = np.arctan2(c[1]-b[1], c[0]-b[0]) - np.arctan2(a[1]-b[1], a[0]-b[0])
    angle = np.abs(radians*180.0/np.pi)

    if angle > 180.0:
        angle = 360 - angle

    return angle

# ------------------ Main Function ------------------
def main():
    cap = cv2.VideoCapture(0)  # Activate webcam

    counter = 0  # Illegal move counter
    movement = None

    with mp_pose.Pose(min_detection_confidence=0.5, min_tracking_confidence=0.5) as pose:
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            # Recolor image to RGB
            image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            image.flags.writeable = False

            # Make detection
            results = pose.process(image)

            # Recolor back to BGR
            image.flags.writeable = True
            image = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)

            try:
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

                # Visualize angle
                cv2.putText(image, str(int(angle)),
                            tuple(np.multiply(lt_shoulder, [640, 480]).astype(int)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 2, cv2.LINE_AA)

                # Status box
                cv2.rectangle(image, (0, 0), (1000, 55), (0, 0, 0), -1)

                # Illegal move counter logic
                if angle > 96 and angle < 130:
                    movement = "Straight :D"
                if angle > 110:
                    movement = "Over Extended :("
                    cv2.putText(image, "Seems that you've over extended your arms", (260, 12),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
                    counter += 1
                if angle < 96:
                    movement = "Cross :("
                    cv2.putText(image, "Seems that you've crossed your arms", (260, 12),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
                    counter += 1

            except:
                pass

            # Rep data
            cv2.putText(image, 'ILLEGAL_MOVES', (15, 12),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
            cv2.putText(image, str(counter), (10, 50),
                        cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 1, cv2.LINE_AA)

            # Movement data
            cv2.putText(image, 'MOVEMENT-->', (145, 12),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
            if movement:
                cv2.putText(image, movement, (145, 50),
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 1, cv2.LINE_AA)

            # Draw landmarks
            mp_drawing.draw_landmarks(image, results.pose_landmarks, mp_pose.POSE_CONNECTIONS,
                                      mp_drawing.DrawingSpec(color=(0, 0, 255), thickness=2, circle_radius=2),
                                      mp_drawing.DrawingSpec(color=(255, 0, 0), thickness=2, circle_radius=2))

            cv2.imshow('Body Posture Detection', image)

            if cv2.waitKey(10) & 0xFF == ord('q'):
                break

    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    main()
