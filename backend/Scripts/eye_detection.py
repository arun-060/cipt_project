import cv2 as cv
import mediapipe as mp
import numpy as np
import math
import time

# Colors for display
class Colors:
    BLACK = (0, 0, 0)
    WHITE = (255, 255, 255)
    GREEN = (0, 255, 0)
    YELLOW = (0, 255, 255)
    PINK = (255, 0, 255)

def eye_detection():
    
    frame_counter = 0
    CEF_COUNTER = 0
    TOTAL_BLINKS = 0

    CLOSED_EYES_FRAME = 3
    FONTS = cv.FONT_HERSHEY_COMPLEX

    LEFT_EYE = [362, 382, 381, 380, 374, 373, 390, 249, 263, 466,
                388, 387, 386, 385, 384, 398]
    RIGHT_EYE = [33, 7, 163, 144, 145, 153, 154, 155, 133, 173,
                 157, 158, 159, 160, 161, 246]

    map_face_mesh = mp.solutions.face_mesh
    camera = cv.VideoCapture(0)

    def landmarksDetection(img, results):
        img_height, img_width = img.shape[:2]
        mesh_coord = [(int(point.x * img_width), int(point.y * img_height))
                      for point in results.multi_face_landmarks[0].landmark]
        return mesh_coord

    def euclideanDistance(point, point1):
        x, y = point
        x1, y1 = point1
        return math.sqrt((x1 - x) ** 2 + (y1 - y) ** 2)

    def blinkRatio(landmarks, right_indices, left_indices):
        rh_right = landmarks[right_indices[0]]
        rh_left = landmarks[right_indices[8]]
        rv_top = landmarks[right_indices[12]]
        rv_bottom = landmarks[right_indices[4]]

        lh_right = landmarks[left_indices[0]]
        lh_left = landmarks[left_indices[8]]
        lv_top = landmarks[left_indices[12]]
        lv_bottom = landmarks[left_indices[4]]

        rhDistance = euclideanDistance(rh_right, rh_left)
        rvDistance = euclideanDistance(rv_top, rv_bottom)
        lvDistance = euclideanDistance(lv_top, lv_bottom)
        lhDistance = euclideanDistance(lh_right, lh_left)

        reRatio = rhDistance / rvDistance
        leRatio = lhDistance / lvDistance
        ratio = (reRatio + leRatio) / 2
        return ratio

    def eyesExtractor(img, right_eye_coords, left_eye_coords):
        gray = cv.cvtColor(img, cv.COLOR_BGR2GRAY)
        dim = gray.shape
        mask = np.zeros(dim, dtype=np.uint8)
        cv.fillPoly(mask, [np.array(right_eye_coords, dtype=np.int32)], 255)
        cv.fillPoly(mask, [np.array(left_eye_coords, dtype=np.int32)], 255)
        eyes = cv.bitwise_and(gray, gray, mask=mask)
        eyes[mask == 0] = 155

        r_max_x = max(right_eye_coords, key=lambda item: item[0])[0]
        r_min_x = min(right_eye_coords, key=lambda item: item[0])[0]
        r_max_y = max(right_eye_coords, key=lambda item: item[1])[1]
        r_min_y = min(right_eye_coords, key=lambda item: item[1])[1]

        l_max_x = max(left_eye_coords, key=lambda item: item[0])[0]
        l_min_x = min(left_eye_coords, key=lambda item: item[0])[0]
        l_max_y = max(left_eye_coords, key=lambda item: item[1])[1]
        l_min_y = min(left_eye_coords, key=lambda item: item[1])[1]

        cropped_right = eyes[r_min_y:r_max_y, r_min_x:r_max_x]
        cropped_left = eyes[l_min_y:l_max_y, l_min_x:l_max_x]

        return cropped_right, cropped_left

    def positionEstimator(cropped_eye):
        h, w = cropped_eye.shape
        gaussain_blur = cv.GaussianBlur(cropped_eye, (9, 9), 0)
        _, threshed_eye = cv.threshold(gaussain_blur, 130, 255, cv.THRESH_BINARY)
        piece = int(w / 3)
        right_piece = threshed_eye[0:h, 0:piece]
        center_piece = threshed_eye[0:h, piece: piece + piece]
        left_piece = threshed_eye[0:h, piece + piece:w]
        return pixelCounter(right_piece, center_piece, left_piece)

    def pixelCounter(first_piece, second_piece, third_piece):
        right_part = np.sum(first_piece == 0)
        center_part = np.sum(second_piece == 0)
        left_part = np.sum(third_piece == 0)
        eye_parts = [right_part, center_part, left_part]
        max_index = eye_parts.index(max(eye_parts))
        if max_index == 0:
            return "RIGHT", Colors.GREEN
        elif max_index == 1:
            return "CENTER", Colors.WHITE
        elif max_index == 2:
            return "LEFT", Colors.YELLOW
        else:
            return "CLOSED", Colors.PINK

    with map_face_mesh.FaceMesh(min_detection_confidence=0.5,
                                min_tracking_confidence=0.5) as face_mesh:
        start_time = time.time()

        while True:
            frame_counter += 1
            ret, frame = camera.read()
            if not ret:
                break

            frame = cv.resize(frame, None, fx=1.5, fy=1.5)
            rgb_frame = cv.cvtColor(frame, cv.COLOR_BGR2RGB)
            results = face_mesh.process(rgb_frame)

            if results.multi_face_landmarks:
                mesh_coords = landmarksDetection(frame, results)
                ratio = blinkRatio(mesh_coords, RIGHT_EYE, LEFT_EYE)

                # Blink detection
                if ratio > 4.1:
                    CEF_COUNTER += 1
                else:
                    if CEF_COUNTER > CLOSED_EYES_FRAME:
                        TOTAL_BLINKS += 1
                        CEF_COUNTER = 0

                right_coords = [mesh_coords[p] for p in RIGHT_EYE]
                left_coords = [mesh_coords[p] for p in LEFT_EYE]
                crop_right, crop_left = eyesExtractor(frame, right_coords, left_coords)

                eye_position, color = positionEstimator(crop_right)
                eye_position_left, _ = positionEstimator(crop_left)

                # Display info
                cv.putText(frame, f'Blink Count: {TOTAL_BLINKS}', (30, 50), FONTS, 0.7, Colors.GREEN, 2)
                cv.putText(frame, f'Right Eye: {eye_position}', (30, 100), FONTS, 0.7, color, 2)
                cv.putText(frame, f'Left Eye: {eye_position_left}', (30, 150), FONTS, 0.7, color, 2)

            end_time = time.time() - start_time
            fps = frame_counter / end_time
            cv.putText(frame, f'FPS: {round(fps, 1)}', (30, 200), FONTS, 0.7, Colors.PINK, 2)

            cv.imshow("Eye Detection", frame)
            if cv.waitKey(1) & 0xFF == ord('q'):
                break

        camera.release()
        cv.destroyAllWindows()

if __name__ == "__main__":
    eye_detection()
