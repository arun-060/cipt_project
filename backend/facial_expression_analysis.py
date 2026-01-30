import cv2
import numpy as np
from tensorflow.keras.models import load_model
from keras.preprocessing import image
import os

# Labels and thresholds
EMOTION_LABELS = ['angry', 'disgust', 'fear', 'happy', 'sad', 'surprise', 'neutral']

# Load model and cascade
detector_model_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
model_path = "model.h5"

emotion_model = load_model(model_path)
face_detector = cv2.CascadeClassifier(detector_model_path)


def predict_emotion(face_img):
    """Predict emotions from a cropped face image."""
    try:
        resized_img = cv2.resize(face_img, (48, 48))
        gray_img = cv2.cvtColor(resized_img, cv2.COLOR_BGR2GRAY)
        img_pixels = image.img_to_array(gray_img)
        img_pixels = np.expand_dims(img_pixels, axis=0) / 255.0
        predictions = emotion_model.predict(img_pixels, verbose=0)[0]
        return dict(zip(EMOTION_LABELS, predictions))
    except Exception as e:
        print(f"Prediction error: {e}")
        return {}


def explain_parameter(name, value, threshold, condition, description):
    """Format each parameter line with ✅/❌ and explanation."""
    if condition == ">=":
        status = "✅ Acceptable" if value >= threshold else "❌ Poor"
        symbol = ">="
    elif condition == "<=":
        status = "✅ Acceptable" if value <= threshold else "❌ Poor"
        symbol = "<="
    else:
        status = "❌ Condition error"
        symbol = "?"
    return f"{name:<18} {value:<10.2f} {symbol} {threshold:<10} {status} – {description}"


def analyze_facial_expressions(video_path):
    """Main function to analyze facial expressions from a video."""
    if not os.path.exists(video_path):
        print(f"❌ Error: File not found at {video_path}")
        return

    cap = cv2.VideoCapture(video_path)
    frame_count = 0
    neutral_count = 0
    au12_list, au4_list, au7_list = [], [], []
    emotions_list = []

    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frame_count += 1

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_detector.detectMultiScale(gray, 1.3, 5)

        if len(faces) == 0:
            continue

        x, y, w, h = faces[0]
        face_img = frame[y:y + h, x:x + w]
        emotion_pred = predict_emotion(face_img)
        if not emotion_pred:
            continue

        au12 = emotion_pred.get("happy", 0.0)  # Smile intensity
        au4 = emotion_pred.get("angry", 0.0) + emotion_pred.get("disgust", 0.0)  # Brow tension
        au7 = emotion_pred.get("fear", 0.0) + emotion_pred.get("sad", 0.0)  # Eyelid tension
        emotion_label = max(emotion_pred, key=emotion_pred.get)

        au12_list.append(au12)
        au4_list.append(au4)
        au7_list.append(au7)
        emotions_list.append(emotion_label)

        if emotion_label == "neutral":
            neutral_count += 1

    cap.release()

    if frame_count == 0:
        print("❌ No valid frames found in the video.")
        return

    # Compute averages
    au12_avg = np.mean(au12_list)
    au4_ratio = np.sum(np.array(au4_list) > 0.3) / len(au4_list)
    au7_ratio = np.sum(np.array(au7_list) > 0.4) / len(au7_list)
    neutral_rate = neutral_count / frame_count
    face_voice_corr = 0.25  # placeholder for now

    # Apply corrected rules
    poor_flags = sum([
        au12_avg < 0.3,             # AU12 must be >= 0.3
        au4_ratio > 0.3,            # AU4 must be <= 0.3
        au7_ratio > 0.4,            # AU7 must be <= 0.4
        neutral_rate > 0.8,         # Neutral must be <= 0.8
        face_voice_corr < 0.3       # Corr must be >= 0.3
    ])
    verdict = "Poor Expression" if poor_flags >= 3 else "Acceptable"

    # Print evaluation
    print("\n📊 Facial Expression Evaluation Report (Corrected):")
    print(f"AU12 (Smile Intensity): {au12_avg:.4f} (threshold >= 0.3)")
    print(f"AU4_PoorRatio (Anger/Disgust): {au4_ratio:.4f} (threshold <= 0.3)")
    print(f"AU7_PoorRatio (Fear/Sad): {au7_ratio:.4f} (threshold <= 0.4)")
    print(f"NeutralRate: {neutral_rate:.4f} (threshold <= 0.8)")
    print(f"FaceVoiceCorr: {face_voice_corr:.2f} (threshold >= 0.3)")
    print(f"\n✅ Final Verdict: {verdict}\n")

    # Detailed table
    print("🧾 Interpretation Summary (based on thresholds):")
    print(f"{'Parameter':<18} {'Value':<10} {'Threshold':<12} {'Interpretation'}")
    print("-" * 80)
    print(explain_parameter("AU12 (Smile)", au12_avg, 0.3, ">=", "Smile intensity (AU12)"))
    print(explain_parameter("AU4 Ratio", au4_ratio, 0.3, "<=", "Brow tension (Angry/Disgust)"))
    print(explain_parameter("AU7 Ratio", au7_ratio, 0.4, "<=", "Eyelid tension (Fear/Sad)"))
    print(explain_parameter("Neutral Rate", neutral_rate, 0.8, "<=", "Neutral emotion dominance"))
    print(explain_parameter("Voice Match", face_voice_corr, 0.3, ">=", "Expression matches speech"))

    return verdict


if __name__ == "__main__":
    print("📂 Facial Expression Analyzer")
    analyze_facial_expressions("D:/My Projects/cipttry/cipt_done/media/recordings/WIN_20250917_22_58_33_Pro.mp4")
