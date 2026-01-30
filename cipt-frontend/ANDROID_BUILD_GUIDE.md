# Building Android APK for Interview Prep App

## Prerequisites

Before you can build the APK, you need to install:

1. **Java Development Kit (JDK) 17**
   - Download from: https://adoptium.net/
   - Install and set JAVA_HOME environment variable

2. **Android Studio**
   - Download from: https://developer.android.com/studio
   - During installation, make sure to install:
     - Android SDK
     - Android SDK Platform
     - Android Virtual Device (optional, for testing)

3. **Gradle** (usually comes with Android Studio)

## Building the APK

### Method 1: Using Android Studio (Recommended)

1. **Open the Android project:**
   ```bash
   npm run android:build
   ```
   This will:
   - Build your React app
   - Sync files to Android
   - Open Android Studio

2. **In Android Studio:**
   - Wait for Gradle sync to complete (bottom right corner)
   - Click `Build` → `Build Bundle(s) / APK(s)` → `Build APK(s)`
   - Wait for build to complete (usually 2-5 minutes)
   - Click "locate" in the notification to find your APK

3. **APK Location:**
   ```
   d:\Website-react\cipt-frontend\android\app\build\outputs\apk\debug\app-debug.apk
   ```

### Method 2: Using Command Line (Advanced)

1. **Navigate to android folder:**
   ```bash
   cd android
   ```

2. **Build debug APK:**
   ```bash
   gradlew assembleDebug
   ```

3. **Build release APK (for distribution):**
   ```bash
   gradlew assembleRelease
   ```

## Installing the APK on Your Phone

### Option 1: Direct Transfer
1. Copy `app-debug.apk` to your phone
2. Enable "Install from Unknown Sources" in Settings
3. Tap the APK file to install

### Option 2: ADB (Android Debug Bridge)
```bash
adb install android\app\build\outputs\apk\debug\app-debug.apk
```

## Important Notes

⚠️ **Backend Requirement:**
- The Android app will try to connect to `http://localhost:5000`
- This won't work on a real phone!
- You need to either:
  1. Deploy your backend to a server (e.g., Heroku, AWS)
  2. Update the API URLs in your React code to point to your server's IP
  3. Use ngrok to expose your local backend

### Updating API URLs for Mobile

In your React code, change:
```javascript
// FROM:
fetch('http://localhost:5000/api/...')

// TO:
fetch('http://YOUR_SERVER_IP:5000/api/...')
// or
fetch('https://your-backend.herokuapp.com/api/...')
```

## Quick Commands

```bash
# Build and open Android Studio
npm run android:build

# Just sync changes (after modifying React code)
npm run android:sync

# Then rebuild in Android Studio
```

## Troubleshooting

### "JAVA_HOME not set"
- Set environment variable: `JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-17.x.x`
- Add to PATH: `%JAVA_HOME%\bin`

### "SDK location not found"
- Create `android/local.properties`:
  ```
  sdk.dir=C:\\Users\\YourUsername\\AppData\\Local\\Android\\Sdk
  ```

### App crashes on phone
- Check if backend URL is accessible from phone
- Enable USB debugging and check logs: `adb logcat`

## Next Steps

1. Install Android Studio
2. Run `npm run android:build`
3. Build APK in Android Studio
4. Deploy backend to a server
5. Update API URLs in code
6. Rebuild and test!
