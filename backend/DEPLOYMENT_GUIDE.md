# Backend Deployment Guide (Render)

Your backend is now **100% deployment ready**.

## ✅ Pre-Deployment Checklist

### Files Created/Updated:
- ✅ `server.js` - Production-ready with dynamic URLs & secure sessions
- ✅ `package.json` - Clean dependencies with engine specification
- ✅ `.env.example` - Environment variable template
- ✅ `.gitignore` - Proper exclusions for production
- ✅ `Dockerfile` (in project root) - Docker configuration for Render

### Code Fixes Applied:
- ✅ Removed hardcoded `localhost:5000` URLs
- ✅ Added dynamic base URL generation
- ✅ Production-ready session configuration
- ✅ CORS configured for production frontend
- ✅ Server binds to `0.0.0.0` for container deployment

---

## 🚀 Deployment Steps (Render.com)

### Step 1: Push to GitHub

```bash
cd d:\Website-react
git add .
git commit -m "Backend deployment ready"
git push origin main
```

### Step 2: Deploy on Render

1. Go to [render.com](https://render.com) and sign in
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository
4. Configure:
   - **Name**: `cipt-backend`
   - **Runtime**: **Docker** (Important!)
   - **Region**: Choose closest to your users
   - **Instance Type**: Free (for testing) or Starter ($7/month)

### Step 3: Add Environment Variables

In Render dashboard, go to **Environment** and add:

| Variable | Value | Required |
|----------|-------|----------|
| `NODE_ENV` | `production` | ✅ |
| `SESSION_SECRET` | `your-32-char-secret-key` | ✅ |
| `FRONTEND_URL` | `https://your-app.vercel.app` | ✅ |
| `AWS_ACCESS_KEY` | Your AWS key | ✅ |
| `AWS_SECRET_KEY` | Your AWS secret | ✅ |
| `AWS_REGION` | `ap-south-1` | ✅ |
| `AWS_BUCKET_NAME` | Your S3 bucket | ✅ |

### Step 4: Deploy

Click **"Create Web Service"**. Render will:
1. Build Docker image (~5-10 minutes first time)
2. Install Python dependencies
3. Install Node.js dependencies
4. Start the server

### Step 5: Get Your Backend URL

Once deployed, Render will give you a URL like:
```
https://cipt-backend.onrender.com
```

**Save this URL!** You'll need it for frontend deployment.

---

## ⚠️ Important Notes

### Database Persistence
- **Free Tier**: SQLite database resets on each deploy
- **Solution**: The app uses AWS S3 for video storage (persistent)
- For user data persistence, consider:
  - Render PostgreSQL add-on
  - External database (Supabase, PlanetScale)

### Cold Starts
- Free tier sleeps after 15 min inactivity
- First request takes ~50 seconds to wake up
- Paid tier ($7/month) stays always-on

### Video Processing
- ML analysis requires significant RAM
- Free tier: 512MB RAM (may hit limits)
- Starter tier: 1GB RAM (recommended)

### AWS S3 Setup
Your videos are uploaded to S3. Ensure your bucket has:
1. CORS configuration allowing your domains
2. Proper IAM permissions

---

## 🔧 Local Testing

Before deploying, test locally:

```bash
cd d:\Website-react\backend
npm install
node server.js
```

Server should start on `http://localhost:5000`

---

## 📝 Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `5000` |
| `NODE_ENV` | Environment mode | `development` |
| `SESSION_SECRET` | Session encryption key | - |
| `FRONTEND_URL` | Frontend origin for CORS | `http://localhost:3000` |
| `BACKEND_URL` | Backend URL for report links | Auto-detected |
| `PYTHON_PATH` | Python executable path | `/usr/local/bin/python` |
| `AWS_ACCESS_KEY` | AWS S3 access key | - |
| `AWS_SECRET_KEY` | AWS S3 secret key | - |
| `AWS_REGION` | AWS region | - |
| `AWS_BUCKET_NAME` | S3 bucket name | - |

---

## 🐛 Troubleshooting

### Issue: "CORS Error"
**Solution**: Add your Vercel URL to `FRONTEND_URL` env variable

### Issue: "Python script failed"
**Solution**: 
- Check Render logs for Python errors
- Ensure all Python dependencies are in `requirements.txt`
- Verify `PYTHON_PATH` is correct (`/usr/local/bin/python`)

### Issue: "Session not persisting"
**Solution**: 
- Ensure `SESSION_SECRET` is set
- Check `sameSite` cookie settings for cross-origin

### Issue: "Docker build failed"
**Solution**:
- Check Dockerfile syntax
- Ensure `requirements.txt` is valid
- Review Render build logs

---

**Your backend is ready to deploy! 🎉**
