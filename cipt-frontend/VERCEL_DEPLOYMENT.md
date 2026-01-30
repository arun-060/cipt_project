# Vercel Deployment Guide - Frontend

## ✅ Pre-Deployment Checklist

Your frontend is now **Vercel-ready**! Here's what has been configured:

### Files Created:
- ✅ `vercel.json` - Vercel configuration for routing and caching
- ✅ `.env.production` - Production environment template
- ✅ `.env.local.example` - Local development example
- ✅ `src/config.js` - Dynamic API URL configuration

### Code Updates:
- ✅ All API calls now use `API_BASE_URL` from config
- ✅ Backend CORS updated to accept production URLs
- ✅ Routing configured for React Router

---

## 🚀 Deployment Steps

### Step 1: Push to GitHub
```bash
cd d:\Website-react\cipt-frontend
git add .
git commit -m "Prepare frontend for Vercel deployment"
git push origin main
```

### Step 2: Deploy on Vercel

1. Go to [vercel.com](https://vercel.com) and sign in with GitHub
2. Click **"Add New Project"**
3. Import your repository
4. **Configure Project:**
   - **Framework Preset**: Create React App (auto-detected)
   - **Root Directory**: `cipt-frontend`
   - **Build Command**: `npm run build` (auto-filled)
   - **Output Directory**: `build` (auto-filled)

5. **Add Environment Variable:**
   - Click "Environment Variables"
   - Name: `REACT_APP_API_URL`
   - Value: Your backend URL (e.g., `https://cipt-backend.onrender.com`)
   - **Important**: No trailing slash!

6. Click **"Deploy"**

### Step 3: Configure Backend CORS

After deployment, you'll get a Vercel URL like `https://your-app.vercel.app`

Add this to your **Backend** (Render) environment variables:
- Name: `FRONTEND_URL`
- Value: `https://your-app.vercel.app`

Then redeploy your backend on Render.

---

## 🔧 Local Development

To run locally after these changes:

1. Create `.env.local` file:
```bash
cp .env.local.example .env.local
```

2. The file should contain:
```
REACT_APP_API_URL=http://localhost:5000
```

3. Start the dev server:
```bash
npm start
```

---

## 🐛 Troubleshooting

### Issue: "CORS Error" in production
**Solution**: Make sure you added `FRONTEND_URL` to your backend environment variables on Render.

### Issue: API calls fail with 404
**Solution**: Check that `REACT_APP_API_URL` in Vercel doesn't have a trailing slash.

### Issue: Blank page after deployment
**Solution**: 
1. Check Vercel build logs for errors
2. Ensure `vercel.json` rewrites are configured (already done)
3. Check browser console for errors

### Issue: Environment variable not working
**Solution**: 
1. Vercel requires `REACT_APP_` prefix for Create React App
2. After adding/changing env vars, redeploy the project
3. Clear browser cache

---

## 📝 Notes

- **Build Time**: ~2-3 minutes on Vercel
- **Auto-Deploy**: Vercel will auto-deploy on every push to main branch
- **Preview Deployments**: Every pull request gets a preview URL
- **Free Tier**: Plenty for this project (100GB bandwidth/month)

---

## ✨ What's Next?

After successful deployment:
1. Test all features (login, video upload, report generation)
2. Set up custom domain (optional) in Vercel dashboard
3. Enable analytics in Vercel settings
4. Monitor performance with Vercel Analytics

---

**Your frontend is ready to deploy! 🎉**
