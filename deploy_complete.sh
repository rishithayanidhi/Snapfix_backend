#!/bin/bash
# SnapFix Complete Deployment Script
# Deploys backend to Render and builds APK for distribution

echo "🚀 SnapFix Complete Deployment Starting..."

# Step 1: Deploy Backend to Render
echo ""
echo "📡 Deploying Backend to Render.com..."
git add .
git commit -m "SnapFix production deployment - $(date)"
git push origin main
echo "✅ Backend deployment triggered! Check https://dashboard.render.com"

# Step 2: Build APK for distribution
echo ""
echo "📱 Building APK for direct distribution..."
cd snapfix_Frontend
powershell -ExecutionPolicy Bypass -File "./build_production.ps1"

echo ""
echo "🎉 Deployment Complete!"
echo ""
echo "📋 Next Steps:"
echo "  1. Monitor backend deployment at: https://dashboard.render.com"
echo "  2. Backend will be live at: https://snapfix-backend.onrender.com"
echo "  3. APK ready for distribution: snapfix_Frontend/build/app/outputs/flutter-apk/app-release.apk"
echo "  4. Test the APK → Backend connection"
echo ""
echo "🚀 Your SnapFix system is now live!"