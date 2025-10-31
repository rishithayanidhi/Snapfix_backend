# SnapFix Complete Deployment Script (Windows)
# Deploys backend to Render and builds APK for distribution

Write-Host "SnapFix Complete Deployment Starting..." -ForegroundColor Green

# Step 1: Deploy Backend to Render
Write-Host ""
Write-Host "Deploying Backend to Render.com..." -ForegroundColor Cyan
git add .
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
git commit -m "SnapFix production deployment - $timestamp"
git push origin main
Write-Host "Backend deployment triggered! Check https://dashboard.render.com" -ForegroundColor Green

# Step 2: Build APK for distribution
Write-Host ""
Write-Host "Building APK for direct distribution..." -ForegroundColor Cyan
Set-Location -Path "snapfix_Frontend"
& ".\build_production.ps1"
Set-Location -Path ".."

Write-Host ""
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Monitor backend deployment at: https://dashboard.render.com" -ForegroundColor Gray
Write-Host "  2. Backend will be live at: https://snapfix-backend.onrender.com" -ForegroundColor Gray  
Write-Host "  3. APK ready for distribution: snapfix_Frontend/build/app/outputs/flutter-apk/app-release.apk" -ForegroundColor Gray
Write-Host "  4. Test the APK to Backend connection" -ForegroundColor Gray
Write-Host ""
Write-Host "Your SnapFix system is now live!" -ForegroundColor Magenta