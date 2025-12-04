# Deploy Guide (Hindi)

Ye guide Cloudflare Pages par project deploy karne ke liye hai.

## 1) GitHub repo banaye
1. https://github.com par login karein.
2. New repository banaye (name: nonxnetwork-detect ya koi bhi).
3. Local machine par ya GitHub web UI se upar wala project structure push karein.

## 2) Files push karne ka simple tarika (local):
1. Terminal kholen:
   ```bash
   git init
   git add .
   git commit -m "Initial"
   git branch -M main
   git remote add origin https://github.com/<aapka-username>/<repo-name>.git
   git push -u origin main