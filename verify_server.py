"""
verify_server.py
=================
這是驗證系統「網頁端」的獨立後端程式，跟 bot.py 是分開執行的兩支程式，
透過同一個 MongoDB（verify_tokens 這個 collection）跟 Discord API 串接。

【執行前必看，你需要準備】：
  1. 一台有網域 + HTTPS 的對外主機（VPS / Cloud Run / Render 等皆可），
     因為 Discord OAuth2 的 Redirect URI 必須是 https 開頭且能被 Discord 存取到。
  2. 到 Discord Developer Portal 該應用程式的 OAuth2 頁面，新增一個 Redirect URI，
     內容要跟下面 DISCORD_REDIRECT_URI 完全一致（例如 https://verify.yourdomain.com/oauth/callback）。
  3. 到 https://dash.cloudflare.com/ 免費申請一組 Turnstile 的 Site Key / Secret Key
     （這是 Cloudflare 的免費人機驗證服務，可以取代付費的 hCaptcha）。
  4. （選用）到 https://proxycheck.io/ 申請一組免費 API Key，用來做 IP / VPN 風控查詢。
     沒有申請的話，IP 風控這塊會直接略過（不會擋人，但也不會偵測 VPN）。
  5. 把下面 CONFIG 區塊的環境變數都設定好（建議用 .env 或系統環境變數，不要寫死在程式碼裡）。

【啟動方式】：
    pip install flask requests pymongo --break-system-packages
    python verify_server.py

【重要限制（誠實告知）】：
  - 這裡的「無頭瀏覽器偵測」只是基本的 navigator.webdriver 檢查，
    真正嚴謹的自動化偵測（例如偵測 Puppeteer/Selenium 的各種特徵）需要
    像 FingerprintJS Pro、DataDome 這類付費服務，這裡沒辦法完全取代。
    不過 Cloudflare Turnstile 本身在背景就會做很多機器人偵測，這是你主要的防線。
  - IP 風控（VPN / Proxy 偵測）的準確度取決於你使用的第三方服務與付費方案，
    免費方案通常有查詢次數限制與較低的準確率。
"""

import os
import time
import datetime
import requests
from flask import Flask, request, redirect, render_template_string, jsonify
from pymongo import MongoClient

# ============================================================
# CONFIG（建議全部改用環境變數，這裡給預設值方便你知道要填什麼）
# ============================================================
MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://rick109_db_user:M9ZQhfUX64L6tyry@cluster0.ja68cy7.mongodb.net/?retryWrites=true&w=majority")

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "你的Discord應用程式ClientID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "你的Discord應用程式ClientSecret")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "https://verify-ei0t.onrender.com/oauth/callback")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "你的機器人Token（跟bot.py同一支）")

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "你的CloudflareTurnstileSiteKey")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "你的CloudflareTurnstileSecretKey")

PROXYCHECK_API_KEY = os.environ.get("PROXYCHECK_API_KEY", "")  # 留空 = 不做 IP 風控查詢

MIN_ACCOUNT_AGE_DAYS = 7
DISCORD_EPOCH_MS = 1420070400000  # Discord Snowflake 起始時間 (2015-01-01)

app = Flask(__name__)
mongo_client = MongoClient(MONGO_URI)
db = mongo_client["cash_bot"]
verify_tokens = db["verify_tokens"]


# ============================================================
# 工具函式
# ============================================================

def get_client_ip():
    # 如果部署在 nginx / Cloudflare 後面，要用 X-Forwarded-For 取得真實 IP
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def check_ip_risk(ip):
    """回傳 (是否可疑, 說明)。沒有設定 API Key 就直接放行。"""
    if not PROXYCHECK_API_KEY:
        return False, "未設定 IP 風控 API，略過檢查"
    try:
        resp = requests.get(
            f"https://proxycheck.io/v2/{ip}",
            params={"key": PROXYCHECK_API_KEY, "vpn": "1", "risk": "1"},
            timeout=5
        )
        data = resp.json()
        info = data.get(ip, {})
        is_proxy = info.get("proxy") == "yes"
        risk = int(info.get("risk", 0))
        if is_proxy or risk >= 66:
            return True, f"偵測到高風險 IP（proxy={info.get('proxy')}, risk={risk}）"
        return False, "IP 風控通過"
    except Exception as e:
        # 查詢失敗時預設「不擋」，避免服務中斷影響正常使用者；正式環境可依需求改成擋下
        return False, f"IP 風控查詢失敗（{e}），略過"


def discord_snowflake_created_at(user_id: str) -> datetime.datetime:
    ms = (int(user_id) >> 22) + DISCORD_EPOCH_MS
    return datetime.datetime.utcfromtimestamp(ms / 1000)


def get_token_doc(token):
    return verify_tokens.find_one({"_id": token})


def token_is_expired(doc):
    return datetime.datetime.utcnow() > doc["expires_at"]


# ============================================================
# 頁面模板（極簡深色主題，內嵌 HTML，方便單檔案部署）
# ============================================================

LOADING_PAGE = """
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="UTF-8">
<title>安全驗證</title>
<style>
  body { background:#0d1117; color:#e6edf3; font-family: -apple-system, "Microsoft JhengHei", sans-serif;
         display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
  .box { text-align:center; }
  .spinner { width:56px; height:56px; border:4px solid #1f2937; border-top-color:#3b82f6;
             border-radius:50%; animation:spin 1s linear infinite; margin:0 auto 24px; }
  @keyframes spin { to { transform:rotate(360deg); } }
  p { color:#9ca3af; font-size:15px; }
</style>
</head>
<body>
  <div class="box">
    <div class="spinner"></div>
    <p id="status">安全環境檢查中...</p>
  </div>
<script>
  // 基本的無頭瀏覽器 / 自動化腳本特徵檢查（僅為輔助層，非完全防禦）
  function basicBotHeuristics() {
    const flags = [];
    if (navigator.webdriver) flags.push("webdriver");
    if (!window.chrome && navigator.userAgent.includes("Chrome")) flags.push("fake_chrome");
    if (navigator.plugins && navigator.plugins.length === 0) flags.push("no_plugins");
    return flags;
  }

  fetch("/api/preflight", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: "{{ token }}", bot_flags: basicBotHeuristics() })
  })
  .then(r => r.json())
  .then(data => {
    if (data.ok) {
      document.getElementById("status").innerText = "檢查通過，正在導向 Discord 授權頁面...";
      window.location.href = data.redirect;
    } else {
      document.getElementById("status").innerText = data.message || "驗證失敗";
    }
  })
  .catch(() => {
    document.getElementById("status").innerText = "連線發生錯誤，請稍後再試";
  });
</script>
</body>
</html>
"""

FAIL_PAGE = """
<!DOCTYPE html>
<html lang="zh-Hant">
<head><meta charset="UTF-8"><title>驗證失敗</title>
<style>
  body { background:#0d1117; color:#e6edf3; font-family: -apple-system, "Microsoft JhengHei", sans-serif;
         display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
  .box { text-align:center; max-width:420px; padding:24px; }
  .icon { font-size:56px; margin-bottom:16px; }
  h1 { font-size:20px; color:#f87171; }
  p { color:#9ca3af; }
</style></head>
<body>
  <div class="box">
    <div class="icon">⛔</div>
    <h1>驗證失敗</h1>
    <p>{{ message }}</p>
  </div>
</body>
</html>
"""

TURNSTILE_PAGE = """
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="UTF-8"><title>安全驗證</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
  body { background:#0d1117; color:#e6edf3; font-family: -apple-system, "Microsoft JhengHei", sans-serif;
         display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
  .box { text-align:center; }
  h1 { font-size:18px; margin-bottom:24px; }
</style>
</head>
<body>
  <div class="box">
    <h1>請完成下方的人機驗證以繼續</h1>
    <form id="cf-form" method="POST" action="/api/turnstile-verify">
      <input type="hidden" name="token" value="{{ token }}">
      <div class="cf-turnstile" data-sitekey="{{ site_key }}" data-callback="onTurnstileSuccess"></div>
    </form>
  </div>
<script>
  function onTurnstileSuccess() {
    document.getElementById("cf-form").submit();
  }
</script>
</body>
</html>
"""

SUCCESS_PAGE = """
<!DOCTYPE html>
<html lang="zh-Hant">
<head><meta charset="UTF-8"><title>驗證成功</title>
<style>
  body { background:#0d1117; color:#e6edf3; font-family: -apple-system, "Microsoft JhengHei", sans-serif;
         display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
  .box { text-align:center; }
  .icon { font-size:64px; color:#22c55e; margin-bottom:16px; }
  h1 { font-size:20px; }
  p { color:#9ca3af; }
</style></head>
<body>
  <div class="box">
    <div class="icon">✅</div>
    <h1>驗證成功！</h1>
    <p>正在為您開通伺服器權限，現在您可以返回 Discord 了。</p>
  </div>
</body>
</html>
"""


# ============================================================
# 路由
# ============================================================

@app.route("/verify")
def verify_entry():
    token = request.args.get("token", "")
    doc = get_token_doc(token)
    if not doc:
        return render_template_string(FAIL_PAGE, message="驗證連結無效，請重新從 Discord 點擊按鈕取得連結。")
    if doc.get("used"):
        return render_template_string(FAIL_PAGE, message="這組驗證連結已經使用過了。")
    if token_is_expired(doc):
        return render_template_string(FAIL_PAGE, message="驗證連結已過期（超過 5 分鐘），請重新從 Discord 點擊按鈕取得連結。")
    return render_template_string(LOADING_PAGE, token=token)


@app.route("/api/preflight", methods=["POST"])
def api_preflight():
    body = request.get_json(force=True, silent=True) or {}
    token = body.get("token", "")
    bot_flags = body.get("bot_flags", [])

    doc = get_token_doc(token)
    if not doc:
        return jsonify(ok=False, message="驗證連結無效")
    if doc.get("used"):
        return jsonify(ok=False, message="這組驗證連結已經使用過了")
    if token_is_expired(doc):
        return jsonify(ok=False, message="驗證連結已過期")

    # 1) 無頭瀏覽器 / 自動化腳本基本特徵檢查
    if "webdriver" in bot_flags:
        return jsonify(ok=False, message="偵測到自動化瀏覽器，驗證已拒絕")

    # 2) IP 風控
    ip = get_client_ip()
    suspicious, reason = check_ip_risk(ip)
    if suspicious:
        return jsonify(ok=False, message=f"IP 風控未通過：{reason}")

    verify_tokens.update_one({"_id": token}, {"$set": {"stage": "preflight_passed", "ip": ip}})

    oauth_url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        "&response_type=code"
        "&scope=identify"
        f"&state={token}"
    )
    return jsonify(ok=True, redirect=oauth_url)


@app.route("/oauth/callback")
def oauth_callback():
    code = request.args.get("code")
    token = request.args.get("state", "")

    doc = get_token_doc(token)
    if not doc:
        return render_template_string(FAIL_PAGE, message="驗證連結無效")
    if doc.get("used"):
        return render_template_string(FAIL_PAGE, message="這組驗證連結已經使用過了")
    if token_is_expired(doc):
        return render_template_string(FAIL_PAGE, message="驗證連結已過期")
    if doc.get("stage") != "preflight_passed":
        return render_template_string(FAIL_PAGE, message="請重新從 Discord 按鈕開始驗證流程")
    if not code:
        return render_template_string(FAIL_PAGE, message="Discord 授權失敗或被取消")

    # 用 code 交換 access token
    try:
        token_resp = requests.post(
            "https://discord.com/api/oauth2/token",
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        token_resp.raise_for_status()
        access_token = token_resp.json()["access_token"]

        user_resp = requests.get(
            "https://discord.com/api/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10
        )
        user_resp.raise_for_status()
        discord_user = user_resp.json()
    except Exception as e:
        return render_template_string(FAIL_PAGE, message=f"與 Discord 溝通時發生錯誤，請稍後再試（{e}）")

    oauth_user_id = discord_user["id"]

    # 確認這個 OAuth 登入的帳號，跟當初在 Discord 按下按鈕的人是同一位
    if oauth_user_id != doc["user_id"]:
        return render_template_string(FAIL_PAGE, message="此驗證連結不屬於您的帳號，請用發起驗證的那個 Discord 帳號登入。")

    # 帳號風控：註冊時間 / 是否有頭像
    created_at = discord_snowflake_created_at(oauth_user_id)
    account_age_days = (datetime.datetime.utcnow() - created_at).days
    has_avatar = discord_user.get("avatar") is not None

    if account_age_days < MIN_ACCOUNT_AGE_DAYS or not has_avatar:
        return render_template_string(FAIL_PAGE, message="您的帳號安全強度不足，無法通過驗證。")

    verify_tokens.update_one({"_id": token}, {"$set": {"stage": "oauth_passed"}})

    return render_template_string(TURNSTILE_PAGE, token=token, site_key=TURNSTILE_SITE_KEY)


@app.route("/api/turnstile-verify", methods=["POST"])
def api_turnstile_verify():
    token = request.form.get("token", "")
    cf_response = request.form.get("cf-turnstile-response", "")

    doc = get_token_doc(token)
    if not doc:
        return render_template_string(FAIL_PAGE, message="驗證連結無效")
    if doc.get("used"):
        return render_template_string(FAIL_PAGE, message="這組驗證連結已經使用過了")
    if token_is_expired(doc):
        return render_template_string(FAIL_PAGE, message="驗證連結已過期")
    if doc.get("stage") != "oauth_passed":
        return render_template_string(FAIL_PAGE, message="請重新從 Discord 按鈕開始驗證流程")
    if not cf_response:
        return render_template_string(FAIL_PAGE, message="請完成人機驗證")

    try:
        cf_resp = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": TURNSTILE_SECRET_KEY, "response": cf_response, "remoteip": get_client_ip()},
            timeout=10
        )
        cf_result = cf_resp.json()
    except Exception as e:
        return render_template_string(FAIL_PAGE, message=f"人機驗證服務發生錯誤（{e}）")

    if not cf_result.get("success"):
        return render_template_string(FAIL_PAGE, message="人機驗證失敗，請重新嘗試。")

    # 一切通過，透過 Discord API 直接把身分組加給使用者
    guild_id = doc["guild_id"]
    user_id = doc["user_id"]
    role_id = doc["role_id"]

    try:
        put_resp = requests.put(
            f"https://discord.com/api/v10/guilds/{guild_id}/members/{user_id}/roles/{role_id}",
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            timeout=10
        )
        if put_resp.status_code not in (200, 201, 204):
            return render_template_string(FAIL_PAGE, message=f"身分組派發失敗，請聯繫管理員（狀態碼 {put_resp.status_code}）。")
    except Exception as e:
        return render_template_string(FAIL_PAGE, message=f"身分組派發時發生錯誤，請聯繫管理員（{e}）")

    verify_tokens.update_one({"_id": token}, {"$set": {"used": True, "stage": "used", "used_at": datetime.datetime.utcnow()}})

    return render_template_string(SUCCESS_PAGE)


if __name__ == "__main__":
    # 本機測試用；正式環境請用 gunicorn/uwsgi 之類的 WSGI server 搭配 nginx 反向代理 + HTTPS
    app.run(host="0.0.0.0", port=5000, debug=False)
