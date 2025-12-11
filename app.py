from flask import Flask, request, jsonify
import requests, json, time, threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
from byte import Encrypt_ID, encrypt_api

app = Flask(__name__)

key = b"Yg&tc%DEuh6%Zc^8"
iv = b"6oyZDr22E3ychjM%"

all_tokens = []
token_status = {"is_getting": False, "count": 0, "total": 0, "success": 0}

INFO_ACCOUNT = {"uid": "4332566158", "password": "LuanOri_RIO_BY_LUANORI_DEV_2222"}
info_token = None  

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        if result.field not in result_dict:
            result_dict[result.field] = []
        field_data = {}
        if result.wire_type in ["varint", "string", "bytes"]:
            field_data = result.data
        elif result.wire_type == "length_delimited":
            field_data = parse_results(result.data.results)
        result_dict[result.field].append(field_data)
    return {key: value[0] if len(value) == 1 else value for key, value in result_dict.items()}

def protobuf_dec(hex_str):
    try:
        return json.loads(json.dumps(parse_results(Parser().parse(hex_str)), ensure_ascii=False))
    except:
        return {}

def encrypt_api_ff(hex_data):
    try:
        plain_text = bytes.fromhex(hex_data)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except:
        return ""

def get_account_info(uid, token):
    try:
        payload = f"08{Encrypt_ID(uid)}10" + "01"
        encrypted = encrypt_api_ff(payload)
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        headers = {
            "ReleaseVersion": "OB51",
            "Authorization": f"Bearer {token}",
            "X-GA": "v1 1",
            "Host": "clientbp.ggblueshark.com"
        }
        res = requests.post(url, headers=headers, data=bytes.fromhex(encrypted))
        if res.status_code != 200:
            return None
        data = protobuf_dec(res.content.hex())
        if "1" in data:
            info = data["1"]
            return {
                "Account UID": info.get("1", "Unknown"),
                "Account Name": info.get("3", "Unknown"),
                "Account Region": info.get("5", "Unknown"),
                "Account Level": info.get("6", 0),
                "Account Likes": info.get("21", 0)
            }
    except Exception as e:
        print("Lỗi get_account_info:", e)
    return None

def get_jwt_tokens():
    global token_status, all_tokens
    try:
        with open('account.json', 'r') as f:
            accounts = json.load(f)
    except Exception as e:
        print(f"[!] Lỗi khi đọc account.json: {e}")
        return

    tokens = []
    token_status.update({
        "is_getting": True,
        "count": 0,
        "total": len(accounts),
        "success": 0
    })

    print(f"\n[🚀] Bắt đầu get token cho {len(accounts)} tài khoản...\n")

    for acc in accounts:
        data_field = acc.get("data")
        if not data_field or ":" not in data_field:
            continue
        uid, password = data_field.split(":", 1)
        try:
            url = f"https://api.freefireservice.dnc.su/auth/account:login?data={uid}:{password}"
            res = requests.get(url, timeout=10)
            token_status["count"] += 1
            if res.status_code == 200:
                js = res.json()
                if "8" in js:
                    tokens.append(("vn", js["8"]))
                    token_status["success"] += 1
                    print(f"[✅] UID {uid} thành công ({token_status['count']}/{token_status['total']})")
            else:
                print(f"[⚠️] UID {uid} lỗi {res.status_code}")
        except Exception as e:
            print(f"[❌] UID {uid}: {e}")

    all_tokens = tokens
    token_status["is_getting"] = False
    print(f"\n[🎯] Tổng acc get thành công: {token_status['success']}\n")

def get_token_cho_acc_info():
    global info_token
    uid = INFO_ACCOUNT["uid"]
    password = INFO_ACCOUNT["password"]
    try:
        url = f"https://api.freefireservice.dnc.su/auth/account:login?data={uid}:{password}"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            js = res.json()
            if "8" in js:
                info_token = js["8"]
                print(f"[🔑] Token info account {uid} lấy lại thành công.")
                return info_token
        print(f"[❌] Lỗi lấy token cho info account ({res.status_code})")
    except Exception as e:
        print(f"[⚠️] Lỗi khi get token info account: {e}")
    info_token = None
    return None

    for acc in accounts:
        data_field = acc.get("data")
        if not data_field or ":" not in data_field:
            continue
        uid, password = data_field.split(":", 1)
        try:
            url = f"https://api.freefireservice.dnc.su/auth/account:login?data={uid}:{password}"
            res = requests.get(url, timeout=10)
            token_status["count"] += 1
            if res.status_code == 200:
                js = res.json()
                if "8" in js:
                    tokens.append(("vn", js["8"]))
                    token_status["success"] += 1
                    print(f"[✅] UID {uid} thành công ({token_status['count']}/{token_status['total']})")
            else:
                print(f"[⚠️] UID {uid} lỗi {res.status_code}")
        except Exception as e:
            print(f"[❌] UID {uid}: {e}")

    all_tokens = tokens
    token_status["is_getting"] = False
    print(f"\n[🎯] Tổng acc get thành công: {token_status['success']}\n")


def run_get_token_periodically():
    while True:
        token_status["last_run"] = time.time()
        get_jwt_tokens()
        token_status["next_run"] = time.time() + (5 * 60 * 60)
        time.sleep(5 * 60 * 60)

def load_tokens():
    regions = ["vn"]
    all_tokens = []
    for region in regions:
        file_name = f"token_{region}.json"
        try:
            with open(file_name, "r") as file:
                data = json.load(file)
            tokens = [(region, item["8"]) for item in data]
            all_tokens.extend(tokens)
        except Exception as e:
            print(f"Lỗi khi tải token từ file {file_name}: {e}")
    return all_tokens

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retry_strategy = Retry(
    total=2,
    backoff_factor=0.1,
    status_forcelist=[429, 500, 502, 503, 504]
)
adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=retry_strategy)
session.mount("https://", adapter)

def send_friend_request(uid, token, region, results_lock, results):
    try:
        encrypted_id = Encrypt_ID(uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)

        url = "https://clientbp.ggblueshark.com/RequestAddingFriend"
        headers = {
            "Authorization": f"Bearer {token}",
            "ReleaseVersion": "OB51",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "Connection": "keep-alive",
        }

        response = session.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=3)

        with results_lock:
            if response.status_code == 200:
                results["thanhcong"] += 1
            else:
                results["thatbai"] += 1
    except Exception as e:
        with results_lock:
            results["thatbai"] += 1

@app.route("/spam", methods=["GET"])
def spam():
    uid = request.args.get("uid")
    server = request.args.get("server", "vn")

    if not uid:
        return jsonify({"error": "Thiếu tham số UID"}), 400

    if token_status["is_getting"]:
        percent = round((token_status["count"] / token_status["total"]) * 100, 2) if token_status["total"] > 0 else 0
    
        next_time = token_status.get("next_run", 0)
        if next_time > time.time():
            remain = int(next_time - time.time())
            remain_h = remain // 3600
            remain_m = (remain % 3600) // 60
            remain_str = f"{remain_h}h {remain_m}m"
        else:
            remain_str = "Đang cập nhật..."
    
        return jsonify({
            "status": "Đang lấy token...",
            "đã_lấy": f"{token_status['count']}/{token_status['total']}",
            "hoàn_thành": f"{percent}%",
            "thành_công": token_status["success"],
            "Đang Tiến Hành Get Token": True,
            "api_sẽ_chạy_lại_sau": remain_str
        })
    
    if not all_tokens:
        return jsonify({"error": "Chưa có token khả dụng"}), 500
    # ====================================================
    
    tokens = all_tokens

    start_time = time.time()

    global info_token
    if not info_token:
        info_token = get_token_cho_acc_info()
    
    acc_info = get_account_info(uid, info_token)
    if not acc_info:  
        print("[⚠️] Token info lỗi, đang lấy lại...")
        info_token = get_token_cho_acc_info()
        acc_info = get_account_info(uid, info_token)

    results = {"thanhcong": 0, "thatbai": 0}
    results_lock = threading.Lock()

    threads = []
    for region, token in tokens[:100]:
        t = threading.Thread(target=send_friend_request, args=(uid, token, region, results_lock, results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    end_time = time.time()

    return jsonify({
    "result": {
        "API": {
            "speeds": f"{round(end_time - start_time, 1)}s",
            "success": True
        },
        "Spam Info": {
            "Spam Successful": results["thanhcong"],
            "Spam Failed": results["thatbai"]
        },
        "User Info": {
            "Account Level": acc_info.get("Account Level") if acc_info else 0,
            "Account Likes": acc_info.get("Account Likes") if acc_info else 0,
            "Account Name": acc_info.get("Account Name") if acc_info else "Unknown",
            "Account Region": acc_info.get("Account Region") if acc_info else server.upper(),
            "Account UID": acc_info.get("Account UID") if acc_info else uid
        },
        "Copyright": {
            "author": "Senzu ● Tenju 𝕏 LuanOri",
            "website": "𝙇𝙪𝙖𝙣𝙊𝙧𝙞.𝙎𝙥𝙖𝙘𝙚",
            "version": "1.12.2",
            "year": "2025 - 2027",
            "message": "Bản quyền thuộc về @LuanOri. Vui lòng không re-up dưới mọi hình thức!",
            "contact": "Facebook: FB.COM/LuanOri | Telegram: t.me/LuanOri04"
        }
    },
    "note": "Tool được phát triển bởi LuanOri Rio/Team - Chỉ sử dụng cho mục đích học tập!"
})

if __name__ == "__main__":
    threading.Thread(target=run_get_token_periodically, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=True)
