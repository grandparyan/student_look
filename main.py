import os
import json
import gspread
import logging
import datetime
from fastapi import FastAPI, Request, HTTPException, Depends, status, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from oauth2client.service_account import ServiceAccountCredentials
from pydantic import BaseModel
from typing import List, Optional

# --- 安全性與認證 (Auth) ---
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

# --- 設定日誌 ---
logging.basicConfig(level=logging.INFO)

# ==============================================================================
# 1. Google Sheets 服務帳號與設定
# ==============================================================================
spreadsheet_id = "1IHyA7aRxGJekm31KIbuORpg4-dVY8XTOEbU6p8vK3y4"
WORKSHEET_NAME = "設備報修" # 確保這個名稱和你的工作表完全一致
scope = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive",
]

# 全域變數
client = None
sheet = None

def initialize_gspread():
    """初始化 Google Sheets 連線。"""
    global client, sheet
    if client:
        logging.info("Gspread client 已初始化。")
        return True

    try:
        creds_json_str = os.environ.get('SERVICE_ACCOUNT_CREDENTIALS')
        if not creds_json_str:
            logging.error("致命錯誤：找不到 SERVICE_ACCOUNT_CREDENTIALS 環境變數。")
            return False
        
        creds_dict = json.loads(creds_json_str)
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, scope)
        client = gspread.authorize(creds)
        spreadsheet = client.open_by_key(spreadsheet_id)
        sheet = spreadsheet.worksheet(WORKSHEET_NAME)
        logging.info("Google Sheets 連線成功並取得工作表。")
        return True
    except Exception as e:
        logging.error(f"初始化 Google Sheets 時發生錯誤: {e}", exc_info=True)
        return False

# ==============================================================================
# 2. 安全性 & 認證 (JWT) 設定
# ==============================================================================
# !!! 警告: 請在生產環境中將此金鑰更換為一個隨機生成的安全字串 !!!
# 你可以使用: openssl rand -hex 32
SECRET_KEY = os.environ.get("SECRET_KEY", "your_fallback_secret_key_please_change_me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 24 小時

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # "token" 是指登入端點的路徑

# --- 模擬使用者資料庫 ---
# 在真實應用中，這應該來自資料庫。
# 密碼 "pass123" 的 bcrypt 雜湊值
hashed_password = pwd_context.hash("pass123")

# 這是你發下去的帳號密碼的 "資料庫"
# 你可以在這裡新增更多使用者
FAKE_USERS_DB = {
    "user1": {
        "username": "user1",
        "full_name": "張三", # 這會是填入 Google Sheet 的名字
        "hashed_password": hashed_password
    },
    "user2": {
        "username": "user2",
        "full_name": "李四",
        "hashed_password": hashed_password
    },
    "staff": {
        "username": "staff",
        "full_name": "王五 (教職員)",
        "hashed_password": hashed_password
    }
}

# --- Pydantic 模型 (用於資料驗證) ---
class User(BaseModel):
    username: str
    full_name: str

class Token(BaseModel):
    access_token: str
    token_type: str

class RepairRequest(BaseModel):
    """用於接收 /submit-repair 的資料模型"""
    reporterName: str
    deviceLocation: str
    problemDescription: str
    # 注意：我們移除了 'helperTeacher'，以匹配你之前的 main.py 邏輯

class Task(BaseModel):
    """用於 /tasks 端點的資料模型"""
    row_number: int
    timestamp: str
    reporter: str
    location: str
    description: str
    status: str
    required_count: int
    accepted_by: List[str]
    is_full: bool

# --- 認證輔助函式 ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user_from_db(username: str):
    if username in FAKE_USERS_DB:
        return FAKE_USERS_DB[username]
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
Signature: `(token: str = Depends(oauth2_scheme)) -> User`

This function is a dependency used by FastAPI endpoints to get the currently authenticated user.

1.  **`token: str = Depends(oauth2_scheme)`**: This tells FastAPI to get the Bearer token from the request's `Authorization` header. `oauth2_scheme` (defined as `OAuth2PasswordBearer(tokenUrl="token")`) handles the extraction.
2.  **`credentials_exception`**: An `HTTPException` that will be raised if the token is invalid or missing, prompting the user to log in (HTTP 401).
3.  **`jwt.decode(...)`**: Attempts to decode the provided JWT using the `SECRET_KEY` and `ALGORITHM`.
4.  **`token_data.get("sub")`**: Extracts the 'subject' from the token, which we use to store the `username`.
5.  **`get_user_from_db(...)`**: Fetches the user's details from our `FAKE_USERS_DB` using the extracted username.
6.  **`return User(...)`**: Returns a `User` object (Pydantic model) containing the user's `username` and `full_name`.

If any step fails (e.g., token expired, invalid signature, user not found), it raises the `credentials_exception`.
"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="無法驗證憑證",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user_data = get_user_from_db(username)
    if user_data is None:
        raise credentials_exception
        
    return User(username=user_data["username"], full_name=user_data["full_name"])

# ==============================================================================
# 3. FastAPI 應用程式
# ==============================================================================
app = FastAPI(title="設備報修與任務系統 API")

# 設定 CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 允許所有來源 (在生產中應更嚴格)
    allow_credentials=True,
    allow_methods=["*"], # 允許所有 HTTP 方法
    allow_headers=["*"], # 允許所有標頭
)

@app.on_event("startup")
def on_startup():
    """應用程式啟動時執行的函式"""
    if not initialize_gspread():
        logging.error("應用程式啟動失敗：無法初始化 Google Sheets。")
        # 在真實應用中，你可能想在這裡阻止應用程式啟動
    else:
        logging.info("應用程式啟動成功。")

# --- 核心端點 (Endpoints) ---

@app.get("/")
async def read_root():
    return {"message": "歡迎使用設備報修與任務系統 API"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    使用者登入端點。
    使用 "form data" 傳送 'username' 和 'password'。
    成功後返回一個 access_token。
    """
    user_data = get_user_from_db(form_data.username)
    if not user_data or not verify_password(form_data.password, user_data["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="不正確的使用者名稱或密碼",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_data["username"], "name": user_data["full_name"]}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """
    一個受保護的端點，用於測試登入狀態。
    它會返回當前登入使用者的資訊。
    """
    return current_user

# --- 舊功能：提交報修單 (已從 Flask 移植) ---
@app.post("/submit-repair")
async def submit_repair(request: RepairRequest):
    """
    接收報修表單提交 (與你舊的 main.py 相容)。
    """
    if not sheet:
        logging.error("工作表未初始化。")
        raise HTTPException(status_code=500, detail="伺服器內部錯誤：工作表未就緒。")

    try:
        utc_now = datetime.utcnow()
        taiwan_time = utc_now + timedelta(hours=8)
        timestamp = taiwan_time.strftime("%Y-%m-%d %H:%M:%S")

        # 你的邏輯：時間、姓名、位置、描述、狀態
        row = [
            timestamp, 
            request.reporterName,
            request.deviceLocation,
            request.problemDescription,
            "待處理"
        ]
        
        sheet.append_row(row)
        
        logging.info(f"資料成功寫入 (FastAPI)：{row}")
        return {"status": "success", "message": "報修單已成功提交！"}

    except Exception as e:
        logging.error(f"寫入 Google Sheets 時發生錯誤: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"伺服器錯誤: {e}")

# --- 新功能：任務系統 ---

@app.get("/tasks", response_model=List[Task])
async def get_pending_tasks(current_user: User = Depends(get_current_user)):
    """
    (需要登入)
    獲取所有 '待處理' 的任務列表。
    """
    if not sheet:
        raise HTTPException(status_code=500, detail="伺服器內部錯誤：工作表未就緒。")
    
    try:
        # 獲取所有資料 (包含標頭)
        all_values = sheet.get_all_values()
        
        # 假設第一列是標頭
        if not all_values:
            return []
            
        header = all_values[0]
        rows = all_values[1:]
        
        tasks = []
        # 從 2 開始，因為第 1 列是標頭，而 Google Sheet 列號是 1-based
        for i, row in enumerate(rows, start=2):
            
            # 確保列有足夠的資料
            if len(row) < 6: # 至少需要 A-F 欄
                continue 
                
            status = row[4].strip() # E 欄 (狀態)
            
            if status == "待處理":
                required_count_str = row[5].strip() # F 欄 (負責人數)
                
                try:
                    required_count = int(required_count_str)
                except ValueError:
                    required_count = 1 # 如果 F 欄不是數字，預設為 1
                
                # G 欄之後都是接取人
                accepted_by = [name for name in row[6:] if name.strip()]
                
                tasks.append(Task(
                    row_number=i,
                    timestamp=row[0],
                    reporter=row[1],
                    location=row[2],
                    description=row[3],
                    status=status,
                    required_count=required_count,
                    accepted_by=accepted_by,
                    is_full=(len(accepted_by) >= required_count)
                ))
                
        return tasks

    except Exception as e:
        logging.error(f"讀取任務列表時發生錯誤: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"讀取工作表時發生錯誤: {e}")


@app.post("/accept-task/{row_number}")
async def accept_task(
    row_number: int, 
    current_user: User = Depends(get_current_user)
):
    """
    (需要登入)
    接取一個指定列號 (row_number) 的任務。
    """
    if not sheet:
        raise HTTPException(status_code=500, detail="伺服器內部錯誤：工作表未就緒。")

    try:
        # 1. 獲取該列的當前資料
        # gspread.worksheet.row_values() 會返回一個 list
        row_data = sheet.row_values(row_number)
        
        if not row_data:
            raise HTTPException(status_code=404, detail=f"找不到列號 {row_number} 的任務。")
            
        # 2. 檢查狀態
        status = row_data[4].strip() if len(row_data) > 4 else ""
        if status != "待處理":
            raise HTTPException(status_code=400, detail="此任務不是 '待處理' 狀態，無法接取。")

        # 3. 獲取 F 欄 (負責人數)
        if len(row_data) < 6:
            raise HTTPException(status_code=500, detail="工作表結構不完整 (缺少 F 欄)。")
            
        try:
            required_count = int(row_data[5].strip())
        except ValueError:
            raise HTTPException(status_code=400, detail="任務 '負責人數' (F 欄) 不是一個有效的數字。")

        # 4. 獲取 G 欄及之後的接取人 (G, H, I, J, K...)
        # row_data[6:] 會是 G 欄之後的所有資料
        accepted_list = row_data[6:]
        current_accepted_names = [name for name in accepted_list if name.strip()]
        
        # 5. 檢查是否已接取
        if current_user.full_name in current_accepted_names:
            raise HTTPException(status_code=400, detail="你已經接取過此任務了。")

        # 6. 檢查是否已額滿
        if len(current_accepted_names) >= required_count:
            raise HTTPException(status_code=400, detail="任務已額滿，無法接取。")

        # 7. 執行接取 (寫入)
        # 找到 G 欄 (第 7 欄) 之後的第一個空格
        # G=7, H=8, I=9, J=10, K=11...
        # 'current_accepted_names' 的長度就是當前人數
        # 如果 0 人，填 G (欄 7)
        # 如果 1 人，填 H (欄 8)
        # ...
        target_column = 7 + len(current_accepted_names) 
        
        sheet.update_cell(row_number, target_column, current_user.full_name)
        
        logging.info(f"使用者 '{current_user.full_name}' 成功接取任務 (列 {row_number}, 欄 {target_column})")
        
        # (可選) 檢查是否因為這次接取而額滿，並更新狀態
        if (len(current_accepted_names) + 1) == required_count:
            # 額滿了，更新 E 欄 (第 5 欄) 狀態
            sheet.update_cell(row_number, 5, "處理中") # 或 "已額滿"
            return {"status": "success", "message": f"任務接取成功！此任務現已額滿並更新為 '處理中'。"}
        
        return {"status": "success", "message": f"任務接取成功！"}

    except gspread.exceptions.APIError as e:
        logging.error(f"GSpread API 錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API 錯誤: {e.args}")
    except Exception as e:
        logging.error(f"接取任務時發生未知錯誤: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"接取任務時發生未知錯誤: {e}")

# uvicorn main:app --reload --port 8000
