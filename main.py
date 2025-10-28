import os
import json
import gspread
import logging
import datetime
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

# --- 認證 (JWT) 相關 ---
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated # 用於 FastAPI 0.95+

# --- Google Sheets 相關 ---
from oauth2client.service_account import ServiceAccountCredentials

# --- 設定日誌 ---
logging.basicConfig(level=logging.INFO)

# =======================================================================
# 應用程式設定
# =======================================================================

app = FastAPI(
    title="設備報修與任務系統 API",
    description="提供報修提交、任務查看與接取功能"
)

# --- CORS 設定 ---
# 允許所有來源，這在開發時很方便
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =======================================================================
# Google Sheets 設定與初始化
# =======================================================================

spreadsheet_id = "1IHyA7aRxGJekm31KIbuORpg4-dVY8XTOEbU6p8vK3y4"
WORKSHEET_NAME = "設備報修"
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
        logging.info("Google Sheets 連線成功並獲取工作表。")
        return True
    except gspread.exceptions.SpreadsheetNotFound:
        logging.error(f"錯誤：找不到 ID 為 '{spreadsheet_id}' 的試算表。")
        return False
    except gspread.exceptions.WorksheetNotFound:
        logging.error(f"錯誤：在試算表中找不到名稱為 '{WORKSHEET_NAME}' 的工作表。")
        return False
    except Exception as e:
        logging.error(f"初始化 Gspread 時發生未預期的錯誤: {e}")
        return False

# 在 FastAPI 啟動時執行初始化
@app.on_event("startup")
def startup_event():
    if not initialize_gspread():
        logging.warning("應用程式啟動，但 Google Sheets 連線失敗。API 可能無法正常運作。")

def get_sheet():
    """依賴項：獲取 Google Sheet 工作表物件"""
    if sheet is None:
        logging.warning("Sheet 未初始化，嘗試重新連線...")
        if not initialize_gspread():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="無法連線至 Google Sheets 服務。"
            )
    return sheet

# =======================================================================
# 認證 (Authentication) 設定
# =======================================================================

# --- 安全性設定 ---
# 讀取環境變數，若不存在則使用一個預設值（警告：生產環境中應*必定*設定環境變數）
SECRET_KEY = os.environ.get("SECRET_KEY", "a_very_insecure_default_secret_key_CHANGE_ME")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8 # 8 小時

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- 資料模型 (Pydantic Models) ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    full_name: Optional[str] = None # 我們將儲存全名在 token 中

class User(BaseModel):
    username: str
    full_name: str
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

# --- 模擬使用者資料庫 ---
# 在這裡加入你的使用者帳號、全名和雜湊後的密碼
# !! 注意: 'pass123' 的雜湊值是 '$2b$12$Ea.Rhv4jQ5suPb4XAGYfruj.6kXlHqNiyN1uGkCYgVvSMatQh/yJ.'
FAKE_USERS_DB = {
    "user1": {
        "username": "user1",
        "full_name": "張三",
        "hashed_password": "$2b$12$Ea.Rhv4jQ5suPb4XAGYfruj.6kXlHqNiyN1uGkCYgVvSMatQh/yJ.", # "pass123"
        "disabled": False,
    },
    "user2": {
        "username": "user2",
        "full_name": "李四",
        "hashed_password": "$2b$12$Ea.Rhv4jQ5suPb4XAGYfruj.6kXlHqNiyN1uGkCYgVvSMatQh/yJ.", # "pass123"
        "disabled": False,
    },
    "manager": {
        "username": "manager",
        "full_name": "王經理",
        "hashed_password": "$2b$12$Ea.Rhv4jQ5suPb4XAGYfruj.6kXlHqNiyN1uGkCYgVvSMatQh/yJ.", # "pass123"
        "disabled": False,
    }
}

# --- 認證輔助函式 ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="無法驗證憑證",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        full_name: str = payload.get("full_name")
        if username is None or full_name is None:
            raise credentials_exception
        token_data = TokenData(username=username, full_name=full_name)
    except JWTError:
        raise credentials_exception
    
    user = get_user(FAKE_USERS_DB, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user # 回傳 UserInDB 物件，包含 full_name

# =======================================================================
# API 端點 (Endpoints)
# =======================================================================

# --- 1. 服務靜態 HTML 檔案 ---

@app.get("/", include_in_schema=False)
async def read_index():
    """服務 index.html 任務系統前端"""
    return FileResponse('index.html')

@app.get("/repair", include_in_schema=False)
async def read_repair_form():
    """服務 repair_form.html 報修表單前端"""
    return FileResponse('repair_form.html')

# --- 2. 報修提交 (來自 repair_form.html) ---

class RepairRequest(BaseModel):
    reporterName: str
    deviceLocation: str
    problemDescription: str
    helperTeacher: Optional[str] = None # 保持這個欄位彈性

@app.post("/submit-repair")
async def submit_repair(request: RepairRequest, current_sheet: Annotated[gspread.Worksheet, Depends(get_sheet)]):
    """
    接收來自 repair_form.html 的報修請求並寫入 Google Sheet。
    """
    try:
        # 獲取當前的 UTC 時間並轉換為台灣時區
        utc_now = datetime.datetime.utcnow()
        taiwan_time = utc_now + datetime.timedelta(hours=8)
        timestamp = taiwan_time.strftime("%Y-%m-%d %H:%M:%S")

        # 根據你 Flask app 的邏輯 (看起來是 5 欄)：
        row = [
            timestamp,
            request.reporterName,
            request.deviceLocation,
            request.problemDescription,
            "待處理" # E 欄：狀態
        ]
        
        # 你的 Flask app 似乎有 5 個欄位。
        # 如果你的 G-Sheet 有 協辦老師 欄位 (例如 F 欄)，你需要把它加回來
        # row = [
        #     timestamp,
        #     request.reporterName,
        #     request.deviceLocation,
        #     request.problemDescription,
        #     "待處理", # E 欄：狀態
        #     request.helperTeacher or "" # F 欄：協辦老師
        # ]
        
        current_sheet.append_row(row)
        logging.info(f"資料成功寫入：{row}")
        
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"status": "success", "message": "報修單已成功提交！"}
        )
        
    except Exception as e:
        logging.error(f"寫入 Google Sheet 時發生錯誤: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"伺服器內部錯誤，無法寫入 Google Sheet: {e}"
        )

# --- 3. 認證 (來自 index.html) ---

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    提供帳號密碼以獲取 Access Token (JWT)。
    """
    user = get_user(FAKE_USERS_DB, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="不正確的使用者名稱或密碼",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.disabled:
        raise HTTPException(status_code=400, detail="使用者帳號已停用")

    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        # 我們將 username 和 full_name 都存入 token
        data={"sub": user.username, "full_name": user.full_name}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- 4. 任務系統 API (來自 index.html) ---

class Task(BaseModel):
    row_number: int
    timestamp: str
    reporter: str
    location: str
    description: str
    status: str
    required_count: int
    current_count: int
    assignees: List[str]

@app.get("/tasks", response_model=List[Task])
async def get_tasks(
    current_sheet: Annotated[gspread.Worksheet, Depends(get_sheet)],
    current_user: Annotated[User, Depends(get_current_user)] # 確保使用者已登入
):
    """
    獲取所有狀態為「待處理」的任務列表。
    """
    try:
        # 獲取所有資料 (包含標頭)
        all_data = current_sheet.get_all_records()
        tasks = []
        
        # 欄位名稱 (假設)
        # A: 時間戳, B: 報修人, C: 地點, D: 問題描述, E: 狀態, F: 負責人數, G: 負責人1, H: 負責人2...
        
        for index, row in enumerate(all_data):
            row_number = index + 2 # +1 (index 轉行號), +1 (跳過標頭)
            status_val = str(row.get("狀態", "")).strip()
            
            if status_val == "待處理":
                # 獲取負責人數
                try:
                    required_count_str = str(row.get("負責人數", 0)).strip()
                    if required_count_str:
                        required_count = int(required_count_str)
                    else:
                        required_count = 0 # 如果 F 欄是空字串
                except (ValueError, TypeError):
                    required_count = 0 # 如果 F 欄不是數字，當作 0
                
                # 收集 G 欄之後的負責人
                assignees = []
                # 假設 G~K 欄 (5人)
                for i in range(1, 6): # 負責人1 到 負責人5
                    assignee_name = str(row.get(f"負責人{i}", "")).strip()
                    if assignee_name:
                        assignees.append(assignee_name)
                
                tasks.append(Task(
                    row_number=row_number,
                    timestamp=str(row.get("時間戳", "N/A")),
                    reporter=str(row.get("報修人", "N/A")),
                    location=str(row.get("地點", "N/A")),
                    description=str(row.get("問題描述", "N/A")),
                    status=status_val,
                    required_count=required_count,
                    current_count=len(assignees),
                    assignees=assignees
                ))
                
        return tasks

    except Exception as e:
        logging.error(f"讀取任務列表時發生錯誤: {e}")
        raise HTTPException(
            status_code=500, detail=f"讀取 Google Sheet 失敗: {e}"
        )

@app.post("/accept-task/{row_number}", response_model=Task)
async def accept_task(
    row_number: int,
    current_sheet: Annotated[gspread.Worksheet, Depends(get_sheet)],
    current_user: Annotated[UserInDB, Depends(get_current_user)] # 我們需要 user.full_name
):
    """
    接取一個任務，將使用者名稱填入 G, H, I, J, K... 欄位。
    """
    try:
        # 1. 讀取指定行的資料 (G:K 欄位是 7~11)
        # 欄位索引：A=1, B=2, C=3, D=4, E=5, F=6, G=7, H=8, I=9, J=10, K=11
        row_data = current_sheet.row_values(row_number)
        
        # 基本檢查
        if not row_data or len(row_data) < 6: # 至少要有 F 欄
             raise HTTPException(status_code=404, detail="找不到該任務或欄位資料不完整。")

        task_status = row_data[4].strip() # E 欄 (索引 4)
        
        if task_status != "待處理":
            raise HTTPException(status_code=400, detail=f"此任務狀態為「{task_status}」，無法接取。")

        # 2. 檢查 F 欄 (負責人數)
        try:
            required_count_str = row_data[5].strip() # F 欄 (索引 5)
            if required_count_str:
                required_count = int(required_count_str)
            else:
                required_count = 0
        except (ValueError, TypeError, IndexError):
            required_count = 0 # 如果 F 欄空白或不是數字
        
        if required_count <= 0:
            raise HTTPException(status_code=400, detail="此任務未設定負責人數(F欄)，無法接取。")

        # 3. 檢查 G~K 欄 (索引 6 到 10) 的現有負責人
        assignees = []
        first_empty_col_index = -1
        
        # 我們只檢查 G 到 K (最多 5 人)
        for i in range(6, 11): # 欄位索引 6(G) 到 10(K)
            assignee_name = ""
            if i < len(row_data):
                assignee_name = row_data[i].strip()
            
            if assignee_name:
                # 檢查是否已接取
                if assignee_name == current_user.full_name:
                    raise HTTPException(status_code=400, detail="你已經接取過此任務。")
                assignees.append(assignee_name)
            elif first_empty_col_index == -1:
                # 
                first_empty_col_index = i

        # 4. 判斷是否額滿
        if len(assignees) >= required_count:
            raise HTTPException(status_code=400, detail="此任務已額滿，無法接取。")
            
        if first_empty_col_index == -1:
            # 如果 G-K 都滿了 (5人)，但所需人數 > 5，這裡會出錯
            # 這是 G-K 欄位限制，暫時先這樣
             raise HTTPException(status_code=400, detail="此任務已滿 (已達 5 人上限)。")

        # 5. 執行更新 (寫入 G/H/I... 欄)
        # gspread 的 cell 索引是 (row, col)，從 1 開始
        target_col = first_empty_col_index + 1 # 轉換為 1-based 索引
        current_sheet.update_cell(row_number, target_col, current_user.full_name)
        
        # 6. 檢查是否因為這次加入而額滿，如果是，更新 E 欄狀態
        if (len(assignees) + 1) == required_count:
            current_sheet.update_cell(row_number, 5, "處理中") # E 欄 (col=5)
            new_status = "處理中"
        else:
            new_status = "待處理"
        
        # 7. 回傳更新後的任務狀態
        assignees.append(current_user.full_name)
        return Task(
            row_number=row_number,
            timestamp=row_data[0],
            reporter=row_data[1],
            location=row_data[2],
            description=row_data[3],
            status=new_status,
            required_count=required_count,
            current_count=len(assignees),
            assignees=assignees
        )

    except gspread.exceptions.APIError as e:
        logging.error(f"Gspread API 錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API 錯誤: {e.s}")
    except Exception as e:
        logging.error(f"接取任務時發生未知錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"伺服器內部錯誤: {e}")

# =======================================================================
# Uvicorn 啟動點 (如果直接執行此檔案)
# =======================================================================
if __name__ == "__main__":
    import uvicorn
    # 檢查 PORT 環境變數，這是 Render 需要的
    port = int(os.environ.get("PORT", 8000))
    # 監聽 0.0.0.0 才能在容器外被訪問
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)

