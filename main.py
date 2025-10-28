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

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated 

from oauth2client.service_account import ServiceAccountCredentials

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="設備報修與任務系統 API",
    description="提供報修提交、任務查看與接取功能"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

spreadsheet_id = "1IHyA7aRxGJekm31KIbuORpg4-dVY8XTOEbU6p8vK3y4"
WORKSHEET_NAME = "設備報修"
scope = [
    "https://spreadsheets.google.com/feeds",
    'https://www.googleapis.com/auth/spreadsheets',
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive"
]

creds_json_str = os.environ.get('GOOGLE_CREDENTIALS_JSON')

if not creds_json_str:
    logging.error("錯誤：未設定 'GOOGLE_CREDENTIALS_JSON' 環境變數。")
    # 在生產環境中，您可能希望應用程式在這裡失敗或使用備用憑證
    # 為了在本地開發中繼續，我們將 creds 設為 None
    creds = None
else:
    try:
        creds_json = json.loads(creds_json_str)
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_json, scope)
    except json.JSONDecodeError:
        logging.error("錯誤：GOOGLE_CREDENTIALS_JSON 環境變數不是有效的 JSON。")
        creds = None
    except Exception as e:
        logging.error(f"從 JSON 憑證初始化時發生錯誤: {e}")
        creds = None

# 如果 creds 為 None (例如本地開發且未設定環境變數)，嘗試本地檔案
if creds is None:
    logging.warning("警告：未從環境變數載入憑證。嘗試本地 'credentials.json' 檔案...")
    try:
        creds = ServiceAccountCredentials.from_json_keyfile_name("credentials.json", scope)
        logging.info("成功從 'credentials.json' 載入憑證。")
    except FileNotFoundError:
        logging.error("錯誤：本地 'credentials.json' 檔案未找到。")
        creds = None
    except Exception as e:
        logging.error(f"從本地 'credentials.json' 檔案載入時發生錯誤: {e}")
        creds = None

if creds is None:
    logging.critical("重大錯誤：無法載入 Google 憑證。Google Sheets 功能將無法使用。")
    # 根據您的需求，您可能希望在這裡 raise an exception
    # raise Exception("無法初始化 Google 憑證")


# --- Google Sheets 用戶端 ---
# 將 client 初始化移至函式中，以便在需要時進行延遲初始化或重新授權
def get_gspread_client():
    try:
        if creds is None:
            raise Exception("Google 憑證未被初始化。")
        client = gspread.authorize(creds)
        if creds.access_token_expired:
            client.login() # 重新整理 token
        return client
    except Exception as e:
        logging.error(f"獲取 Gspread 用戶端時發生錯誤: {e}")
        return None

def get_worksheet():
    client = get_gspread_client()
    if client is None:
        raise HTTPException(status_code=503, detail="無法連接至 Google Sheets 服務 (憑證問題)")
    try:
        sheet = client.open_by_key(spreadsheet_id).worksheet(WORKSHEET_NAME)
        return sheet
    except gspread.exceptions.SpreadsheetNotFound:
        logging.error(f"找不到 Spreadsheet ID: {spreadsheet_id}")
        raise HTTPException(status_code=500, detail="找不到指定的 Google Spreadsheet")
    except gspread.exceptions.WorksheetNotFound:
        logging.error(f"在 Spreadsheet 中找不到工作表: {WORKSHEET_NAME}")
        raise HTTPException(status_code=500, detail=f"找不到工作表: {WORKSHEET_NAME}")
    except Exception as e:
        logging.error(f"打開工作表時發生未知錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"連接工作表時發生錯誤: {e}")


# --- Pydantic 模型 ---
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

class AssignTaskRequest(BaseModel):
    row_number: int

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    full_name: str
    disabled: bool = False

class UserInDB(User):
    hashed_password: str


# --- 認證設定 ---
SECRET_KEY = os.environ.get("SECRET_KEY", "a_very_secret_key_fallback_for_dev") # 應在生產環境中設定
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- 假資料庫 (用於演示) ---
# 在實際應用中，這應該來自您的資料庫
fake_users_db = {
    "studentA": {
        "username": "studentA",
        "full_name": "學生 A",
        "hashed_password": pwd_context.hash("passA"), # 範例密碼
        "disabled": False
    },
    "studentB": {
        "username": "studentB",
        "full_name": "學生 B",
        "hashed_password": pwd_context.hash("passB"), # 範例密碼
        "disabled": False
    },
    "staffC": {
        "username": "staffC",
        "full_name": "職員 C (維修人員)",
        "hashed_password": pwd_context.hash("passC"), # 範例密碼
        "disabled": False
    }
}

# --- 認證輔助函式 ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db, username: str) -> Optional[UserInDB]:
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
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
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="帳號已被停用")
    return current_user


# --- API 端點 ---

# 1. 認證端點
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = get_user(fake_users_db, form_data.username)
    
    # --- !! 修復點 !! ---
    # 在驗證前，將密碼截斷為 72 位元組，以防止 bcrypt 錯誤
    safe_password = form_data.password[:72]
    
    if not user or not verify_password(safe_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="不正確的帳號或密碼",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# 2. 獲取當前使用者資訊
@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user

# 3. 獲取所有可接取的任務
@app.get("/tasks/", response_model=List[Task])
async def get_available_tasks(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    try:
        sheet = get_worksheet()
        # 獲取 A 到 I 欄的所有資料
        all_data = sheet.get_all_values()
        
        tasks = []
        # 從第二行開始讀取 (跳過標頭)
        for i, row in enumerate(all_data[1:], start=2):
            if not any(row): # 跳過空行
                continue
                
            # 確保行有足夠的欄位
            if len(row) < 9:
                logging.warning(f"第 {i} 行資料不完整，已跳過: {row}")
                continue

            status = row[4].strip()
            
            # 我們只關心 "待處理" 的任務
            if status == "待處理":
                try:
                    required_count = int(row[5])
                except ValueError:
                    logging.warning(f"第 {i} 行的需求人數格式錯誤 (非數字)，已跳過: {row[5]}")
                    continue
                
                # 欄位 G, H, I (索引 6, 7, 8) 是接取人
                assignees = [name.strip() for name in row[6:9] if name.strip()]
                
                # 檢查當前使用者是否已經接取
                if current_user.full_name in assignees:
                    continue # 如果已經接取，則不在列表中顯示

                tasks.append(Task(
                    row_number=i,
                    timestamp=row[0],
                    reporter=row[1],
                    location=row[2],
                    description=row[3],
                    status=status,
                    required_count=required_count,
                    current_count=len(assignees),
                    assignees=assignees
                ))
                
        return tasks

    except gspread.exceptions.APIError as e:
        logging.error(f"Gspread API 錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API 錯誤: {e}")
    except Exception as e:
        logging.error(f"獲取任務時發生未知錯誤: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"獲取任務時發生內部錯誤: {e}")

# 4. 接取任務
@app.post("/tasks/assign", response_model=Task)
async def assign_task(
    request_body: AssignTaskRequest,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    try:
        current_sheet = get_worksheet()
        row_number = request_body.row_number
        
        # 獲取特定行的 A 到 I (1 到 9) 欄資料
        row_data = current_sheet.row_values(row_number)
        
        if not row_data or len(row_data) < 9:
             raise HTTPException(status_code=404, detail="找不到指定的任務行或資料不完整。")

        status = row_data[4].strip()
        
        if status != "待處理":
            raise HTTPException(status_code=400, detail=f"此任務狀態為 '{status}'，無法接取。")

        try:
            required_count = int(row_data[5])
        except ValueError:
             raise HTTPException(status_code=500, detail="任務需求人數格式錯誤。")

        # 欄位 G, H, I (索引 6, 7, 8)
        assignees = [name.strip() for name in row_data[6:9] if name.strip()]

        if current_user.full_name in assignees:
            raise HTTPException(status_code=400, detail="您已經接取過此任務。")

        first_empty_col = -1
        # G 欄對應索引 6 (col 7)
        if not row_data[6].strip():
            first_empty_col = 6
        # H 欄對應索引 7 (col 8)
        elif not row_data[7].strip():
            first_empty_col = 7
        # I 欄對應索引 8 (col 9)
        elif not row_data[8].strip():
            first_empty_col = 8

        # 在我們檢查空欄位之前，再次檢查人數（防止競爭條件）
        if len(assignees) >= required_count:
            current_sheet.update_cell(row_number, 5, "處理中") # 第 5 欄是狀態
            raise HTTPException(status_code=400, detail="此任務剛剛已額滿。")

        if first_empty_col == -1:
             raise HTTPException(status_code=500, detail="找不到可填入的欄位，但任務未滿員。")

        target_col = first_empty_col + 1 # Gspread 欄位是 1-based index
        current_sheet.update_cell(row_number, target_col, current_user.full_name)
        
        new_status = "待處理"
        if (len(assignees) + 1) == required_count:
            current_sheet.update_cell(row_number, 5, "處理中") # 第 5 欄是狀態
            new_status = "處理中"
        
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
        raise HTTPException(status_code=500, detail=f"Google Sheets API 錯誤: {e}")
    except Exception as e:
        logging.error(f"接取任務時發生未知錯誤: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"接取任務時發生內部錯誤: {e}")


# 5. 託管靜態檔案 (HTML/CSS/JS)
# 確保你有一個名為 'static' 的資料夾，或者相應地調整路徑
# app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def read_root():
    # 假設 index.html 在與 main.py 相同目錄或 'static' 資料夾中
    # 為了簡單起見，我們假設它在同一個目錄中
    try:
        return FileResponse("index.html")
    except FileNotFoundError:
        logging.error("index.html 未找到。")
        return JSONResponse(
            content={"error": "找不到前端介面檔案 (index.html)。"},
            status_code=404
        )
    except Exception as e:
        logging.error(f"讀取 index.html 時發生錯誤: {e}")
        return JSONResponse(
            content={"error": "無法提供前端介面。"},
            status_code=500
        )

# Uvicorn 啟動 (用於本地開發)
if __name__ == "__main__":
    import uvicorn
    # 讀取 Render.com 提供的 PORT 環境變數，如果沒有則預設為 8000
    port = int(os.environ.get("PORT", 8000))
    # 監聽 0.0.0.0 以接受來自外部的連線 (Render.com 需要)
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
