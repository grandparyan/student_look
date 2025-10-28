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

# --- CORS 中介軟體 ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 允許所有來源，在生產環境中應更加嚴格
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Google Sheets 設定 ---
spreadsheet_id = "1IHyA7aRxGJekm31KIbuORpg4-dVY8XTOEbU6p8vK3y4"
WORKSHEET_NAME = "設備報修"
USER_SHEET_NAME = "使用者名單" # 儲存使用者帳密的工
scope = [
    "https://spreadsheets.google.com/feeds",
    'https://www.googleapis.com/auth/spreadsheets',
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive"
]

# 從環境變數讀取 Google 憑證
creds_json_str = os.environ.get('GOOGLE_CREDENTIALS_JSON')

if not creds_json_str:
    logging.error("錯誤：未設定 'GOOGLE_CREDENTIALS_JSON' 環境變數。")
    # 在本地開發時，可以嘗試讀取檔案
    try:
        with open('google_credentials.json', 'r') as f:
            creds_json_str = f.read()
        logging.info("成功從 'google_credentials.json' 檔案載入憑證。")
    except FileNotFoundError:
        logging.error("本地 'google_credentials.json' 檔案也未找到。")
        creds_json_str = "{}" # 至少給一個空值，避免 json.loads 失敗

try:
    creds_json = json.loads(creds_json_str)
    creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_json, scope)
    client = gspread.authorize(creds)
    
    # 嘗試開啟 Google Sheet 來驗證憑證是否有效
    try:
        sh = client.open_by_key(spreadsheet_id)
        worksheet = sh.worksheet(WORKSHEET_NAME)
        user_worksheet = sh.worksheet(USER_SHEET_NAME)
        logging.info(f"成功連接到 Google Sheet: {sh.title}")
    except gspread.exceptions.APIError as e:
        logging.error(f"Google API 錯誤：無法開啟 Google Sheet。請檢查憑證權限與 Spreadsheet ID。 {e}")
        # 這裡不 raise 異常，讓應用程式繼續啟動，但在 API 呼叫時會失敗
    except gspread.exceptions.WorksheetNotFound as e:
        logging.error(f"找不到工作表：{e}。請確保 '{WORKSHEET_NAME}' 和 '{USER_SHEET_NAME}' 工作表存在。")

except json.JSONDecodeError:
    logging.error("錯誤：'GOOGLE_CREDENTIALS_JSON' 環境變數的內容不是有效的 JSON。")
except Exception as e:
    logging.error(f"載入 Google 憑證時發生未知錯誤: {e}")


# --- 1. 安全性與認證 (Authentication) ---

# JWT 設定
SECRET_KEY = os.environ.get("SECRET_KEY", "your_fallback_secret_key_1234567890") # 務必在 Render 設定此環境變數
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8 # 8 小時

# 密碼雜湊
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic 模型 (使用者相關)
class User(BaseModel):
    username: str # 帳號 (學號)
    full_name: str # 姓名
    group: str # 組別
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    user_info: Optional[str] = None # 我們將把 full_name 和 group 存在這裡


# --- 輔助函式 (認證) ---

def get_user_from_sheet(username: str) -> Optional[User]:
    """從 Google Sheet 中查找使用者"""
    try:
        user_records = user_worksheet.get_all_records()
        for record in user_records:
            if str(record.get('帳號')) == username:
                return User(
                    username=str(record.get('帳號')),
                    full_name=str(record.get('姓名')),
                    group=str(record.get('組別')),
                    hashed_password=str(record.get('雜湊密碼'))
                )
        return None
    except Exception as e:
        logging.error(f"從 Google Sheet 獲取使用者時出錯: {e}")
        return None

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """驗證密碼"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    """建立 JWT Token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """解析 Token 並獲取當前使用者"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="無法驗證憑證",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # 我們將使用者資訊 JSON 字串存在 'sub'
        user_info_str = payload.get("sub") 
        if user_info_str is None:
            raise credentials_exception
        
        user_info = json.loads(user_info_str)
        
        # 為了向下相容 User 模型，我們需要從 user_info 填充 User
        # 但對於 API 端點，我們只需要 full_name 和 group
        # 這裡我們返回一個 "部分" 的 User 物件，只包含我們需要的資訊
        return User(
            username="N/A", # 我們不需要在後續操作中再次查詢 username
            full_name=user_info.get("full_name"),
            group=user_info.get("group"),
            hashed_password="" # 不需要
        )

    except JWTError:
        raise credentials_exception
    except json.JSONDecodeError:
        logging.error("解析 Token 中的 'sub' 欄位失敗")
        raise credentials_exception


# --- API 端點 (認證) ---

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    使用帳號 (username) 和密碼 (password) 登入以獲取 Token。
    這是 OAuth2 標準端點，使用 x-www-form-urlencoded。
    """
    user = get_user_from_sheet(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="不正確的帳號或密碼",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 將使用者資訊打包成 JSON 字串存入 'sub'
    user_info_for_token = {
        "full_name": user.full_name,
        "group": user.group
    }
    user_info_str = json.dumps(user_info_for_token)
    
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_info_str}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    """
    獲取當前登入使用者的資訊。
    """
    # current_user 已經是從 Token 解碼出來的 User 物件
    return current_user


# --- 2. 任務系統 (Task System) ---

# Pydantic 模型 (任務相關)
class Task(BaseModel):
    row_number: int
    group: str
    title: str
    description: str
    status: str
    required_count: int
    assignees: List[str]
    is_full: bool
    
class TaskAssignRequest(BaseModel):
    row_number: int


# --- API 端點 (任務) ---

@app.get("/tasks", response_model=List[Task])
async def get_all_tasks(current_user: Annotated[User, Depends(get_current_user)]):
    """
    獲取所有任務列表。僅限登入使用者訪問。
    """
    try:
        # 重新獲取 worksheet 物件以確保連線是最新的
        sh = client.open_by_key(spreadsheet_id)
        worksheet = sh.worksheet(WORKSHEET_NAME)
        
        # 獲取標題行（A1:F1）
        header = worksheet.row_values(1)
        # 假設標題在 A 欄到 F 欄
        # A=組別, B=標題, C=描述, D=狀態, E=需求人數, F=已接取人員
        
        # 獲取第2行及之後的所有資料
        all_data_rows = worksheet.get_all_values()[1:] # 跳過標題行
        
        tasks = []
        for i, row in enumerate(all_data_rows):
            if not any(row): # 略過空行
                continue
                
            row_number = i + 2 # Google Sheet 的行號是從 1 開始，且我們跳過了標題
            
            try:
                # 確保欄位存在，否則給予預設值
                group = row[0] if len(row) > 0 else "N/A"
                title = row[1] if len(row) > 1 else "N/A"
                description = row[2] if len(row) > 2 else ""
                status = row[3] if len(row) > 3 else "待處理"
                
                # 處理需求人數
                try:
                    required_count = int(row[4]) if len(row) > 4 and row[4] else 1
                except ValueError:
                    required_count = 1 # 如果 E 欄不是數字，預設為 1
                
                # 處理已接取人員
                assignees_str = row[5] if len(row) > 5 else ""
                assignees = [name.strip() for name in assignees_str.split(';') if name.strip()]
                
                is_full = len(assignees) >= required_count
                
                tasks.append(Task(
                    row_number=row_number,
                    group=group,
                    title=title,
                    description=description,
                    status=status,
                    required_count=required_count,
                    assignees=assignees,
                    is_full=is_full
                ))
            except Exception as e:
                logging.error(f"解析 Google Sheet 第 {row_number} 行時出錯: {e} - 資料: {row}")

        return tasks

    except gspread.exceptions.APIError as e:
        logging.error(f"Gspread API 錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API 錯誤: {e}")
    except Exception as e:
        logging.error(f"獲取任務時發生未知錯誤: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"獲取任務時發生內部錯誤: {e}")


@app.post("/tasks/assign", response_model=Task)
async def assign_task_to_user(
    request: TaskAssignRequest,
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    將當前使用者指派到一個任務。
    """
    row_number = request.row_number
    user_full_name = current_user.full_name
    
    try:
        # 重新獲取 worksheet 物件
        sh = client.open_by_key(spreadsheet_id)
        worksheet = sh.worksheet(WORKSHEET_NAME)

        # 1. 讀取該行的資料
        try:
            row_data = worksheet.row_values(row_number)
            if not any(row_data):
                raise HTTPException(status_code=404, detail="找不到該任務 (行號不存在或為空)")
        except gspread.exceptions.APIError as e:
            if "RANGE_NOT_FOUND" in str(e):
                raise HTTPException(status_code=404, detail=f"找不到行號為 {row_number} 的任務")
            raise e

        # 2. 解析資料 (與 /tasks 端點邏輯一致)
        # A=組別(0), B=標題(1), C=描述(2), D=狀態(3), E=需求人數(4), F=已接取人員(5)
        
        # 處理需求人數
        try:
            required_count = int(row_data[4]) if len(row_data) > 4 and row_data[4] else 1
        except ValueError:
            required_count = 1
        
        # 處理已接取人員
        assignees_str = row_data[5] if len(row_data) > 5 else ""
        assignees = [name.strip() for name in assignees_str.split(';') if name.strip()]

        # 3. 檢查邏輯
        if user_full_name in assignees:
            raise HTTPException(status_code=400, detail="您已經接取過此任務")

        if len(assignees) >= required_count:
            raise HTTPException(status_code=400, detail="此任務人數已滿，無法接取")

        # 4. 更新資料
        assignees.append(user_full_name)
        new_assignees_str = "; ".join(assignees)
        
        # 檢查是否額滿並更新狀態
        new_status = row_data[3] if len(row_data) > 3 else "待處理" # 保持原狀態
        if len(assignees) >= required_count:
            new_status = "已額滿" # 如果接取後剛好額滿，更新狀態

        # 5. 寫回 Google Sheet
        # 更新 F 欄 (已接取人員) 和 D 欄 (狀態)
        worksheet.update_cell(row_number, 6, new_assignees_str) # F 欄 (第6欄)
        worksheet.update_cell(row_number, 4, new_status)        # D 欄 (第4欄)

        # 6. 返回更新後的任務狀態
        return Task(
            row_number=row_number,
            group=row_data[0],
            title=row_data[1],
            description=row_data[2],
            status=new_status,
            required_count=required_count,
            assignees=assignees,
            is_full=True if new_status == "已額滿" else False
        )

    except gspread.exceptions.APIError as e:
        logging.error(f"Gspread API 錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API 錯誤: {e}")
    except Exception as e:
        logging.error(f"接取任務時發生未知錯誤: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"接取任務時發生內部錯誤: {e}")


# --- 3. 託管靜態檔案 (HTML/CSS/JS) ---

@app.get("/")
async def read_root():
    """
    提供前端 index.html 檔案。
    """
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
        raise HTTPException(status_code=500, detail="無法讀取介面檔案")

 --- (可選) 密碼產生器，僅供管理員使用 ---
 註解掉此端點，避免安全風險
 @app.get("/hash_password")
 async def hash_password(password: str):
     """
     (開發用) 產生密碼雜湊值。
     """
     return {"hashed_password": pwd_context.hash(password)}
