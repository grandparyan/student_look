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
# from passlib.context import CryptContext # <-- 移除 passlib
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated 

from oauth2client.service_account import ServiceAccountCredentials

# --- 日誌設定 ---
# 設置日誌級別為 INFO
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="設備報修與任務系統 API",
    description="提供報修提交、任務查看與接取功能"
)

# --- CORS 中間件 ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 允許所有來源
    allow_credentials=True,
    allow_methods=["*"], # 允許所有方法
    allow_headers=["*"], # 允許所有標頭
)

# --- Google Sheets 設定 ---
spreadsheet_id = "1IHyA7aRxGJekm31KIbuORpg4-dVY8XTOEbU6p8vK3y4"
WORKSHEET_NAME = "設備報修"
USER_WORKSHEET_NAME = "使用者名單" # <-- 新增：使用者工作表名稱

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
    # 在生產環境中，您可能希望應用程式在此處失敗
    creds = None
    client = None
    spreadsheet = None
    worksheet = None
    user_worksheet = None # <-- 新增
else:
    try:
        creds_json = json.loads(creds_json_str)
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_json, scope)
        client = gspread.authorize(creds)
        spreadsheet = client.open_by_key(spreadsheet_id)
        
        # 載入 "設備報修" 工作表
        try:
            worksheet = spreadsheet.worksheet(WORKSHEET_NAME)
        except gspread.WorksheetNotFound:
            logging.error(f"找不到工作表：{WORKSHEET_NAME}。")
            worksheet = None
        except Exception as e:
            logging.error(f"載入 {WORKSHEET_NAME} 工作表時出錯: {e}")
            worksheet = None

        # --- 新增：載入 "使用者名單" 工作表 ---
        try:
            user_worksheet = spreadsheet.worksheet(USER_WORKSHEET_NAME)
        except gspread.WorksheetNotFound:
            logging.error(f"找不到工作表：{USER_WORKSHEET_NAME}。")
            user_worksheet = None
        except Exception as e:
            logging.error(f"載入 {USER_WORKSHEET_NAME} 工作表時出錯: {e}")
            user_worksheet = None
        # --- 結束新增 ---

    except json.JSONDecodeError:
        logging.error("錯誤：'GOOGLE_CREDENTIALS_JSON' 環境變數不是有效的 JSON。")
        client = None
        spreadsheet = None
        worksheet = None
        user_worksheet = None # <-- 新增
    except Exception as e:
        logging.error(f"Google Sheets 初始化失敗: {e}")
        client = None
        spreadsheet = None
        worksheet = None
        user_worksheet = None # <-- 新增

# --- 1. Pydantic 資料模型 ---

class Task(BaseModel):
    """
    任務的資料模型，用於 API 回應。
    """
    row_id: int
    task_id: str
    location: str
    description: str
    status: str
    required_count: int
    current_count: int
    assignees: List[str]

class TaskTakeRequest(BaseModel):
    """
    接取任務的請求模型。
    """
    row_id: int

class User(BaseModel):
    """
    使用者的基本資料模型。
    """
    username: str
    role: str

class UserInDB(User):
    """
    儲存在資料庫（或 Google Sheet）中的使用者模型，包含明文密碼。
    """
    # --- 修改：不再使用雜湊密碼 ---
    password: str 

# --- 2. 安全性與認證 (JWT) ---

# 從環境變數讀取密鑰，如果未設定則使用預設值（不推薦用於生產）
SECRET_KEY = os.environ.get("SECRET_KEY", "your-fallback-secret-key-for-development")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # Token 效期 30 分鐘

# --- 移除密碼雜湊 ---
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 密碼流程
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- 移除 fake_users_db ---
# (假資料庫已被移除)

# --- 3. 認證輔助函式 ---

# --- 移除 verify_password ---
# (不再需要驗證雜湊)

# --- 修改：從 Google Sheet 獲取使用者 (使用明文密碼) ---
def get_user_from_sheet(username: str) -> Optional[UserInDB]:
    """
    從 Google Sheet (使用者名單) 獲取使用者資料。
    """
    if user_worksheet is None:
        logging.error("使用者工作表 'user_worksheet' 未被正確初始化。")
        return None
    
    try:
        # 假設工作表包含 '帳號', '密碼', '角色' 欄位
        # get_all_records() 會將第一列作為鍵 (key)
        all_users = user_worksheet.get_all_records()
        
        for user_data in all_users:
            if user_data.get('帳號') == username:
                # 確保必要欄位存在
                # --- 修改：檢查 '密碼' 而不是 '雜湊密碼' ---
                if '密碼' not in user_data or '角色' not in user_data:
                    logging.warning(f"使用者 '{username}' 在 Sheet 中資料不完整（缺少 '密碼' 或 '角色'）。")
                    continue
                    
                return UserInDB(
                    username=user_data.get('帳號'),
                    password=user_data.get('密碼'), # <-- 直接獲取明文密碼
                    role=user_data.get('角色')
                )
        
        # 找不到使用者
        logging.info(f"在 Sheet 中找不到使用者: {username}")
        return None
    
    except Exception as e:
        logging.error(f"從 Google Sheet 獲取使用者 '{username}' 時出錯: {e}", exc_info=True)
        return None
# --- 結束修改 ---


def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    """
    建立 JWT access token。
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """
    解析 token，獲取當前使用者。
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
    
    # --- 修改：使用 get_user_from_sheet ---
    user_data = get_user_from_sheet(username=username)
    if user_data is None:
        raise credentials_exception
    
    # 返回 User 模型，不包含密碼
    return User(username=user_data.username, role=user_data.role)
    # --- 結束修改 ---

# --- 4. API 端點 (Endpoints) ---

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """
    使用者登入端點，驗證成功後返回 access token。
    """
    # --- 修改：使用 get_user_from_sheet (明文密碼) ---
    user = get_user_from_sheet(form_data.username)
    
    # 檢查使用者是否存在，以及密碼是否正確
    # --- 修改：直接比對明文密碼 ---
    if not user or form_data.password != user.password:
        logging.warning(f"登入失敗: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="不正確的帳號或密碼",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # --- 結束修改 ---
    
    # 建立 access token
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, 
        expires_delta=access_token_expires
    )
    
    logging.info(f"使用者登入成功: {user.username}")
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}


@app.get("/users/me", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    獲取當前登入使用者的資訊。
    """
    return current_user


@app.get("/tasks", response_model=List[Task])
async def get_tasks(
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    獲取所有「待處理」和「處理中」的任務列表。
    """
    if worksheet is None:
        logging.error("任務工作表 'worksheet' 未初始化，無法獲取任務。")
        raise HTTPException(status_code=500, detail="無法連接到任務資料庫")

    try:
        # 獲取所有資料 (包含標頭)
        all_data = worksheet.get_all_values()
        
        if not all_data:
            return [] # 如果工作表為空，返回空列表

        # 獲取標頭 (第一列)
        headers = all_data[0]
        # 獲取資料 (從第二列開始)
        records = all_data[1:]
        
        tasks = []
        
        # 尋找欄位索引
        # 使用 .get(header.strip()) 來避免潛在的空格問題
        header_map = {header.strip(): i for i, header in enumerate(headers)}
        
        try:
            idx_status = header_map['狀態']
            idx_id = header_map['任務ID']
            idx_loc = header_map['地點']
            idx_desc = header_map['狀況描述']
            idx_req = header_map['需求人數']
            idx_assign = header_map['指派人員']
        except KeyError as e:
            logging.error(f"工作表缺少必要欄位: {e}")
            raise HTTPException(status_code=5.00, detail=f"Google Sheet 欄位缺失: {e}")

        # 遍歷每一行資料 (row_index 從 2 開始，因為 1 是標頭)
        for i, row_data in enumerate(records):
            row_id = i + 2 # Google Sheet 的行號 (1-based index)
            
            # 安全性檢查：確保 row_data 夠長
            if len(row_data) <= idx_status:
                logging.warning(f"第 {row_id} 行資料不完整，跳過。")
                continue

            status = row_data[idx_status].strip()

            # 只顯示「待處理」或「處理中」的任務
            if status in ["待處理", "處理中"]:
                
                # 解析需求人數
                try:
                    required_count_str = row_data[idx_req] if len(row_data) > idx_req else "1"
                    required_count = int(required_count_str) if required_count_str else 1
                except (ValueError, IndexError):
                    required_count = 1 # 如果欄位為空或格式錯誤，預設為 1

                # 解析指派人員
                assignees_str = row_data[idx_assign] if len(row_data) > idx_assign else ""
                if assignees_str:
                    assignees = [name.strip() for name in assignees_str.split(',')]
                else:
                    assignees = []
                
                # 確保所有欄位都存在且在索引範圍內
                if len(row_data) > max(idx_id, idx_loc, idx_desc):
                    task = Task(
                        row_id=row_id,
                        task_id=row_data[idx_id],
                        location=row_data[idx_loc],
                        description=row_data[idx_desc],
                        status=status,
                        required_count=required_count,
                        current_count=len(assignees),
                        assignees=assignees
                    )
                    tasks.append(task)
                else:
                    logging.warning(f"第 {row_id} 行資料欄位不足，跳過。")
        
        return tasks

    except gspread.exceptions.APIError as e:
        logging.error(f"Gspread API 錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API 錯誤: {e}")
    except Exception as e:
        logging.error(f"獲取任務時發生未知錯誤: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"獲取任務時發生內部錯誤: {e}")


@app.post("/tasks/take")
async def take_task(
    request: TaskTakeRequest,
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    學生接取一個任務。
    """
    if worksheet is None:
        logging.error("任務工作表 'worksheet' 未初始化，無法接取任務。")
        raise HTTPException(status_code=500, detail="無法連接到任務資料庫")

    row_id = request.row_id
    username = current_user.username

    try:
        # 1. 獲取該行的所有資料
        # (注意: gspread.values_get 似乎沒有直接按行號獲取的方法，
        # 我們先獲取整行，然後再找欄位索引)
        
        # 獲取標頭 (第一列) 以找到 '狀態', '指派人員', '需求人數' 的欄位索引
        headers = worksheet.row_values(1)
        header_map = {header.strip(): i for i, header in enumerate(headers)}

        try:
            col_idx_status = header_map['狀態'] + 1 # gspread col 是 1-based
            col_idx_assignees = header_map['指派人員'] + 1
            col_idx_required = header_map['需求人數'] + 1
        except KeyError as e:
            logging.error(f"工作表缺少必要欄位: {e}")
            raise HTTPException(status_code=500, detail=f"Google Sheet 欄位缺失: {e}")

        # 獲取特定行的資料
        row_data = worksheet.row_values(row_id)
        
        # 安全性檢查：確保 row_data 夠長
        if len(row_data) <= max(col_idx_status - 1, col_idx_assignees - 1, col_idx_required - 1):
            logging.error(f"嘗試接取任務失敗：第 {row_id} 行資料不完整。")
            raise HTTPException(status_code=404, detail=f"找不到行號為 {row_id} 的任務資料。")

        current_status = row_data[col_idx_status - 1].strip()
        assignees_str = row_data[col_idx_assignees - 1]
        required_str = row_data[col_idx_required - 1]

        # 2. 解析指派人員和需求人數
        if assignees_str:
            assignees = [name.strip() for name in assignees_str.split(',')]
        else:
            assignees = []
        
        try:
            required_count = int(required_str) if required_str else 1
        except (ValueError, IndexError):
            required_count = 1 # 預設為 1

        # 3. 檢查業務邏輯
        if current_status == "已完成":
            raise HTTPException(status_code=400, detail="任務已完成，無法接取。")

        if username in assignees:
            raise HTTPException(status_code=400, detail="您已經接取過此任務。")

        if len(assignees) >= required_count:
            # 雖然前端應該會隱藏，但後端還是要擋
            raise HTTPException(status_code=400, detail="任務人數已滿，無法接取。")

        # 4. 更新資料
        assignees.append(username)
        new_assignees_str = ", ".join(assignees)
        
        # 檢查是否達到人數上限
        new_status = "處理中"
        if len(assignees) == required_count:
            new_status = "處理中 (滿)" # 或者您可以自訂狀態
        
        # 5. 將更新寫回 Google Sheet
        # (批次更新狀態和指派人員)
        worksheet.update_cell(row_id, col_idx_status, new_status)
        worksheet.update_cell(row_id, col_idx_assignees, new_assignees_str)
        
        logging.info(f"使用者 {username} 成功接取任務 (Row {row_id})。")

        # 6. 返回更新後的任務狀態
        return {
            "message": "任務接取成功！",
            "row_id": row_id,
            "new_status": new_status,
            "new_assignees": assignees,
            "current_count": len(assignees)
        }

    except gspread.exceptions.CellNotFound:
        raise HTTPException(status_code=404, detail=f"找不到行號為 {row_id} 的任務。")
    except gspread.exceptions.APIError as e:
        logging.error(f"Gspread API 錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API 錯誤: {e}")
    except Exception as e:
        logging.error(f"接取任務時發生未知錯誤 (Row {row_id}): {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"接取任務時發生內部錯誤: {e}")


# 5. 託管靜態檔案 (HTML)
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
        return JSONResponse(
            content={"error": "讀取介面檔案時發生伺服器內部錯誤。"},
            status_code=500
        )

