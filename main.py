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
    'https://www.googleapis.com/auth/spreadsheets',
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive"
]

# 從環境變數讀取 Google 憑證 (Heroku/Render 推薦)
creds_json_str = os.environ.get('GOOGLE_CREDENTIALS_JSON')

if not creds_json_str:
    logging.error("錯誤：未設定 'GOOGLE_CREDENTIALS_JSON' 環境變數。")
    # 在本地開發時，可以選擇從檔案讀取
    # try:
    #     with open('credentials.json', 'r') as f:
    #         creds_json = json.load(f)
    #     logging.info("本地開發：從 credentials.json 載入憑證。")
    # except FileNotFoundError:
    #     logging.error("本地開發錯誤：找不到 credentials.json 檔案。")
    #     creds_json = {} # 避免啟動失敗
    creds_json = {}
else:
    try:
        creds_json = json.loads(creds_json_str)
        logging.info("成功從環境變數載入 Google 憑證。")
    except json.JSONDecodeError as e:
        logging.error(f"解析 GOOGLE_CREDENTIALS_JSON 失敗: {e}")
        creds_json = {}

try:
    creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_json, scope)
    client = gspread.authorize(creds)
    sheet = client.open_by_key(spreadsheet_id)
    logging.info("Google Sheets 連線成功。")
except Exception as e:
    logging.error(f"Google Sheets 連線失敗: {e}")
    # 讓應用程式繼續執行，但在 API 呼叫時會失敗
    client = None
    sheet = None

def get_sheet():
    """ 依賴項：獲取 Google Sheet 工作表 """
    global client, sheet, creds, creds_json, scope, spreadsheet_id, WORKSHEET_NAME
    
    if not client or not sheet:
        logging.warning("Gspread client 未初始化，嘗試重新連線...")
        try:
            if not creds_json:
                raise Exception("缺少 Google 憑證資料")
            creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_json, scope)
            client = gspread.authorize(creds)
            sheet = client.open_by_key(spreadsheet_id)
            logging.info("Gspread 重新連線成功。")
        except Exception as e:
            logging.error(f"Gspread 重新連線失敗: {e}")
            raise HTTPException(status_code=503, detail=f"無法連線至 Google Sheets: {e}")

    try:
        # 檢查憑證是否過期，如果過期則刷新
        if creds.access_token_expired:
            logging.info("Google 憑證已過期，正在刷新...")
            client.login()
        
        current_sheet = sheet.worksheet(WORKSHEET_NAME)
        return current_sheet
    except gspread.exceptions.WorksheetNotFound:
        logging.error(f"找不到工作表: {WORKSHEET_NAME}")
        raise HTTPException(status_code=500, detail=f"找不到工作表: {WORKSHEET_NAME}")
    except Exception as e:
        logging.error(f"獲取工作表時發生錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"獲取工作表時發生錯誤: {e}")


# =======================================================================
# 1. 靜態檔案服務 (HTML/CSS/JS)
# =======================================================================

@app.get("/")
async def read_index():
    """ 提供 index.html """
    return FileResponse('index.html')

# =======================================================================
# 2. 報修提交 API (公開)
# =======================================================================
class Report(BaseModel):
    reporter: str
    location: str
    description: str

@app.post("/submit_report")
async def submit_report(report: Report, current_sheet: gspread.Worksheet = Depends(get_sheet)):
    """
    接收設備報修表單提交，並將其寫入 Google Sheet。
    """
    try:
        # A 欄：時間戳記
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # B 欄：報修人
        reporter = report.reporter
        # C 欄：地點
        location = report.location
        # D 欄：狀況描述
        description = report.description
        # E 欄：狀態 (預設為 "待處理")
        status = "待處理"
        # F 欄：所需人數 (預設為 1)
        required_count = 1
        
        new_row = [timestamp, reporter, location, description, status, required_count]
        
        # 插入到第二行 (標題行之後)
        current_sheet.insert_row(new_row, 2) 
        
        logging.info(f"新增報修: {new_row}")
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "報修提交成功！", "data": new_row}
        )
    except gspread.exceptions.APIError as e:
        logging.error(f"Gspread API 錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API 錯誤: {e.s}")
    except Exception as e:
        logging.error(f"提交報修時發生未知錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"伺服器內部錯誤: {e}")

# =======================================================================
# 3. 認證系統 (JWT)
# =======================================================================

# --- 設定 ---
SECRET_KEY = os.environ.get("SECRET_KEY", "a_very_secret_key_that_should_be_changed")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8 # 8 小時

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- 資料模型 ---
class User(BaseModel):
    username: str
    full_name: str
    disabled: bool = False
    
class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# --- 模擬資料庫 ---
# 在真實應用中，這裡應該是查詢資料庫
# 確保密碼是使用 bcrypt 加密的
# (範例密碼: "student123")
fake_users_db = {
    "s1": {
        "username": "s1",
        "full_name": "同學A",
        "hashed_password": "$2b$12$E.Gq9mXbNKYGvPId.UpiyeaS2j0NlI.IuCUlYxM2P62M1n/PV5y.q",
        "disabled": False,
    },
    "s2": {
        "username": "s2",
        "full_name": "同學B",
        "hashed_password": "$2b$12$E.Gq9mXbNKYGvPId.UpiyeaS2j0NlI.IuCUlYxM2P62M1n/PV5y.q",
        "disabled": False,
    },
    "s3": {
        "username": "s3",
        "full_name": "同學C",
        "hashed_password": "$2b$12$E.Gq9mXbNKYGvPId.UpiyeaS2j0NlI.IuCUlYxM2P62M1n/PV5y.q",
        "disabled": False,
    },
    "s4": {
        "username": "s4",
        "full_name": "同學D",
        "hashed_password": "$2b$12$E.Gq9mXbNKYGvPId.UpiyeaS2j0NlI.IuCUlYxM2P62M1n/PV5y.q",
        "disabled": False,
    },
    "s5": {
        "username": "s5",
        "full_name": "同學E",
        "hashed_password": "$2b$12$E.Gq9mXbNKYGvPId.UpiyeaS2j0NlI.IuCUlYxM2P62M1n/PV5y.q",
        "disabled": False,
    },
}

# --- 輔助函式 ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- 依賴項：獲取當前使用者 ---
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

# --- 登入 API ---
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = get_user(fake_users_db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
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


# =======================================================================
# 4. 任務系統 API (需要認證)
# =======================================================================

# ！！！ 新增的 API 端點 ！！！
@app.get("/users/me", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    """
    獲取當前已認證使用者的詳細資訊 (用於前端顯示 "你好, ...")
    """
    return current_user
# ！！！ 以上是新增的程式碼 ！！！


class Task(BaseModel):
    row_number: int       # 工作表中的行號 (用於更新)
    timestamp: str        # A 欄
    reporter: str         # B 欄
    location: str         # C 欄
    description: str      # D 欄
    status: str           # E 欄
    required_count: int   # F 欄
    current_count: int    # G-K 欄位計算
    assignees: List[str]  # G-K 欄位

class TakeTaskRequest(BaseModel):
    row_number: int

# --- 讀取任務列表 ---
@app.get("/tasks", response_model=List[Task])
async def get_tasks(
    current_user: Annotated[User, Depends(get_current_active_user)],
    current_sheet: gspread.Worksheet = Depends(get_sheet)
):
    """
    獲取所有狀態為 "待處理" 的任務列表
    """
    try:
        all_data = current_sheet.get_all_values()
        tasks = []
        
        if not all_data:
            return []
            
        header = all_data[0]
        # 欄位 G 到 K (索引 6 到 10) 是處理人員
        assignee_cols_indices = list(range(6, 11)) # 索引 G(6), H(7), I(8), J(9), K(10)

        # 從第二行開始 (索引 1)
        for i, row in enumerate(all_data[1:]):
            row_number = i + 2 # Google Sheet 行號是 1-based，且跳過標題行
            
            # 確保行資料足夠長
            if len(row) < 6: # 至少要有 A-F 欄
                continue

            status = row[4].strip() # E 欄 (狀態)
            
            # 我們只關心 "待處理" 的任務
            if status == "待處理":
                try:
                    required_count_str = row[5].strip() # F 欄 (所需人數)
                    required_count = int(required_count_str) if required_count_str.isdigit() else 1
                except ValueError:
                    required_count = 1
                
                assignees = []
                for col_index in assignee_cols_indices:
                    if col_index < len(row) and row[col_index].strip():
                        assignees.append(row[col_index].strip())
                
                current_count = len(assignees)
                
                # 檢查是否已滿員 (但狀態仍是待處理) -> 系統自我修復
                if current_count >= required_count:
                    current_sheet.update_cell(row_number, 5, "處理中") # 更新 E 欄
                    status = "處理中"
                    # 不在列表顯示
                    continue
                
                # 檢查當前使用者是否已在列表中
                if current_user.full_name in assignees:
                    # 使用者已經接取此任務，不在列表顯示
                    continue

                task = Task(
                    row_number=row_number,
                    timestamp=row[0],
                    reporter=row[1],
                    location=row[2],
                    description=row[3],
                    status=status,
                    required_count=required_count,
                    current_count=current_count,
                    assignees=assignees
                )
                tasks.append(task)
                
        return tasks

    except gspread.exceptions.APIError as e:
        logging.error(f"Gspread API 錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"Google Sheets API 錯誤: {e.s}")
    except Exception as e:
        logging.error(f"獲取任務時發生未知錯誤: {e}")
        raise HTTPException(status_code=500, detail=f"伺服器內部錯誤: {e}")


# --- 接取任務 ---
@app.post("/take_task", response_model=Task)
async def take_task(
    request: TakeTaskRequest,
    current_user: Annotated[User, Depends(get_current_active_user)],
    current_sheet: gspread.Worksheet = Depends(get_sheet)
):
    """
    允許使用者接取一個 "待處理" 的任務
    """
    row_number = request.row_number
    
    try:
        # 1. 獲取該行的最新資料
        row_data = current_sheet.row_values(row_number)
        
        if not row_data:
            raise HTTPException(status_code=404, detail="找不到該任務 (行號錯誤)")
            
        # 2. 檢查任務狀態
        status = row_data[4].strip()
        if status != "待處理":
            raise HTTPException(status_code=400, detail=f"此任務狀態為 '{status}'，無法接取。")

        # 3. 獲取處理人員欄位 (G-K, 索引 6-10)
        assignee_cols_indices = list(range(6, 11)) # G(6), H(7), I(8), J(9), K(10)
        assignees = []
        first_empty_col = -1
        
        for col_index in assignee_cols_indices:
            if col_index < len(row_data):
                assignee_name = row_data[col_index].strip()
                if assignee_name:
                    # 檢查是否重複接取
                    if assignee_name == current_user.full_name:
                        raise HTTPException(status_code=400, detail="您已經接取過此任務。")
                    assignees.append(assignee_name)
                elif first_empty_col == -1:
                    first_empty_col = col_index
            elif first_empty_col == -1: # 如果行資料不夠長
                 first_empty_col = col_index
        
        # 4. 檢查是否已滿員
        try:
            required_count_str = row_data[5].strip() # F 欄
            required_count = int(required_count_str) if required_count_str.isdigit() else 1
        except ValueError:
            required_count = 1

        if len(assignees) >= required_count:
            # 狀態應為 "處理中"，但 gspread 快取可能延遲
            current_sheet.update_cell(row_number, 5, "處理中") # 更新 E 欄
            raise HTTPException(status_code=400, detail="此任務剛剛已額滿。")

        # 5. 將使用者名稱填入第一個空格
        if first_empty_col == -1:
             # 理論上不會發生，因為上一步已檢查滿員
             raise HTTPException(status_code=500, detail="找不到可填入的欄位，但任務未滿員。")

        target_col = first_empty_col + 1 # 轉換為 1-based 索引
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
# Uvicorn/Gunicorn 啟動設定
# =======================================================================
if __name__ == "__main__":
    import uvicorn
    # 本地開發時使用
    uvicorn.run(
        "main:app", 
        host="127.0.0.1", 
        port=8000, 
        reload=True
    )
else:
    # 當使用 Gunicorn 部署時 (例如在 Render 上)
    # Gunicorn 會需要這個來指定工作者類別
    # 指令: gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker
    pass
