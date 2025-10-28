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
    client = None
    sheet = None

def get_sheet():
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


@app.get("/")
async def read_index():
    return FileResponse('index.html')

class Report(BaseModel):
    reporter: str
    location: str
    description: str

@app.post("/submit_report")
async def submit_report(report: Report, current_sheet: gspread.Worksheet = Depends(get_sheet)):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        reporter = report.reporter
        location = report.location
        description = report.description
        status = "待處理"
        required_count = 1
        
        new_row = [timestamp, reporter, location, description, status, required_count]
        
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

SECRET_KEY = os.environ.get("SECRET_KEY", "a_very_secret_key_that_should_be_changed")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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

# --- 模擬資料庫 (已加上註解) ---
# 這裡是您應用程式的「使用者資料庫」。
# 警告：這只適用於範例。在真實產品中，您應該使用真實的資料庫（例如 PostgreSQL, MySQL）。
#
# 關於密碼：
# "hashed_password" 欄位中儲存的是「雜湊」過的密碼，而不是原始密碼。
# 這是基於安全的考量。
#
# 這組雜湊值 ("$2b$12$E.Gq...") 對應的原始密碼是： "student123"
#
fake_users_db = {
    "s1": { # 這是第一位使用者
        "username": "s1", # 登入時使用的「帳號」
        "full_name": "同學A", # 登入後，畫面上顯示的「全名」
        "hashed_password": "$2b$12$E.Gq9mXbNKYGvPId.UpiyeaS2j0NlI.IuCUlYxM2P62M1n/PV5y.q", # "student123" 的 bcrypt 雜湊值
        "disabled": False, # 帳號是否被停用
    },
    "s2": { # 這是第二位使用者
        "username": "s2", # 登入時使用的「帳號」
        "full_name": "同學B", # 登入後，畫面上顯示的「全名」
        "hashed_password": "$2b$12$E.Gq9mXbNKYGvPId.UpiyeaS2j0NlI.IuCUlYxM2P62M1n/PV5y.q", # "student123" 的 bcrypt 雜湊值
        "disabled": False,
    },
    "s3": { # 這是第三位使用者
        "username": "s3",
        "full_name": "同學C",
        "hashed_password": "$2b$12$E.Gq9mXbNKYGvPId.UpiyeaS2j0NlI.IuCUlYxM2P62M1n/PV5y.q", # "student123" 的 bcrypt 雜湊值
        "disabled": False,
    },
    "s4": { # 這是第四位使用者
        "username": "s4",
        "full_name": "同學D",
        "hashed_password": "$2b$12$E.Gq9mXbNKYGvPId.UpiyeaS2j0NlI.IuCUlYxM2P62M1n/PV5y.q", # "student123" 的 bcrypt 雜湊值
        "disabled": False,
    },
    "s5": { # 這是第五位使用者
        "username": "s5",
        "full_name": "同學E",
        "hashed_password": "$2b$12$E.Gq9mXbNKYGvPId.UpiyeaS2j0NlI.IuCUlYxM2P62M1n/PV5y.q", # "student123" 的 bcrypt 雜湊值
        "disabled": False,
    },
}
# --- 註解結束 ---

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


@app.get("/users/me", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


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

class TakeTaskRequest(BaseModel):
    row_number: int

@app.get("/tasks", response_model=List[Task])
async def get_tasks(
    current_user: Annotated[User, Depends(get_current_active_user)],
    current_sheet: gspread.Worksheet = Depends(get_sheet)
):
    try:
        all_data = current_sheet.get_all_values()
        tasks = []
        
        if not all_data:
            return []
            
        header = all_data[0]
        assignee_cols_indices = list(range(6, 11)) 

        for i, row in enumerate(all_data[1:]):
            row_number = i + 2 
            
            if len(row) < 6: 
                continue

            status = row[4].strip() 
            
            if status == "待處理":
                try:
                    required_count_str = row[5].strip() 
                    required_count = int(required_count_str) if required_count_str.isdigit() else 1
                except ValueError:
                    required_count = 1
                
                assignees = []
                for col_index in assignee_cols_indices:
                    if col_index < len(row) and row[col_index].strip():
                        assignees.append(row[col_index].strip())
                
                current_count = len(assignees)
                
                if current_count >= required_count:
                    current_sheet.update_cell(row_number, 5, "處理中") 
                    status = "處理中"
                    continue
                
                if current_user.full_name in assignees:
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


@app.post("/take_task", response_model=Task)
async def take_task(
    request: TakeTaskRequest,
    current_user: Annotated[User, Depends(get_current_active_user)],
    current_sheet: gspread.Worksheet = Depends(get_sheet)
):
    row_number = request.row_number
    
    try:
        row_data = current_sheet.row_values(row_number)
        
        if not row_data:
            raise HTTPException(status_code=404, detail="找不到該任務 (行號錯誤)")
            
        status = row_data[4].strip()
        if status != "待處理":
            raise HTTPException(status_code=400, detail=f"此任務狀態為 '{status}'，無法接取。")

        assignee_cols_indices = list(range(6, 11)) 
        assignees = []
        first_empty_col = -1
        
        for col_index in assignee_cols_indices:
            if col_index < len(row_data):
                assignee_name = row_data[col_index].strip()
                if assignee_name:
                    if assignee_name == current_user.full_name:
                        raise HTTPException(status_code=400, detail="您已經接取過此任務。")
                    assignees.append(assignee_name)
                elif first_empty_col == -1:
                    first_empty_col = col_index
            elif first_empty_col == -1: 
                 first_empty_col = col_index
        
        try:
            required_count_str = row_data[5].strip() 
            required_count = int(required_count_str) if required_count_str.isdigit() else 1
        except ValueError:
            required_count = 1

        if len(assignees) >= required_count:
            current_sheet.update_cell(row_number, 5, "處理中") 
            raise HTTPException(status_code=400, detail="此任務剛剛已額滿。")

        if first_empty_col == -1:
             raise HTTPException(status_code=500, detail="找不到可填入的欄位，但任務未滿員。")

        target_col = first_empty_col + 1 
        current_sheet.update_cell(row_number, target_col, current_user.full_name)
        
        if (len(assignees) + 1) == required_count:
            current_sheet.update_cell(row_number, 5, "處理中") 
            new_status = "處理中"
        else:
            new_status = "待處理"
        
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app", 
        host="127.0.0.1", 
        port=8000, 
        reload=True
    )
else:
    pass

