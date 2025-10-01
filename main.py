import os
import json
import gspread
import logging
import datetime
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from oauth2client.service_account import ServiceAccountCredentials

# 設定日誌等級，方便在 Render 上除錯
logging.basicConfig(level=logging.INFO)

# ----------------------------------------------------
# 設定 Google Sheets 參數
# 請確保您的服務帳號有此試算表的「編輯者」權限
# 請注意：此處的 spreadsheet_id 仍沿用您提供的 ID
spreadsheet_id = "1IHyA7aRxGJekm31KIbuORpg4-dVY8XTOEbU6p8vK3y4"
WORKSHEET_NAME = "設備報修" 
STATUS_COLUMN_INDEX = 5 # 狀態欄位在 Sheets 中的索引 (E 欄是第 5 欄)

# Google Sheets API 範圍
scope = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive",
]

# 全域變數用於儲存 gspread client 和工作表
client = None
sheet = None

def initialize_gspread():
    """初始化 Google Sheets 連線。"""
    global client, sheet
    
    # 避免重複初始化
    if client and sheet:
        return True 

    try:
        creds_json = os.environ.get('SERVICE_ACCOUNT_CREDENTIALS')
        if not creds_json:
            logging.error("致命錯誤：找不到 SERVICE_ACCOUNT_CREDENTIALS 環境變數。")
            return False

        # 嘗試解析 JSON 憑證
        creds_dict = json.loads(creds_json)
        creds = ServiceAccountCredentials.from_json_keyfile_dict(
            creds_dict,
            scope
        )
        client = gspread.authorize(creds)
        
        # 嘗試打開試算表並選取工作表
        sheet = client.open_by_key(spreadsheet_id).worksheet(WORKSHEET_NAME)
        logging.info(f"成功連線到 Google Sheets。工作表名稱: {WORKSHEET_NAME}")
        return True

    except gspread.exceptions.WorksheetNotFound:
        logging.error(f"嚴重錯誤：找不到名稱為「{WORKSHEET_NAME}」的工作表。請檢查名稱或試算表 ID。")
        return False
    except gspread.exceptions.SpreadsheetNotFound:
        logging.error(f"嚴重錯誤：找不到試算表ID為「{spreadsheet_id}」的試算表。請檢查 ID 或服務帳號權限。")
        return False
    except Exception as e:
        logging.error(f"連線到 Google Sheets 時發生未知錯誤: {e}")
        return False

# ----------------------------------------------------
# Flask 應用程式設定
app = Flask(__name__)
# 啟用 CORS
CORS(app) 

# 在應用程式第一次請求前先初始化 gspread
with app.app_context():
    initialize_gspread()

# ----------------------------------------------------
# 路由定義

# 1. 根路由：用於顯示 HTML 報修表單 (學生填寫介面)
@app.route('/')
def home():
    """回傳學生填寫的報修表單 HTML 內容。"""
    # 保持您原有的 HTML 內容，此處省略以保持簡潔
    html_content = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>設備報修系統 - 學生報修</title>
    <!-- 載入 Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #f4f7f9; }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">

    <div class="w-full max-w-lg bg-white p-8 md:p-10 rounded-xl shadow-2xl">
        
        <!-- 標題區塊 -->
        <div class="text-center mb-8">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 text-indigo-600 mx-auto mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37a1.724 1.724 0 002.572-1.065z" />
                <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            <h1 class="text-3xl font-bold text-gray-900">設備報修單 (學生填寫)</h1>
            <p class="text-gray-500 mt-1">請填寫詳細資訊，以便我們快速處理。</p>
            <p class="text-xs mt-3 text-indigo-500 hover:underline"><a href="/teacher">點此前往教師/管理員介面</a></p>
        </div>

        <!-- 訊息顯示區塊 (取代 alert) -->
        <div id="message-box" class="hidden mb-6 p-3 text-center rounded-lg font-medium transition-all duration-300"></div>

        <!-- 表單開始 -->
        <form id="repairForm" class="space-y-6">
            
            <!-- 報修人姓名 (reporterName) -->
            <div>
                <label for="reporter_name_input" class="block text-sm font-medium text-gray-700 mb-1">報修人姓名 (必填)</label>
                <input type="text" id="reporter_name_input" required class="w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-indigo-500 focus:border-indigo-500">
            </div>

            <!-- 設備位置 (deviceLocation) -->
            <div>
                <label for="location_input" class="block text-sm font-medium text-gray-700 mb-1">設備位置 / 教室名稱 (必填)</label>
                <input type="text" id="location_input" required class="w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-indigo-500 focus:border-indigo-500">
            </div>

            <!-- 問題描述 (problemDescription) -->
            <div>
                <label for="problem_input" class="block text-sm font-medium text-gray-700 mb-1">問題詳細描述 (必填)</label>
                <textarea id="problem_input" rows="4" required class="w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-indigo-500 focus:border-indigo-500 resize-none"></textarea>
            </div>
            
            <!-- 提交按鈕 -->
            <div>
                <button type="submit" id="submit-button" class="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-md text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition duration-150 ease-in-out">
                    送出報修單
                </button>
            </div>
        </form>
        <!-- 表單結束 -->
    </div>

    <script>
        // 注意: 這裡的 API_URL 應該設定為您的 Render 服務網址
        const API_URL = ""; // 保持為空，讓 Canvas 環境自動設定
        const SUBMIT_ENDPOINT = '/submit_report';

        const form = document.getElementById('repairForm');
        const submitButton = document.getElementById('submit-button');
        const messageBox = document.getElementById('message-box');

        // 顯示訊息函式（取代 alert）
        function showMessage(message, isSuccess) {
            messageBox.textContent = message;
            messageBox.classList.remove('hidden', 'bg-red-100', 'text-red-800', 'bg-green-100', 'text-green-800');
            
            if (isSuccess) {
                messageBox.classList.add('bg-green-100', 'text-green-800');
            } else {
                messageBox.classList.add('bg-red-100', 'text-red-800');
            }
            setTimeout(() => {
                messageBox.classList.add('hidden');
            }, 5000);
        }

        form.addEventListener('submit', async function(event) {
            event.preventDefault();

            submitButton.disabled = true;
            submitButton.textContent = '正在送出...';
            submitButton.classList.add('opacity-50', 'cursor-not-allowed');

            try {
                const reportData = {
                    "reporterName": document.getElementById('reporter_name_input').value,
                    "deviceLocation": document.getElementById('location_input').value,
                    "problemDescription": document.getElementById('problem_input').value,
                };

                const response = await fetch(API_URL + SUBMIT_ENDPOINT, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(reportData)
                });

                const result = await response.json();

                if (response.ok) {
                    showMessage(result.message, true);
                    form.reset(); 
                } else {
                    throw new Error(result.message || `API 錯誤：HTTP 狀態碼 ${response.status}`);
                }

            } catch (error) {
                console.error("提交失敗:", error);
                showMessage(`提交失敗: ${error.message}`, false);
            } finally {
                submitButton.disabled = false;
                submitButton.textContent = '送出報修單';
                submitButton.classList.remove('opacity-50', 'cursor-not-allowed');
            }
        });
    </script>
</body>
</html>
    """
    return Response(html_content, mimetype='text/html')


# 2. API 路由：用於接收表單提交的資料 (學生填寫)
@app.route('/submit_report', methods=['POST'])
def submit_data_api():
    """接收來自網頁的 POST 請求，將 JSON 資料寫入 Google Sheets。"""
    if not sheet:
        if not initialize_gspread():
            return jsonify({"status": "error", "message": "伺服器初始化失敗，無法連線至 Google Sheets。請檢查 log 訊息。"}), 500

    try:
        data = request.get_json()
    except Exception:
        logging.error("請求資料解析失敗：不是有效的 JSON 格式。")
        return jsonify({"status": "error", "message": "請求必須是 JSON 格式。請檢查網頁前端的 Content-Type。"}), 400

    if not data:
        logging.error("請求資料為空。")
        return jsonify({"status": "error", "message": "請求資料為空。"}), 400
    
    try:
        # 從 JSON 資料中提取欄位
        reporterName = data.get('reporterName', 'N/A')
        deviceLocation = data.get('deviceLocation', 'N/A')
        problemDescription = data.get('problemDescription', 'N/A')
        
        if not all([reporterName != 'N/A', deviceLocation != 'N/A', problemDescription != 'N/A']):
            logging.error(f"缺少必要資料: {data}")
            return jsonify({"status": "error", "message": "缺少必要的報修資料（如報修人、地點或描述）。"}), 400

        # 獲取當前的 UTC 時間並轉換為台灣時區
        taiwan_time = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
        timestamp = taiwan_time.strftime("%Y-%m-%d %H:%M:%S")

        # row 陣列包含 5 個元素：時間戳記、姓名、位置、描述、狀態
        row = [
            timestamp, 
            str(reporterName),
            str(deviceLocation),
            str(problemDescription),
            "待處理" # 預設狀態
        ]
        
        # 將資料附加到工作表的最後一行
        sheet.append_row(row)
        
        logging.info(f"資料成功寫入：{row}")
        return jsonify({"status": "success", "message": "設備報修資料已成功送出！"}), 200
        
    except Exception as e:
        logging.error(f"寫入 Google Sheets 時發生錯誤: {e}")
        return jsonify({"status": "error", "message": f"提交失敗：{str(e)}，可能是 Sheets API 限制或連線問題。"}), 500


# 3. 老師查看介面路由：回傳教師查看報修紀錄的 HTML 內容
@app.route('/teacher')
def teacher_view():
    """回傳教師/管理員查看和更新報修狀態的介面 HTML。"""
    html_content = f"""
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>設備報修系統 - 教師/管理員介面</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ font-family: 'Inter', sans-serif; background-color: #e2e8f0; }}
        .status-badge {{
            padding: 4px 8px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
    </style>
</head>
<body class="min-h-screen p-4 md:p-8">

    <div class="max-w-7xl mx-auto bg-white p-6 md:p-8 rounded-xl shadow-2xl">
        
        <!-- 標題區塊 -->
        <div class="text-center mb-8">
            <h1 class="text-3xl font-bold text-gray-900">報修紀錄追蹤與處理 (教師/管理員)</h1>
            <p class="text-gray-500 mt-1">即時查看並更新報修狀態。</p>
            <p class="text-xs mt-3 text-indigo-500 hover:underline"><a href="/">點此前往學生報修介面</a></p>
        </div>

        <!-- 訊息顯示區塊 -->
        <div id="message-box" class="hidden mb-6 p-3 text-center rounded-lg font-medium transition-all duration-300"></div>

        <!-- 載入中/錯誤區塊 -->
        <div id="loading" class="text-center text-gray-500 p-10">
            <svg class="animate-spin h-5 w-5 mr-3 inline text-indigo-600" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-dasharray="30" stroke-dashoffset="0" style="stroke-dasharray: 80, 20; stroke-dashoffset: 0;"></circle></svg>
            正在載入報修紀錄...
        </div>
        <div id="error-message" class="hidden text-center p-10 text-red-600 font-bold border border-red-300 rounded-lg"></div>

        <!-- 報修表格區塊 -->
        <div id="reports-table-container" class="hidden overflow-x-auto shadow-md rounded-lg">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-indigo-600 text-white">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">時間</th>
                        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">報修人</th>
                        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">位置</th>
                        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">問題描述</th>
                        <th class="px-6 py-3 text-center text-xs font-medium uppercase tracking-wider">狀態</th>
                        <th class="px-6 py-3 text-center text-xs font-medium uppercase tracking-wider">操作</th>
                    </tr>
                </thead>
                <tbody id="reports-table-body" class="bg-white divide-y divide-gray-200">
                    <!-- 紀錄將透過 JavaScript 動態載入 -->
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const API_URL = ""; // 保持為空，讓 Canvas 環境自動設定
        const VIEW_ENDPOINT = '/view_reports';
        const UPDATE_ENDPOINT = '/update_status';
        
        const tableBody = document.getElementById('reports-table-body');
        const loading = document.getElementById('loading');
        const messageBox = document.getElementById('message-box');
        const errorBox = document.getElementById('error-message');
        const tableContainer = document.getElementById('reports-table-container');

        const STATUS_OPTIONS = [
            {{ value: '待處理', label: '待處理', class: 'bg-yellow-100 text-yellow-800' }},
            {{ value: '已完成', label: '已完成', class: 'bg-green-100 text-green-800' }},
            {{ value: '未完成', label: '未完成', class: 'bg-red-100 text-red-800' }}
        ];

        // 顯示訊息函式
        function showMessage(message, isSuccess) {{
            messageBox.textContent = message;
            messageBox.classList.remove('hidden', 'bg-red-100', 'text-red-800', 'bg-green-100', 'text-green-800');
            
            if (isSuccess) {{
                messageBox.classList.add('bg-green-100', 'text-green-800');
            }} else {{
                messageBox.classList.add('bg-red-100', 'text-red-800');
            }}
            setTimeout(() => {{
                messageBox.classList.add('hidden');
            }}, 5000);
        }}

        // 根據狀態回傳 Tailwind CSS 類別
        function getStatusClass(status) {{
            const option = STATUS_OPTIONS.find(opt => opt.value === status);
            return option ? option.class : 'bg-gray-100 text-gray-800';
        }}
        
        // 渲染表格
        function renderTable(reports) {{
            tableBody.innerHTML = '';
            if (reports.length === 0) {{
                tableBody.innerHTML = '<tr><td colspan="6" class="px-6 py-4 text-center text-gray-500">目前沒有任何報修紀錄。</td></tr>';
                return;
            }}

            reports.forEach(report => {{
                const row = tableBody.insertRow();
                row.classList.add('hover:bg-gray-50', 'transition', 'duration-150');
                
                // 設置單元格內容
                row.insertCell().textContent = report['報修時間'];
                row.insertCell().textContent = report['報修人姓名'];
                row.insertCell().textContent = report['設備位置 / 教室名稱'];
                row.insertCell().innerHTML = `<div class="whitespace-normal max-w-sm text-sm text-gray-600">${{report['問題詳細描述']}}</div>`;
                
                // 狀態顯示
                const statusCell = row.insertCell();
                statusCell.classList.add('px-6', 'py-4', 'whitespace-nowrap', 'text-center');
                statusCell.innerHTML = `<span class="status-badge ${{getStatusClass(report['狀態'])}}">{{report['狀態']}}</span>`;

                // 操作欄位 (下拉選單與按鈕)
                const actionCell = row.insertCell();
                actionCell.classList.add('px-6', 'py-4', 'whitespace-nowrap', 'text-sm', 'font-medium', 'flex', 'items-center', 'space-x-2');

                // 下拉選單
                const selectId = `status-select-${{report.sheetRow}}`;
                let selectHtml = `<select id="${{selectId}}" class="px-2 py-1 border border-gray-300 rounded-lg text-sm focus:ring-indigo-500 focus:border-indigo-500">`;
                STATUS_OPTIONS.forEach(opt => {{
                    const selected = opt.value === report['狀態'] ? 'selected' : '';
                    selectHtml += `<option value="${{opt.value}}" ${{selected}}>{{opt.label}}</option>`;
                }});
                selectHtml += `</select>`;
                actionCell.innerHTML += selectHtml;

                // 更新按鈕
                const button = document.createElement('button');
                button.textContent = '更新';
                button.classList.add('update-btn', 'py-1', 'px-3', 'border', 'border-transparent', 'rounded-lg', 'shadow-sm', 'text-sm', 'font-medium', 'text-white', 'bg-indigo-600', 'hover:bg-indigo-700', 'focus:outline-none', 'focus:ring-2', 'focus:ring-offset-2', 'focus:ring-indigo-500', 'transition', 'duration-150', 'ease-in-out');
                button.dataset.row = report.sheetRow; // 儲存 Sheet 列號
                button.onclick = () => handleUpdateStatus(button, report.sheetRow, selectId);
                actionCell.appendChild(button);
            }});
        }}

        // 處理更新狀態的函式
        async function handleUpdateStatus(button, sheetRow, selectId) {{
            const newStatus = document.getElementById(selectId).value;

            // 鎖定按鈕
            button.disabled = true;
            button.textContent = '更新中...';
            button.classList.add('opacity-50', 'cursor-not-allowed');

            try {{
                const response = await fetch(API_URL + UPDATE_ENDPOINT, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ 
                        sheetRow: sheetRow, 
                        newStatus: newStatus 
                    }})
                }});

                const result = await response.json();

                if (response.ok) {{
                    showMessage(result.message, true);
                    // 成功後重新載入資料以反映最新狀態
                    await fetchReports();
                }} else {{
                    throw new Error(result.message || `API 錯誤：HTTP 狀態碼 ${{response.status}}`);
                }}

            }} catch (error) {{
                console.error("更新失敗:", error);
                showMessage(`更新失敗: ${{error.message}}`, false);
                // 如果失敗，只恢復按鈕狀態
                button.disabled = false;
                button.textContent = '更新';
                button.classList.remove('opacity-50', 'cursor-not-allowed');
            }}
        }}

        // 獲取報修紀錄
        async function fetchReports() {{
            loading.classList.remove('hidden');
            tableContainer.classList.add('hidden');
            errorBox.classList.add('hidden');
            messageBox.classList.add('hidden');
            
            try {{
                const response = await fetch(API_URL + VIEW_ENDPOINT);
                const result = await response.json();

                if (response.ok && result.status === 'success') {{
                    renderTable(result.reports);
                    tableContainer.classList.remove('hidden');
                }} else {{
                    throw new Error(result.message || '無法從伺服器取得資料。');
                }}

            }} catch (error) {{
                console.error("載入紀錄失敗:", error);
                errorBox.textContent = `載入報修紀錄失敗：${{error.message}}`;
                errorBox.classList.remove('hidden');
            }} finally {{
                loading.classList.add('hidden');
            }}
        }}

        // 頁面載入時執行
        window.onload = fetchReports;

    </script>
</body>
</html>
    """
    return Response(html_content, mimetype='text/html')


# 4. API 路由：用於給老師查看所有報修紀錄
@app.route('/view_reports', methods=['GET'])
def view_data_api():
    """從 Google Sheets 讀取所有報修資料，並附加 Sheets 列號。"""
    if not sheet:
        if not initialize_gspread():
            return jsonify({"status": "error", "message": "伺服器初始化失敗，無法連線至 Google Sheets。"}), 500

    try:
        # 取得所有欄位標題 (第 1 行)
        headers = sheet.row_values(1)
        
        # 確保標題至少包含 5 欄
        if not headers or len(headers) < 5:
            # 使用預設的 5 個欄位名稱
            headers = ['報修時間', '報修人姓名', '設備位置 / 教室名稱', '問題詳細描述', '狀態']

        # 取得所有資料 (從第 2 行開始)
        # 這裡取得的 list of lists 是從 Sheets row 2 開始
        all_data = sheet.get_all_values()[1:]
        
        reports = []
        # 從 Sheets row 2 (即 list index 0) 開始迭代
        for index, row in enumerate(all_data):
            # 確保資料列的長度與標題數量一致，只取前 5 欄
            full_row = (row + [''] * (len(headers) - len(row)))[:len(headers)]
            
            # 將欄位名稱 (headers) 與對應的資料 (full_row) 組合成字典
            report = dict(zip(headers, full_row))
            
            # 關鍵：加上 Google Sheets 中的實際列號 (1-based index)
            # 標頭在第 1 列，所以第一筆資料從第 2 列開始 (index 0 + 2)
            report['sheetRow'] = index + 2 
            reports.append(report)
            
        logging.info(f"成功讀取 {len(reports)} 條報修紀錄。")
        
        return jsonify({
            "status": "success",
            "message": "報修紀錄讀取成功。",
            "total_reports": len(reports),
            "reports": reports
        }), 200

    except Exception as e:
        logging.error(f"讀取 Google Sheets 時發生未知錯誤: {e}")
        return jsonify({"status": "error", "message": f"讀取資料失敗：{str(e)}。"}), 500


# 5. API 路由：用於更新報修狀態
@app.route('/update_status', methods=['POST'])
def update_status_api():
    """接收 POST 請求，根據列號 (sheetRow) 和新狀態 (newStatus) 更新 Google Sheets 資料。"""
    if not sheet:
        if not initialize_gspread():
            return jsonify({"status": "error", "message": "伺服器初始化失敗，無法連線至 Google Sheets。"}), 500

    try:
        data = request.get_json()
        sheet_row = data.get('sheetRow')
        new_status = data.get('newStatus')
        
        if not sheet_row or not new_status:
            return jsonify({"status": "error", "message": "缺少必要的參數 (sheetRow 或 newStatus)。"}), 400

        # 檢查新狀態是否在允許的範圍內
        allowed_statuses = ["待處理", "已完成", "未完成"]
        if new_status not in allowed_statuses:
             return jsonify({"status": "error", "message": f"無效的狀態值: {new_status}。只允許 {', '.join(allowed_statuses)}。"}), 400

        # 執行更新
        # 更新 E 欄 (STATUS_COLUMN_INDEX = 5) 在指定列 (sheet_row) 的值
        sheet.update_cell(sheet_row, STATUS_COLUMN_INDEX, new_status)
        
        logging.info(f"成功更新列 {sheet_row} 的狀態為: {new_status}")
        return jsonify({"status": "success", "message": f"第 {sheet_row} 列的狀態已成功更新為「{new_status}」。"}), 200
        
    except Exception as e:
        logging.error(f"更新 Google Sheets 狀態時發生錯誤: {e}")
        return jsonify({"status": "error", "message": f"更新狀態失敗：{str(e)}，可能是 Sheets API 限制或連線問題。"}), 500


# ----------------------------------------------------
# 本地測試運行
if __name__ == '__main__':
    # 確保應用程式啟動時就嘗試連線
    with app.app_context():
        initialize_gspread()
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))
# student_look
