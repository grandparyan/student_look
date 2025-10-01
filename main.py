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
spreadsheet_id = "1IHyA7aRxGJekm31KIbuORpg4-dVY8XTOEbU6p8vK3y4"
WORKSHEET_NAME = "設備報修"

# Google Sheets 欄位索引 (1-based index)
# 假設 Sheets 欄位結構為: A:時間, B:姓名, C:位置, D:描述, E:狀態, F:協辦老師
STATUS_COLUMN_INDEX = 5             # E 欄 (狀態)
PERSON_IN_CHARGE_COLUMN_INDEX = 6   # F 欄 (協辦老師/負責人)

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

# 1. 根路由：提供教師/管理員介面的 HTML (即新的 index.html)
@app.route('/')
@app.route('/index.html')
def index_view():
    """回傳教師/管理員查看和更新報修紀錄的介面 HTML 內容。"""
    # 這是您在上次互動中確認要使用的單一 HTML 檔案內容
    html_content = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>設備報修系統 - 教師/管理員介面</title>
    <!-- 載入 Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* 使用 Inter 字體以確保跨平台一致性 */
        body { 
            font-family: 'Inter', sans-serif; 
            background-color: #e2e8f0; 
        }
        /* 狀態標籤樣式 */
        .status-badge {
            padding: 4px 8px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            display: inline-block;
        }
        /* 表格內描述欄位樣式 */
        .description-cell {
            white-space: normal;
            max-width: 15rem; /* 限制寬度，確保手機排版不會過長 */
            text-overflow: ellipsis;
            overflow: hidden;
        }
        /* 針對行動裝置優化表格邊界 */
        @media (max-width: 768px) {
             .hide-on-mobile {
                 display: none;
             }
        }
    </style>
</head>
<body class="min-h-screen p-4 md:p-8">

    <div class="max-w-7xl mx-auto bg-white p-6 md:p-8 rounded-xl shadow-2xl">
        
        <!-- 標題區塊 -->
        <div class="text-center mb-8">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 text-indigo-600 mx-auto mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.807 3.42 3.42 0 014.288 0 3.42 3.42 0 001.946.807M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h1 class="text-3xl font-bold text-gray-900">報修紀錄追蹤與處理 (教師/管理員)</h1>
            <p class="text-gray-500 mt-1">即時查看並更新報修狀態與協辦老師。</p>
        </div>

        <!-- 訊息顯示區塊 -->
        <div id="message-box" class="hidden mb-6 p-3 text-center rounded-lg font-medium transition-all duration-300"></div>

        <!-- 載入中/錯誤區塊 -->
        <div id="loading" class="text-center text-gray-500 p-10">
            <svg class="animate-spin h-5 w-5 mr-3 inline text-indigo-600" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-dasharray="30" stroke-dashoffset="0" style="stroke-dasharray: 80, 20; stroke-dashoffset: 0;"></circle></svg>
            正在載入報修紀錄...
        </div>
        <div id="error-message" class="hidden text-center p-4 text-red-600 font-bold border border-red-300 bg-red-50 rounded-lg"></div>

        <!-- 報修表格區塊 -->
        <div id="reports-table-container" class="hidden overflow-x-auto shadow-md rounded-xl border border-gray-200">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-indigo-600 text-white">
                    <tr>
                        <th class="px-3 py-3 text-left text-xs font-medium uppercase tracking-wider hide-on-mobile">時間</th>
                        <th class="px-3 py-3 text-left text-xs font-medium uppercase tracking-wider">報修人</th>
                        <th class="px-3 py-3 text-left text-xs font-medium uppercase tracking-wider">位置</th>
                        <th class="px-3 py-3 text-left text-xs font-medium uppercase tracking-wider">問題描述</th>
                        <th class="px-3 py-3 text-left text-xs font-medium uppercase tracking-wider hide-on-mobile">協辦老師/負責人</th> 
                        <th class="px-3 py-3 text-center text-xs font-medium uppercase tracking-wider">狀態</th>
                        <th class="px-3 py-3 text-center text-xs font-medium uppercase tracking-wider">操作</th>
                    </tr>
                </thead>
                <tbody id="reports-table-body" class="bg-white divide-y divide-gray-200">
                    <!-- 紀錄將透過 JavaScript 動態載入 -->
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // 注意: 這裡的 API_URL 應該設定為您的 Render 服務網址
        const API_URL = ""; 
        const VIEW_ENDPOINT = '/view_reports';
        const UPDATE_ENDPOINT = '/update_status'; // API 預期同時接收 newStatus 和 newTeacher
        
        const tableBody = document.getElementById('reports-table-body');
        const loading = document.getElementById('loading');
        const messageBox = document.getElementById('message-box');
        const errorBox = document.getElementById('error-message');
        const tableContainer = document.getElementById('reports-table-container');

        // 狀態選項配置
        const STATUS_OPTIONS = [
            { value: '待處理', label: '待處理', class: 'bg-yellow-100 text-yellow-800' },
            { value: '已完成', label: '已完成', class: 'bg-green-100 text-green-800' },
            { value: '未完成', label: '未完成', class: 'bg-red-100 text-red-800' }
        ];

        // 顯示訊息函式
        function showMessage(message, isSuccess) {
            messageBox.textContent = message;
            messageBox.classList.remove('hidden', 'bg-red-100', 'text-red-800', 'bg-green-100', 'text-green-800');
            
            if (isSuccess) {
                messageBox.classList.add('bg-green-100', 'text-green-800');
            } else {
                messageBox.classList.add('bg-red-100', 'text-red-800');
            }
            // 5 秒後隱藏訊息
            setTimeout(() => {
                messageBox.classList.add('hidden');
            }, 5000);
        }

        // 根據狀態回傳 Tailwind CSS 類別
        function getStatusClass(status) {
            const option = STATUS_OPTIONS.find(opt => opt.value === status);
            return option ? option.class : 'bg-gray-100 text-gray-800';
        }
        
        // 渲染表格
        function renderTable(reports) {
            tableBody.innerHTML = '';
            
            if (reports.length === 0) {
                // colspan 是 7，因為有 7 個欄位
                tableBody.innerHTML = '<tr><td colspan="7" class="px-6 py-4 text-center text-gray-500">目前沒有任何報修紀錄。</td></tr>';
                return;
            }

            reports.forEach(report => {
                const row = tableBody.insertRow();
                row.classList.add('hover:bg-gray-50', 'transition', 'duration-150');
                
                // 1. 報修時間 (隱藏於手機版)
                const timeCell = row.insertCell();
                timeCell.textContent = report['報修時間'];
                timeCell.classList.add('px-3', 'py-3', 'whitespace-nowrap', 'text-sm', 'text-gray-500', 'hide-on-mobile');
                
                // 2. 報修人
                row.insertCell().textContent = report['報修人姓名'];
                
                // 3. 位置
                row.insertCell().textContent = report['設備位置 / 教室名稱'];
                
                // 4. 問題描述
                const descriptionCell = row.insertCell();
                descriptionCell.innerHTML = `<div class="description-cell text-sm text-gray-600">${report['問題詳細描述']}</div>`;
                
                // 5. 協辦老師/負責人 (現在是可編輯輸入框)
                const teacherCell = row.insertCell();
                const teacherInputId = `teacher-input-${report.sheetRow}`;
                teacherCell.classList.add('px-3', 'py-3', 'whitespace-nowrap', 'text-sm', 'hide-on-mobile');
                // 預設值為 '無指定' 時顯示空字串，讓使用者易於輸入
                const teacherValue = report['協辦老師'] === '無指定' || report['協辦老師'] === 'N/A' || report['協辦老師'] === '' ? '' : report['協辦老師'];
                teacherCell.innerHTML = `
                    <input type="text" id="${teacherInputId}" 
                           value="${teacherValue}"
                           placeholder="輸入負責人姓名"
                           class="w-full px-2 py-1 border border-gray-300 rounded-lg text-xs md:text-sm focus:ring-indigo-500 focus:border-indigo-500 transition duration-150"
                    >`;

                // 6. 狀態顯示 (下拉選單)
                const statusCell = row.insertCell();
                statusCell.classList.add('px-3', 'py-3', 'whitespace-nowrap', 'text-center');

                const selectId = `status-select-${report.sheetRow}`;
                let selectHtml = `<select id="${selectId}" class="px-2 py-1 border border-gray-300 rounded-lg text-xs md:text-sm focus:ring-indigo-500 focus:border-indigo-500">`;
                STATUS_OPTIONS.forEach(opt => {
                    const selected = opt.value === report['狀態'] ? 'selected' : '';
                    selectHtml += `<option value="${opt.value}" ${selected}>${opt.label}</option>`;
                });
                selectHtml += `</select>`;
                statusCell.innerHTML = selectHtml;

                // 7. 操作欄位 (更新按鈕)
                const actionCell = row.insertCell();
                actionCell.classList.add('px-3', 'py-3', 'whitespace-nowrap', 'text-sm', 'font-medium', 'flex', 'flex-col', 'md:flex-row', 'items-center', 'space-y-1', 'md:space-y-0', 'md:space-x-2', 'justify-center');

                // 更新按鈕
                const button = document.createElement('button');
                button.textContent = '更新';
                button.classList.add('update-btn', 'py-1', 'px-3', 'border', 'border-transparent', 'rounded-lg', 'shadow-sm', 'text-xs', 'md:text-sm', 'font-medium', 'text-white', 'bg-indigo-600', 'hover:bg-indigo-700', 'focus:outline-none', 'focus:ring-2', 'focus:ring-offset-2', 'focus:ring-indigo-500', 'transition', 'duration-150', 'ease-in-out', 'w-full', 'md:w-auto');
                
                // 綁定點擊事件，傳遞 selectId 和 teacherInputId
                button.onclick = () => handleUpdateStatus(button, report.sheetRow, selectId, teacherInputId);
                actionCell.appendChild(button);
            });
        }

        // 處理更新狀態的函式
        async function handleUpdateStatus(button, sheetRow, selectId, teacherInputId) {
            // 取得新的狀態值
            const newStatus = document.getElementById(selectId).value;
            // 取得新的協辦老師/負責人值，如果為空則設為 '無指定'
            const newTeacher = document.getElementById(teacherInputId).value.trim() || '無指定'; 

            // 鎖定按鈕
            button.disabled = true;
            button.textContent = '更新中...';
            button.classList.add('opacity-50', 'cursor-not-allowed');

            try {
                // 注意: 這裡的 API_URL 必須正確設定為您的後端網址才能連線
                const response = await fetch(API_URL + UPDATE_ENDPOINT, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        sheetRow: sheetRow, 
                        newStatus: newStatus,
                        newTeacher: newTeacher // 傳送新的負責人姓名
                    })
                });

                const result = await response.json();

                if (response.ok) {
                    showMessage(result.message, true);
                    await fetchReports();
                } else {
                    throw new Error(result.message || `API 錯誤：HTTP 狀態碼 ${response.status}`);
                }

            } catch (error) {
                console.error("更新失敗:", error);
                showMessage(`更新失敗: ${error.message}`, false);
            } finally {
                // 恢復按鈕狀態
                button.disabled = false;
                button.textContent = '更新';
                button.classList.remove('opacity-50', 'cursor-not-allowed');
            }
        }

        // 獲取報修紀錄
        async function fetchReports() {
            loading.classList.remove('hidden');
            tableContainer.classList.add('hidden');
            errorBox.classList.add('hidden');
            messageBox.classList.add('hidden');
            
            try {
                // 注意: 這裡的 API_URL 必須正確設定為您的後端網址才能連線
                const response = await fetch(API_URL + VIEW_ENDPOINT);
                const result = await response.json();

                if (response.ok && result.status === 'success') {
                    renderTable(result.reports);
                    tableContainer.classList.remove('hidden');
                } else {
                    throw new Error(result.message || '無法從伺服器取得資料。');
                }

            } catch (error) {
                console.error("載入紀錄失敗:", error);
                errorBox.textContent = `載入報修紀錄失敗：${error.message}`;
                errorBox.classList.remove('hidden');
            } finally {
                loading.classList.add('hidden');
            }
        }

        // 頁面載入時執行
        window.onload = fetchReports;

    </script>
</body>
</html>
    """
    return Response(html_content, mimetype='text/html')

# 2. API 路由：用於接收表單提交的資料 (已移除 student.html, 但保留 API 讓教師可自行新增或模擬)
@app.route('/submit_report', methods=['POST'])
def submit_data_api():
    """接收 POST 請求，將 JSON 資料寫入 Google Sheets。"""
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

        # row 陣列包含 A-F 欄位：時間戳記、姓名、位置、描述、狀態、負責人
        row = [
            timestamp, 
            str(reporterName),
            str(deviceLocation),
            str(problemDescription),
            "待處理", # E 欄：預設狀態 (Index 5)
            "無指定"  # F 欄：負責人/協辦老師 (Index 6)
        ]
        
        # 將資料附加到工作表的最後一行
        sheet.append_row(row)
        
        logging.info(f"資料成功寫入：{row}")
        return jsonify({"status": "success", "message": "設備報修資料已成功送出！"}), 200
        
    except Exception as e:
        logging.error(f"寫入 Google Sheets 時發生錯誤: {e}")
        return jsonify({"status": "error", "message": f"提交失敗：{str(e)}，可能是 Sheets API 限制或連線問題。"}), 500


# 3. API 路由：用於給老師查看所有報修紀錄
@app.route('/view_reports', methods=['GET'])
def view_data_api():
    """從 Google Sheets 讀取所有報修資料，包含狀態和協辦老師。"""
    if not sheet:
        if not initialize_gspread():
            return jsonify({"status": "error", "message": "伺服器初始化失敗，無法連線至 Google Sheets。"}), 500

    try:
        # 取得所有欄位標題 (第 1 行)
        headers = sheet.row_values(1)
        
        # 確保標題至少包含 6 欄 (包含協辦老師)
        default_headers = ['報修時間', '報修人姓名', '設備位置 / 教室名稱', '問題詳細描述', '狀態', '協辦老師']
        if not headers or len(headers) < len(default_headers):
            headers = default_headers
        
        # 取得所有資料 (從第 2 行開始)
        all_data = sheet.get_all_values()[1:]
        
        reports = []
        # 從 Sheets row 2 (即 list index 0) 開始迭代
        for index, row in enumerate(all_data):
            # 確保資料列的長度與標題數量一致，並只取前 6 欄
            full_row = (row + [''] * (len(headers) - len(row)))[:len(default_headers)]
            
            # 將欄位名稱 (headers) 與對應的資料 (full_row) 組合成字典
            report = dict(zip(default_headers, full_row))
            
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


# 4. API 路由：用於更新報修狀態和協辦老師 (新增的綜合更新路由)
@app.route('/update_status', methods=['POST'])
def update_status_and_person_api():
    """接收 POST 請求，根據列號更新 Google Sheets 資料的狀態和協辦老師。"""
    if not sheet:
        if not initialize_gspread():
            return jsonify({"status": "error", "message": "伺服器初始化失敗，無法連線至 Google Sheets。"}), 500

    try:
        data = request.get_json()
        sheet_row = data.get('sheetRow')
        new_status = data.get('newStatus')
        new_teacher = data.get('newTeacher') # 協辦老師/負責人
        
        if not sheet_row or not new_status or new_teacher is None:
            return jsonify({"status": "error", "message": "缺少必要的參數 (sheetRow, newStatus, 或 newTeacher)。"}), 400

        # 1. 更新 E 欄 (狀態)
        sheet.update_cell(sheet_row, STATUS_COLUMN_INDEX, str(new_status))
        
        # 2. 更新 F 欄 (協辦老師/負責人)
        # 如果 new_teacher 是 '無指定' 則寫入空字串或 '無指定'
        teacher_value = str(new_teacher).strip() if str(new_teacher).strip() != '無指定' else ''
        sheet.update_cell(sheet_row, PERSON_IN_CHARGE_COLUMN_INDEX, teacher_value)
        
        logging.info(f"成功更新列 {sheet_row}：狀態為「{new_status}」，負責人為「{new_teacher}」。")
        return jsonify({"status": "success", "message": f"第 {sheet_row} 列報修紀錄已成功更新！狀態: {new_status}, 負責人: {new_teacher}"}), 200
        
    except Exception as e:
        logging.error(f"更新 Google Sheets 狀態和負責人時發生錯誤: {e}")
        return jsonify({"status": "error", "message": f"更新失敗：{str(e)}，可能是 Sheets API 限制或連線問題。"}), 500


# ----------------------------------------------------
# 本地測試運行
if __name__ == '__main__':
    # 確保應用程式啟動時就嘗試連線
    with app.app_context():
        initialize_gspread()
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))
