<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>任務接收系統</title>
    <!-- 載入 Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* 使用 Inter 字體 */
        body {
            font-family: 'Inter', sans-serif;
        }
        /* 簡單的載入中動畫 */
        .spinner {
            border-top-color: theme('colors.indigo.500');
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">

    <div id="app" class="container mx-auto p-4 md:p-8 max-w-4xl">

        <!-- ===== 1. 登入畫面 ===== -->
        <div id="login-view">
            <div class="bg-white p-8 rounded-xl shadow-lg max-w-md mx-auto">
                <h1 class="text-2xl font-bold text-center text-gray-800 mb-6">任務系統登入</h1>
                <form id="login-form">
                    <div class="mb-4">
                        <label for="username" class="block text-sm font-medium text-gray-700 mb-1">帳號</label>
                        <input type="text" id="username" name="username" required
                               class="w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                               placeholder="請輸入您的帳號">
                    </div>
                    <div class="mb-6">
                        <label for="password" class="block text-sm font-medium text-gray-700 mb-1">密碼</label>
                        <input type="password" id="password" name="password" required
                               class="w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                               placeholder="請輸入您的密碼">
                    </div>
                    <button type="submit" id="login-button"
                            class="w-full bg-indigo-600 text-white py-2 px-4 rounded-lg font-semibold shadow-md
                                   hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2
                                   transition duration-200 ease-in-out
                                   disabled:bg-gray-400 disabled:cursor-not-allowed">
                        登入
                    </button>
                    <div id="login-message" class="text-center text-sm text-red-600 mt-4"></div>
                </form>
            </div>
        </div>

        <!-- ===== 2. 任務列表畫面 ===== -->
        <div id="tasks-view" class="hidden">
            <div class="bg-white p-6 md:p-8 rounded-xl shadow-lg">
                <div class="flex justify-between items-center mb-6 border-b pb-4">
                    <div>
                        <h1 class="text-3xl font-bold text-gray-800">可接取的任務</h1>
                        <p id="welcome-message" class="text-gray-600 mt-1">正在載入使用者資訊...</p>
                    </div>
                    <button id="logout-button"
                            class="bg-red-500 text-white py-2 px-4 rounded-lg font-semibold shadow-md
                                   hover:bg-red-600 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2
                                   transition duration-200 ease-in-out">
                        登出
                    </button>
                </div>

                <!-- 任務篩選 -->
                <div class="mb-4">
                    <label for="task-filter" class="sr-only">篩選任務</label>
                    <select id="task-filter"
                            class="w-full md:w-1/3 px-4 py-2 border border-gray-300 rounded-lg shadow-sm 
                                   focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500">
                        <option value="pending">待處理 (尚未額滿)</option>
                        <option value="my-tasks">我已接取</option>
                        <option value="full">已額滿</option>
                        <option value="all">所有任務</option>
                    </select>
                </div>

                <!-- 任務操作訊息 -->
                <div id="task-message" class="text-center mb-4"></div>

                <!-- 載入中提示 -->
                <div id="loading-spinner" class="flex justify-center items-center py-10">
                    <div class="spinner w-12 h-12 border-4 border-gray-200 border-t-indigo-500 rounded-full"></div>
                    <p class="ml-4 text-gray-600">正在載入任務列表...</p>
                </div>

                <!-- 任務列表 -->
                <div id="task-list" class="space-y-4">
                    <!-- 任務卡片將會動態插入到這裡 -->
                </div>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const API_BASE_URL = ''; // 部署在 Render 上，相對路徑即可

            // --- 1. 抓取 DOM 元素 ---
            const loginView = document.getElementById('login-view');
            const tasksView = document.getElementById('tasks-view');
            const loginForm = document.getElementById('login-form');
            const loginButton = document.getElementById('login-button');
            const loginMessage = document.getElementById('login-message');
            
            const welcomeMessage = document.getElementById('welcome-message');
            const logoutButton = document.getElementById('logout-button');
            const taskFilter = document.getElementById('task-filter');
            const taskList = document.getElementById('task-list');
            const taskMessage = document.getElementById('task-message');
            const loadingSpinner = document.getElementById('loading-spinner');

            // --- 2. 狀態變數 ---
            let currentUser = null; // { "full_name": "...", "group": "..." }
            let currentToken = null;
            let allTasks = []; // 儲存所有從 API 獲取的任務

            // --- 3. 登入邏輯 ---
            loginForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                loginButton.disabled = true;
                loginButton.textContent = '登入中...';
                loginMessage.textContent = '';

                // 使用 FormData 來處理 application/x-www-form-urlencoded
                const formData = new FormData(loginForm);

                try {
                    const response = await fetch(`${API_BASE_URL}/token`, {
                        method: 'POST',
                        body: new URLSearchParams(formData) // 轉換為 x-www-form-urlencoded
                    });

                    const data = await response.json();

                    if (!response.ok) {
                        throw new Error(data.detail || '登入失敗，請檢查帳號或密碼');
                    }

                    // 登入成功
                    currentToken = data.access_token;
                    // 從 token 中解碼使用者資訊 (注意：這僅用於顯示，不應用於安全驗證)
                    currentUser = parseJwt(currentToken); 
                    
                    updateUI('tasks');
                    welcomeMessage.textContent = `你好, ${currentUser.full_name} (${currentUser.group})。`;
                    fetchTasks();

                } catch (error) {
                    loginMessage.textContent = error.message;
                } finally {
                    loginButton.disabled = false;
                    loginButton.textContent = '登入';
                }
            });

            // --- 4. 登出邏輯 ---
            logoutButton.addEventListener('click', () => {
                currentUser = null;
                currentToken = null;
                allTasks = [];
                taskList.innerHTML = ''; // 清空任務列表
                loginForm.reset(); // 重設登入表單
                updateUI('login');
                loginMessage.textContent = '您已成功登出。';
            });

            // --- 5. 取得任務列表 ---
            async function fetchTasks() {
                if (!currentToken) return;

                loadingSpinner.style.display = 'flex';
                taskList.innerHTML = '';
                taskMessage.textContent = '';

                try {
                    const response = await fetch(`${API_BASE_URL}/tasks`, {
                        method: 'GET',
                        headers: {
                            'Authorization': `Bearer ${currentToken}`
                        }
                    });

                    if (!response.ok) {
                        throw new Error('無法取得任務列表');
                    }

                    allTasks = await response.json();
                    filterAndRenderTasks(); // 取得任務後立即渲染

                } catch (error) {
                    taskMessage.textContent = `錯誤: ${error.message}`;
                    taskMessage.className = 'text-center text-red-600 font-medium mb-4';
                } finally {
                    loadingSpinner.style.display = 'none';
                }
            }

            // --- 6. 渲染與篩選任務 ---
            taskFilter.addEventListener('change', filterAndRenderTasks);

            function filterAndRenderTasks() {
                const filterValue = taskFilter.value;
                let tasksToRender = [];

                if (filterValue === 'pending') {
                    tasksToRender = allTasks.filter(task => !task.is_full);
                } else if (filterValue === 'my-tasks') {
                    tasksToRender = allTasks.filter(task => 
                        currentUser && task.assignees.includes(currentUser.full_name)
                    );
                } else if (filterValue === 'full') {
                    tasksToRender = allTasks.filter(task => task.is_full);
                } else { // 'all'
                    tasksToRender = allTasks;
                }
                
                renderTasks(tasksToRender);
            }
            
            function renderTasks(tasks) {
                taskList.innerHTML = ''; // 清空當前列表
                
                if (tasks.length === 0) {
                    taskList.innerHTML = `<p class="text-gray-500 text-center py-4">這個分類中沒有任務。</p>`;
                    return;
                }

                tasks.forEach(task => {
                    // *** 修正開始 (使用 assignees) ***
                    const isAlreadyAccepted = currentUser ? task.assignees.includes(currentUser.full_name) : false;
                    const peopleNeeded = task.required_count - task.assignees.length;
                    // *** 修正結束 ***

                    let buttonHtml = '';
                    if (isAlreadyAccepted) {
                        buttonHtml = `
                            <button class="bg-gray-400 text-white py-2 px-5 rounded-lg font-semibold cursor-not-allowed" disabled>
                                已接取
                            </button>`;
                    } else if (task.is_full) {
                        buttonHtml = `
                            <button class="bg-gray-400 text-white py-2 px-5 rounded-lg font-semibold cursor-not-allowed" disabled>
                                已額滿
                            </button>`;
                    } else {
                        buttonHtml = `
                            <button data-row-id="${task.row_number}"
                                    class="accept-task-btn bg-indigo-600 text-white py-2 px-5 rounded-lg font-semibold 
                                           hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500
                                           transition duration-200 ease-in-out">
                                接取任務
                            </button>`;
                    }
                    
                    const card = `
                        <div class="border border-gray-200 rounded-lg p-5 bg-white shadow-sm transition-all hover:shadow-md">
                            <div class="flex flex-col md:flex-row justify-between items-start md:items-center">
                                <!-- 任務資訊 -->
                                <div class="mb-4 md:mb-0">
                                    <span class="inline-block bg-indigo-100 text-indigo-700 text-xs font-semibold px-2 py-1 rounded-full mb-2">
                                        ${task.group}
                                    </span>
                                    <h3 class="text-xl font-bold text-gray-800">${task.title}</h3>
                                    <p class="text-gray-600 mt-1">${task.description}</p>
                                    <p class="text-sm text-gray-500 mt-2">
                                        <span class="font-medium">狀態:</span> ${task.status} | 
                                        <span class="font-medium">任務編號:</span> ${task.row_number}
                                    </p>
                                </div>
                                
                                <!-- 人數與按鈕 -->
                                <div class="flex-shrink-0 w-full md:w-auto text-left md:text-right">
                                    <!-- *** 修正開始 (使用 assignees) *** -->
                                    <div class="text-right mb-3">
                                        <p class="text-sm font-semibold ${peopleNeeded > 0 ? 'text-indigo-600' : 'text-gray-600'}">
                                            ${task.is_full ? '人數已滿' : `尚缺 ${peopleNeeded} 人`}
                                            <span class="text-xs text-gray-500 font-normal">(${task.assignees.length} / ${task.required_count})</span>
                                        </p>
                                        <p class="text-xs text-gray-500 mt-1">
                                            ${task.assignees.length > 0 ? '接取者: ' + task.assignees.join(', ') : '尚無人接取'}
                                        </p>
                                    </div>
                                    <!-- *** 修正結束 *** -->
                                    ${buttonHtml}
                                </div>
                            </div>
                        </div>
                    `;
                    taskList.innerHTML += card;
                });
            }

            // --- 7. 接取任務邏輯 ---
            taskList.addEventListener('click', async (e) => {
                // 事件委派：只處理 .accept-task-btn 的點擊
                const button = e.target.closest('.accept-task-btn');
                if (!button) return;

                button.disabled = true;
                button.textContent = '處理中...';
                taskMessage.textContent = '';

                const rowId = button.dataset.rowId;

                try {
                    // *** 修正開始 (API 路徑與 body) ***
                    const response = await fetch(`${API_BASE_URL}/tasks/assign`, {
                        method: 'POST',
                        headers: { 
                            'Authorization': `Bearer ${currentToken}`,
                            'Content-Type': 'application/json' 
                        },
                        body: JSON.stringify({
                            "row_number": parseInt(rowId) // 傳送後端要的 row_number
                        })
                    });
                    // *** 修正結束 ***

                    const result = await response.json();
                    
                    if (!response.ok) {
                        throw new Error(result.detail || '接取失敗');
                    }

                    // 接取成功！
                    taskMessage.textContent = result.message || '任務接取成功！';
                    taskMessage.className = 'text-center text-green-600 font-medium mb-4';
                    
                    // 重新整理任務列表
                    fetchTasks(); 

                } catch (error) {
                    console.error('接取任務失敗:', error);
                    taskMessage.textContent = `錯誤: ${error.message}`;
                    taskMessage.className = 'text-center text-red-600 font-medium mb-4';
                    button.disabled = false; // 讓使用者可以重試
                    button.textContent = '接取任務';
                }
            });


            // --- 8. 更新 UI 畫面 (登入/任務) ---
            function updateUI(view) {
                if (view === 'tasks') {
                    loginView.classList.add('hidden');
                    tasksView.classList.remove('hidden');
                } else {
                    // 'login'
                    loginView.classList.remove('hidden');
                    tasksView.classList.add('hidden');
                }
            }
            
            // --- 輔助函式：解析 JWT ---
            function parseJwt(token) {
                try {
                    const base64Url = token.split('.')[1];
                    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                    }).join(''));
                    
                    // JWT payload 儲存在 'sub' 欄位中，格式為 '{"full_name": ..., "group": ...}'
                    const payload = JSON.parse(json.parse(jsonPayload).sub);
                    return payload;
                } catch (e) {
                    console.error("解析 Token 失敗:", e);
                    return null;
                }
            }


            // --- 初始啟動 ---
            updateUI('login'); // 預設顯示登入畫面
        });
    </script>
</body>
</html>
