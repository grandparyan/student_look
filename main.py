import http.server
import socketserver
import os

PORT = 8000
FILENAME = "index.html"

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # 如果請求的是根目錄 ('/'), 則提供 index.html
        if self.path == '/':
            self.path = FILENAME
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

Handler = MyHttpRequestHandler

# 檢查 index.html 是否存在
if not os.path.exists(FILENAME):
    print(f"錯誤：找不到 {FILENAME} 檔案。")
    print("請確保 'index.html' 和 'main.py' 放在同一個資料夾中。")
else:
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"伺服器已啟動於 http://localhost:{PORT}")
        print(f"正在提供 '{FILENAME}'...")
        print("按下 Ctrl+C 即可停止伺服器。")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n伺服器已關閉。")
            httpd.server_close()
