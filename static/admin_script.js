document.addEventListener('DOMContentLoaded', function() {

    const logContent = document.getElementById('log-content');
    const logContainer = document.getElementById('log-container');

    async function fetchLogs() {
        try {
            const response = await fetch('/admin/api/logs');
            if (!response.ok) {
                logContent.textContent = 'Error fetching logs.';
                return;
            }
            const data = await response.json();
            // Cập nhật nội dung và tự động cuộn xuống dưới
            logContent.textContent = data.logs.join('');
            logContainer.scrollTop = logContainer.scrollHeight;
        } catch (error) {
            console.error('Failed to fetch logs:', error);
            logContent.textContent = 'Failed to connect to the server to get logs.';
        }
    }

    // Tải log lần đầu tiên ngay khi vào trang
    fetchLogs();

    // Thiết lập tự động làm mới log mỗi 5 giây
    setInterval(fetchLogs, 5000);

    // TODO: Thêm logic cho các nút Analyze và Add to Database ở đây
});