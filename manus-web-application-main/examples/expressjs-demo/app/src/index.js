const express = require('express')
const app = express()
const port = process.env['PORT'] || 8080

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// 模拟数据存储
let items = [
    { id: 1, name: 'Lambda@Edge', status: 'active', count: 0 },
    { id: 2, name: 'CloudFront', status: 'active', count: 0 },
    { id: 3, name: 'DynamoDB', status: 'active', count: 0 }
]

// SIGTERM Handler
process.on('SIGTERM', async () => {
    console.info('[express] SIGTERM received');
    console.info('[express] cleaning up');
    await new Promise(resolve => setTimeout(resolve, 100));
    console.info('[express] exiting');
    process.exit(0)
});

// 主页 - 动态交互界面
app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lambda Web Adapter Demo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { 
            max-width: 900px; 
            margin: 0 auto; 
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 32px; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 14px; }
        .content { padding: 30px; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
        }
        .stat-card h3 { font-size: 14px; opacity: 0.9; margin-bottom: 10px; }
        .stat-card .number { font-size: 36px; font-weight: bold; }
        .items { margin-bottom: 30px; }
        .item {
            background: #f8f9fa;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .item:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .item-info { flex: 1; }
        .item-name { font-size: 18px; font-weight: 600; margin-bottom: 5px; }
        .item-status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .status-active { background: #d4edda; color: #155724; }
        .status-inactive { background: #f8d7da; color: #721c24; }
        .item-actions {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .count { 
            font-size: 24px; 
            font-weight: bold; 
            color: #667eea;
            min-width: 40px;
            text-align: center;
        }
        button {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s;
            font-size: 14px;
        }
        .btn-primary {
            background: #667eea;
            color: white;
        }
        .btn-primary:hover { background: #5568d3; transform: scale(1.05); }
        .btn-success {
            background: #28a745;
            color: white;
        }
        .btn-success:hover { background: #218838; transform: scale(1.05); }
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        .btn-danger:hover { background: #c82333; transform: scale(1.05); }
        .btn-warning {
            background: #ffc107;
            color: #000;
        }
        .btn-warning:hover { background: #e0a800; transform: scale(1.05); }
        .add-form {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 30px;
        }
        .add-form h3 { margin-bottom: 15px; color: #333; }
        .form-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        input[type="text"] {
            flex: 1;
            min-width: 200px;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .loading { text-align: center; padding: 20px; color: #666; }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Lambda Web Adapter Demo</h1>
            <p>CloudFront + Lambda@Edge + Lambda (LWA) 动态路由演示</p>
        </div>
        
        <div class="content">
            <div class="stats">
                <div class="stat-card">
                    <h3>总项目数</h3>
                    <div class="number" id="totalItems">0</div>
                </div>
                <div class="stat-card">
                    <h3>活跃项目</h3>
                    <div class="number" id="activeItems">0</div>
                </div>
                <div class="stat-card">
                    <h3>总点击数</h3>
                    <div class="number" id="totalClicks">0</div>
                </div>
            </div>

            <div class="add-form">
                <h3>➕ 添加新项目</h3>
                <div class="form-group">
                    <input type="text" id="newItemName" placeholder="输入项目名称..." />
                    <button class="btn-success" onclick="addItem()">添加</button>
                </div>
            </div>

            <div class="items">
                <h3 style="margin-bottom: 15px; color: #333;">📋 项目列表</h3>
                <div id="itemsList" class="loading">加载中...</div>
            </div>
        </div>

        <div class="footer">
            Powered by AWS Lambda Web Adapter | Express.js
        </div>
    </div>

    <script>
        async function loadItems() {
            try {
                const res = await fetch('/api/items');
                const data = await res.json();
                renderItems(data.items);
                updateStats(data.items);
            } catch (err) {
                document.getElementById('itemsList').innerHTML = 
                    '<div style="color: red;">加载失败: ' + err.message + '</div>';
            }
        }

        function renderItems(items) {
            const html = items.map(item => \`
                <div class="item">
                    <div class="item-info">
                        <div class="item-name">\${item.name}</div>
                        <span class="item-status status-\${item.status}">
                            \${item.status === 'active' ? '✓ 活跃' : '✗ 停用'}
                        </span>
                    </div>
                    <div class="item-actions">
                        <div class="count">\${item.count}</div>
                        <button class="btn-primary" onclick="incrementCount(\${item.id})">
                            👍 点赞
                        </button>
                        <button class="btn-warning" onclick="toggleStatus(\${item.id})">
                            \${item.status === 'active' ? '⏸ 停用' : '▶️ 启用'}
                        </button>
                        <button class="btn-danger" onclick="deleteItem(\${item.id})">
                            🗑️ 删除
                        </button>
                    </div>
                </div>
            \`).join('');
            document.getElementById('itemsList').innerHTML = html || '<div class="loading">暂无数据</div>';
        }

        function updateStats(items) {
            document.getElementById('totalItems').textContent = items.length;
            document.getElementById('activeItems').textContent = 
                items.filter(i => i.status === 'active').length;
            document.getElementById('totalClicks').textContent = 
                items.reduce((sum, i) => sum + i.count, 0);
        }

        async function incrementCount(id) {
            await fetch(\`/api/items/\${id}/increment\`, { method: 'POST' });
            loadItems();
        }

        async function toggleStatus(id) {
            await fetch(\`/api/items/\${id}/toggle\`, { method: 'POST' });
            loadItems();
        }

        async function deleteItem(id) {
            if (confirm('确定要删除这个项目吗？')) {
                await fetch(\`/api/items/\${id}\`, { method: 'DELETE' });
                loadItems();
            }
        }

        async function addItem() {
            const name = document.getElementById('newItemName').value.trim();
            if (!name) {
                alert('请输入项目名称');
                return;
            }
            await fetch('/api/items', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            document.getElementById('newItemName').value = '';
            loadItems();
        }

        // 回车添加
        document.getElementById('newItemName').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') addItem();
        });

        // 初始加载
        loadItems();
    </script>
</body>
</html>
    `)
})

// API: 获取所有项目
app.get('/api/items', (req, res) => {
    res.json({ items })
})

// API: 添加项目
app.post('/api/items', (req, res) => {
    const { name } = req.body
    const newItem = {
        id: items.length > 0 ? Math.max(...items.map(i => i.id)) + 1 : 1,
        name,
        status: 'active',
        count: 0
    }
    items.push(newItem)
    res.json({ success: true, item: newItem })
})

// API: 增加计数
app.post('/api/items/:id/increment', (req, res) => {
    const item = items.find(i => i.id === parseInt(req.params.id))
    if (item) {
        item.count++
        res.json({ success: true, item })
    } else {
        res.status(404).json({ error: 'Item not found' })
    }
})

// API: 切换状态
app.post('/api/items/:id/toggle', (req, res) => {
    const item = items.find(i => i.id === parseInt(req.params.id))
    if (item) {
        item.status = item.status === 'active' ? 'inactive' : 'active'
        res.json({ success: true, item })
    } else {
        res.status(404).json({ error: 'Item not found' })
    }
})

// API: 删除项目
app.delete('/api/items/:id', (req, res) => {
    const index = items.findIndex(i => i.id === parseInt(req.params.id))
    if (index !== -1) {
        items.splice(index, 1)
        res.json({ success: true })
    } else {
        res.status(404).json({ error: 'Item not found' })
    }
})

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})