## 使用介绍

### 安装Node.js之后
cd frontend
```npm
npm install   
```
### 启动

```npm
npm run dev
```

### 拓扑图部分使用了FastAPI实时获取agents列表：
### 安装依赖：
```pip
pip install fastapi uvicorn requests
```
### 在打开前端之前，找到：server\get_data.py并点击右上角运行该脚本
### 或者直接运行：
```uvicorn
uvicorn get_data:app --reload --host 0.0.0.0 --port 8000
```
### 拓扑图使用了X6绘制：
### 安装X6:
```npm
npm install @antv/x6 --save
```

### 要配置python3.12环境
```pip
pip install python-dotenv
```
```pip
pip install fastapi uvicorn requests python-dotenv -i https://pypi.tuna.tsinghua.edu.cn/simple

```

### 解决get_data.py导入问题：
选择解释器路径：D:\combine\wazuh_ai_agent\frontend\.venv\Scripts\python.exe