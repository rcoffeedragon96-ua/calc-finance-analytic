@echo off
chcp 65001 > nul
echo ===================================================
echo Запуск BESS & Solar Calculator SaaS Server...
echo ===================================================
pip install -r requirements.txt
echo Відкрийте у браузері: http://localhost:8000
echo Логін адміна: admin@solar-bess.com.ua
echo Пароль:       AdminBess2026!
echo ===================================================
uvicorn bess_backend_server:app --host 0.0.0.0 --port 8000 --reload
pause
