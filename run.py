"""Uygulamayı başlatır (waitress). Servis olarak: python run.py"""
import config
from app import create_app

app = create_app()

if __name__ == "__main__":
    from waitress import serve
    print(f"Picus × Cloudflare WAF Platformu: http://{config.HOST}:{config.PORT}")
    serve(app, host=config.HOST, port=config.PORT, threads=8)
