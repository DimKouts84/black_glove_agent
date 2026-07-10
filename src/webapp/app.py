"""FastAPI application factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from agent.db import init_db, run_migrations
from agent.run_recovery import recover_stale_runs
from webapp.routes import router as api_router
from webapp.websocket import ws_router

STATIC_DIR = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    init_db()
    run_migrations()
    recover_stale_runs()

    app = FastAPI(
        title="Black Glove",
        description="Local-first penetration testing agent web UI",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://127.0.0.1:8787"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router)
    app.include_router(ws_router)

    if STATIC_DIR.exists():
        assets_dir = STATIC_DIR / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/{full_path:path}")
        async def serve_spa(full_path: str):
            index = STATIC_DIR / "index.html"
            file_path = STATIC_DIR / full_path
            if file_path.is_file() and full_path != "":
                return FileResponse(file_path)
            if index.exists():
                return FileResponse(index)
            return {"message": "Black Glove API running. Build frontend to enable UI."}

    return app
