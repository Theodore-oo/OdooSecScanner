from fastapi import FastAPI, File, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import aiofiles
import os
import tempfile
from scanner import Scanner

app = FastAPI(title="Odoo Security Scanner (OWASP 2025)")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure static directory exists
os.makedirs("static", exist_ok=True)
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/js", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")

scanner = Scanner()

@app.get("/")
async def read_index():
    return FileResponse("static/index.html")

@app.post("/api/scan")
async def scan_module(file: UploadFile = File(...)):
    if not file.filename.endswith('.zip'):
        return JSONResponse(status_code=400, content={"error": "Only ZIP files are supported."})
        
    # Create a temporary file to save the uploaded zip
    fd, temp_path = tempfile.mkstemp(suffix=".zip")
    try:
        os.close(fd)
        async with aiofiles.open(temp_path, 'wb') as out_file:
            content = await file.read()
            await out_file.write(content)
            
        results = scanner.scan_zip(temp_path)
        return results
        
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
