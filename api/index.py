"""
VeriDex AI - Vercel Serverless Function & ASGI Entrypoint
Exports the FastAPI application instance for Vercel Serverless Python Runtime.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from api.server import app

# Vercel looks for 'app' or 'handler'
handler = app
