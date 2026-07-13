from fastapi import FastAPI

app = FastAPI()
raise RuntimeError("detector must never import this module")
