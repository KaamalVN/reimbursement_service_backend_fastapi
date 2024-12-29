from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # Import CORS middleware
from app.database import engine  # Adjusted to import from the app folder
from app.models import Base      # Importing Base from app.models
from app.routes import router     # Importing router from app.routes
import uvicorn                   # Import Uvicorn

# Initialize FastAPI app
app = FastAPI()

# Allow CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to your frontend's URL in production
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods
    allow_headers=["*"],   # Allows all headers
)

# Create tables
Base.metadata.create_all(bind=engine)

# Include routes
app.include_router(router)

@app.get("/")
def read_root():
    return {"message": "Welcome to the Reimbursement Service API!"}

# Run the server programmatically
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
