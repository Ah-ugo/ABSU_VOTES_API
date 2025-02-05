from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pymongo import MongoClient
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from pydantic import BaseModel
from typing import List, Optional
import random
from bson import ObjectId
import os
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
from fastapi.encoders import jsonable_encoder

load_dotenv()

url = os.getenv("MONGO_URL")
# Database setup
client = MongoClient(url)
db = client["absu_voting"]

# Authentication setup
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

cloudinary.config(
    cloud_name=os.getenv("CLOUD_NAME"),
    api_key=os.getenv("API_KEY"),
    api_secret=os.getenv("API_SECRET")
)

app = FastAPI()


# Models
class Student(BaseModel):
    first_name: str
    last_name: str
    matric_no: str
    department: str
    password: str
    profile_image: Optional[str] = None


class Admin(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str


class Election(BaseModel):
    session: str
    positions: List[str]
    candidates: List[dict]
    start_time: datetime
    end_time: datetime


class Candidate(BaseModel):
    name: str
    position: str
    image: str
    manifesto: str
    accomplishments: List[str]
    election_id: str


class Vote(BaseModel):
    election_id: str
    voter_id: str
    candidate_id: str
    position: str


class Announcement(BaseModel):
    title: str
    message: str
    created_at: datetime = datetime.utcnow()


# Hashing passwords
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# Token generation
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Authentication dependencies
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.students.find_one({"matric_no": payload["sub"]})
        if user:
            return user
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_admin_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload["sub"]  # Get the user ID
        user = db.admins.find_one({"_id": ObjectId(user_id)})  # Check by ID instead of email

        if user:
            return user
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")



# Auth Routes
@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user_collection = db["students"]
    admin_collection = db["admins"]

    user = user_collection.find_one({"matric_no": form_data.username})
    if not user:
        user = admin_collection.find_one({"email": form_data.username})

    if not user or not pwd_context.verify(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.encode({"sub": str(user["_id"])}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token, "token_type": "bearer", "role": "admin" if "email" in user else "student"}



@app.post("/register/student/")
def register_student(
    first_name: str = Form(...),
    last_name: str = Form(...),
    matric_no: str = Form(...),
    department: str = Form(...),
    password: str = Form(...),
    profile_image: UploadFile = File(...)
):
    collection = db["students"]
    result = cloudinary.uploader.upload(profile_image.file)
    profile_image_url = result["secure_url"]
    student_data = {
        "first_name": first_name,
        "last_name": last_name,
        "matric_no": matric_no,
        "department": department,
        "password": pwd_context.hash(password),
        "profile_image": profile_image_url
    }
    student_id = collection.insert_one(student_data).inserted_id
    return {"id": str(student_id)}


@app.post("/register/admin/")
def register_admin(
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    profile_image: UploadFile = File(...)
):
    collection = db["admins"]
    result = cloudinary.uploader.upload(profile_image.file)
    profile_image_url = result["secure_url"]
    admin_data = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password": pwd_context.hash(password),
        "profile_image": profile_image_url
    }
    admin_id = collection.insert_one(admin_data).inserted_id
    return {"id": str(admin_id)}


@app.get("/current-user/")
def get_current_user(token: str = Depends(oauth2_scheme)):
    user_collection = db["students"]
    admin_collection = db["admins"]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")

        user = user_collection.find_one({"_id": ObjectId(user_id)}) or admin_collection.find_one(
            {"_id": ObjectId(user_id)})

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Convert ObjectId to string and remove the raw _id field to avoid serialization issues
        user["id"] = str(user["_id"])
        del user["_id"]

        return {"role": "admin" if "email" in user else "student", **user}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.DecodeError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Election Routes
@app.post("/elections/")
def create_election(election: Election, admin: dict = Depends(get_admin_user)):
    election_id = db.elections.insert_one(election.dict()).inserted_id
    return {"id": str(election_id)}


@app.get("/elections/")
def get_elections():
    collection = db["elections"]
    elections = list(collection.find())

    # Convert ObjectId to string
    for election in elections:
        election["_id"] = str(election["_id"])

    return jsonable_encoder(elections)

@app.delete("/elections/{election_id}")
def delete_election(election_id: str):
    collection = db["elections"]
    result = collection.delete_one({"_id": ObjectId(election_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Election not found")
    return {"message": "Election deleted successfully"}


@app.get("/election-positions/")
def get_election_positions():
    collection = db["elections"]
    positions = set()
    for election in collection.find():
        positions.update(election.get("positions", []))
    return list(positions)


@app.post("/election-positions/")
def add_election_positions(session: str, positions: List[str]):
    collection = db["elections"]
    election_id = collection.insert_one({"session": session, "positions": positions}).inserted_id
    return {"id": str(election_id)}


@app.get("/position-candidates/{position}")
async def get_position_candidates(position: str):
    try:
        # Case-insensitive search for positions containing the query
        candidates = db.candidates.find({"position": {"$regex": position, "$options": "i"}})

        # Convert ObjectId to string before returning response
        result = []
        for candidate in candidates:
            candidate["_id"] = str(candidate["_id"])  # Convert ObjectId to string
            result.append(candidate)

        if not result:
            raise HTTPException(status_code=404, detail="No candidates found")

        return jsonable_encoder(result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/position-results/{position}")
def get_position_result(position: str):
    votes_collection = db["votes"]
    candidates_collection = db["candidates"]

    votes = list(votes_collection.find({"position": position}))
    results = {}
    for vote in votes:
        candidate_id = str(vote["candidate_id"])
        results[candidate_id] = results.get(candidate_id, 0) + 1

    candidates = {str(c["_id"]): c["name"] for c in candidates_collection.find({"position": position})}

    return {candidates[c_id]: count for c_id, count in results.items()}


# Candidate Routes
@app.post("/candidates/")
def create_candidate(
    election_id: str = Form(...),
    name: str = Form(...),
    position: str = Form(...),
    short_description: str = Form(...),
    accomplishments: str = Form(...),
    manifesto: str = Form(...),
    image: UploadFile = File(...)
):
    collection = db["candidates"]
    result = cloudinary.uploader.upload(image.file)
    image_url = result["secure_url"]
    candidate_data = {
        "election_id": election_id,
        "name": name,
        "position": position,
        "image_url": image_url,
        "short_description": short_description,
        "accomplishments": accomplishments.split(","),
        "manifesto": manifesto
    }
    candidate_id = collection.insert_one(candidate_data).inserted_id
    return {"id": str(candidate_id)}


@app.get("/candidates/{election_id}")
def get_candidates(election_id: str):
    candidates = list(db.candidates.find({"election_id": election_id}))
    for candidate in candidates:
        candidate["_id"] = str(candidate["_id"])
    return candidates


@app.get("/candidate/{candidate_id}")
def get_candidate_profile(candidate_id: str):
    collection = db["candidates"]
    candidate = collection.find_one({"_id": ObjectId(candidate_id)})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    candidate["_id"] = str(candidate["_id"])  # Convert ObjectId to string
    return candidate



@app.put("/candidates/{candidate_id}")
def update_candidate(candidate_id: str, candidate: Candidate):
    collection = db["candidates"]
    result = collection.update_one({"_id": ObjectId(candidate_id)}, {"$set": candidate.dict()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Candidate not found")
    return {"message": "Candidate updated successfully"}


@app.delete("/candidates/{candidate_id}")
def delete_candidate(candidate_id: str):
    collection = db["candidates"]
    result = collection.delete_one({"_id": ObjectId(candidate_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Candidate not found")
    return {"message": "Candidate deleted successfully"}


# Voting Routes
@app.post("/votes/")
def cast_vote(vote: Vote, student: dict = Depends(get_current_user)):
    existing_vote = db.votes.find_one({"election_id": vote.election_id, "voter_id": student["matric_no"]})
    if existing_vote:
        raise HTTPException(status_code=400, detail="Voter has already voted.")
    vote_id = db.votes.insert_one(vote.dict()).inserted_id
    return {"id": str(vote_id)}


@app.get("/results/{election_id}")
def get_results(election_id: str):
    election = db.elections.find_one({"_id": ObjectId(election_id)})

    if not election:
        raise HTTPException(status_code=404, detail="Election not found")

    results = {}
    for position in election.get("positions", []):
        candidates = list(db.votes.aggregate([
            {"$match": {"election_id": str(election_id), "position": position}},  # Ensure election_id is a string
            {"$group": {"_id": "$candidate_id", "votes": {"$sum": 1}}},
            {"$sort": {"votes": -1}}
        ]))
        results[position] = candidates

    return results


# Timed Candidate Rotation
@app.get("/candidates_of_the_hour/{election_id}")
def candidates_of_the_hour(election_id: str):
    candidates = list(db.candidates.find({"election_id": election_id}))
    selected = {}

    for position in set(c["position"] for c in candidates):
        chosen_candidate = random.choice([c for c in candidates if c["position"] == position])

        # Convert ObjectId to string
        chosen_candidate["_id"] = str(chosen_candidate["_id"])

        selected[position] = chosen_candidate

    return selected


@app.get("/votes/by-department/{department}")
def get_votes_by_department(department: str):
    collection = db["votes"]
    votes = list(collection.find({"department": department}))
    return votes


@app.get("/votes/top-candidates")
def get_top_candidates():
    collection = db["votes"]
    pipeline = [
        {"$group": {"_id": "$candidate_id", "votes": {"$sum": 1}, "position": {"$first": "$position"}}},
        {"$sort": {"votes": -1}},
        {"$group": {"_id": "$position", "top_candidate": {"$first": "$$ROOT"}}},
        {"$replaceRoot": {"newRoot": "$top_candidate"}}
    ]
    results = list(collection.aggregate(pipeline))
    return results


@app.post("/announcements/")
def create_announcement(announcement: Announcement):
    collection = db["announcements"]
    announcement_id = collection.insert_one(announcement.dict()).inserted_id
    return {"id": str(announcement_id)}


@app.get("/announcements/")
def get_announcements():
    collection = db["announcements"]
    announcements = list(collection.find())

    # Convert each MongoDB document properly
    return [{"id": str(a["_id"]), **{k: v for k, v in a.items() if k != "_id"}} for a in announcements]



@app.delete("/announcements/{announcement_id}")
def delete_announcement(announcement_id: str):
    collection = db["announcements"]
    result = collection.delete_one({"_id": ObjectId(announcement_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Announcement not found")
    return {"message": "Announcement deleted successfully"}