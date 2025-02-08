from fastapi import FastAPI, Depends, HTTPException, status, File, Path, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pymongo import MongoClient
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
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
from pymongo import DESCENDING

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


def convert_objectid(data):
    """ Recursively convert ObjectId fields in a dictionary or list to strings. """
    if isinstance(data, dict):
        return {key: convert_objectid(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_objectid(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    return data


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


elections = {}


def get_election_status(election: Election):
    current_time = datetime.utcnow()
    if current_time < election.start_time:
        return "not started"
    elif election.start_time <= current_time <= election.end_time:
        return "ongoing"
    else:
        return "ended"


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

@app.get("/latest-election")
def get_latest_election():
    collection = db["elections"]
    latest_election = collection.find_one(
        sort=[("start_time", -1)])  # Assuming you're sorting by start_time to get the latest election

    if not latest_election:
        raise HTTPException(status_code=404, detail="No elections found")

    # Convert ObjectId to string for serializability
    latest_election["_id"] = str(latest_election["_id"])

    election_session = latest_election.get("session", "No session available")  # Use .get() to avoid KeyError

    return {
        "id": latest_election["_id"],
        "session": election_session,
        "start_time": latest_election["start_time"],
        "end_time": latest_election["end_time"],
    }


@app.post("/elections/")
def create_election(election: Election):
    election_data = election.dict()
    election_data["created_at"] = datetime.utcnow()
    election_id = db.elections.insert_one(election_data).inserted_id
    return {"id": str(election_id)}


@app.get("/election-status/{election_id}")
def get_election_status(election_id: str):
    election = db.elections.find_one({"_id": ObjectId(election_id)})
    if not election:
        raise HTTPException(status_code=404, detail="Election not found")

    now = datetime.utcnow()
    start_time = election["start_time"]
    end_time = election["end_time"]

    if now < start_time:
        status = "upcoming"
    elif start_time <= now <= end_time:
        status = "ongoing"
    else:
        status = "ended"

    return {"status": status, "start_time": start_time, "end_time": end_time}


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
def add_election_positions(election_id: str, positions: List[str]):
    result = db.elections.update_one(
        {"_id": ObjectId(election_id)},
        {"$addToSet": {"positions": {"$each": positions}}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Election not found")
    return {"message": "Positions added successfully"}


@app.get("/position-candidates/{election_id}/{position}")
def get_position_candidates(election_id: str, position: str):
    candidates = list(db.candidates.find({"election_id": election_id, "position": position}))
    for candidate in candidates:
        candidate["_id"] = str(candidate["_id"])
    return jsonable_encoder(candidates)


@app.get("/positions/{election_id}")
def get_positions(election_id: str):
    election = db.elections.find_one({"_id": ObjectId(election_id)})

    if not election:
        raise HTTPException(status_code=404, detail="Election not found")

    # Return positions available in the election
    return {"positions": election.get("positions", [])}



@app.get("/get_position_result/{election_id}/{position}")
def get_position_result(election_id: str, position: str):
    votes = list(db.votes.aggregate([
        {"$match": {"election_id": election_id, "position": position}},
        {"$group": {"_id": "$candidate_id", "count": {"$sum": 1}}},
        {"$sort": {"count": DESCENDING}}
    ]))

    results = []
    for vote in votes:
        candidate = db.candidates.find_one({"_id": ObjectId(vote["_id"])})
        if candidate:
            results.append({
                "candidate_id": vote["_id"],
                "candidate_name": candidate["name"],
                "vote_count": vote["count"]
            })

    return jsonable_encoder(results)


# Candidate Routes
# Candidate Routes
@app.post("/candidates/")
def create_candidate(
        election_id: str = Form(...),
        name: str = Form(...),
        position: str = Form(...),
        short_description: str = Form(...),
        accomplishments: List[str] = Form(...),  # Expecting a list of strings
        manifesto: str = Form(...),
        image: UploadFile = File(...),
        admin: dict = Depends(get_admin_user)
):
    # Upload image to Cloudinary
    collection = db["candidates"]
    result = cloudinary.uploader.upload(image.file)
    image_url = result["secure_url"]

    # Create candidate data
    candidate_data = {
        "election_id": election_id,
        "name": name,
        "position": position,
        "image_url": image_url,
        "short_description": short_description,
        "accomplishments": accomplishments,  # Now directly a list of strings
        "manifesto": manifesto
    }

    # Insert candidate data into MongoDB
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
    # Fetch election details to check status
    election = db.elections.find_one({"_id": ObjectId(vote.election_id)})
    if not election:
        raise HTTPException(status_code=404, detail="Election not found.")

    current_time = datetime.utcnow()
    if current_time < election["start_time"]:
        raise HTTPException(status_code=400, detail="Election has not started yet.")
    if current_time > election["end_time"]:
        raise HTTPException(status_code=400, detail="Election has ended.")

    # Check if the voter has already voted for this position in the same election
    existing_vote = db.votes.find_one({
        "election_id": vote.election_id,
        "voter_id": student["matric_no"],
        "position": vote.position  # Ensure position uniqueness
    })

    if existing_vote:
        raise HTTPException(status_code=400, detail="Voter has already voted for this position.")

    # Insert the vote
    vote_data = vote.dict()
    vote_data["voter_id"] = student["matric_no"]  # Ensure voter identity is stored
    vote_id = db.votes.insert_one(vote_data).inserted_id

    return {"id": str(vote_id)}


# FastAPI endpoint example
@app.get("/has-voted/{election_id}/{voter_id:path}/{candidate_id}")
def has_voted(election_id: str, voter_id: str, candidate_id: str):
    vote = db.votes.find_one({
        "election_id": election_id,
        "voter_id": voter_id,
        "candidate_id": candidate_id
    })

    return {"voted": bool(vote)}


@app.get("/election-timer/{election_id}")
def get_election_timer(election_id: str):
    try:
        election = db.elections.find_one({"_id": ObjectId(election_id)})

        if not election:
            raise HTTPException(status_code=404, detail="Election not found.")

        current_time = datetime.now(timezone.utc)

        start_time = election.get("start_time")
        end_time = election.get("end_time")

        # Ensure start_time and end_time exist
        if not start_time or not end_time:
            raise HTTPException(status_code=500, detail="Missing election time data.")

        # Convert MongoDB datetime to timezone-aware UTC
        if isinstance(start_time, datetime):
            start_time = start_time.replace(tzinfo=timezone.utc)
        if isinstance(end_time, datetime):
            end_time = end_time.replace(tzinfo=timezone.utc)

        # Determine election phase and countdown
        if current_time < start_time:
            phase = "Before Election"
            time_remaining = max(0, (start_time - current_time).total_seconds())
            target_date = start_time.isoformat()
        elif current_time < end_time:
            phase = "During Election"
            time_remaining = max(0, (end_time - current_time).total_seconds())
            target_date = end_time.isoformat()
        else:
            phase = "Election Ended"
            time_remaining = 0
            target_date = end_time.isoformat()

        return {
            "phase": phase,
            "targetDate": target_date,
            "timeRemaining": time_remaining
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/results/{election_id}")
def get_results(election_id: str):
    """Fetch election results grouped by position"""

    existing_votes = list(db.votes.find({"election_id": election_id}))

    if not existing_votes:
        raise HTTPException(status_code=404, detail="No votes found for this election.")

    # 🔹 Aggregation Pipeline to count votes per candidate per position
    pipeline = [
        {"$match": {"election_id": election_id}},  # Filter by election_id
        {"$group": {
            "_id": {"position": "$position", "candidate_id": "$candidate_id"},
            "votes": {"$sum": 1}  # Count votes per candidate
        }},
        {"$sort": {"_id.position": 1, "votes": -1}},  # Sort by position and votes
    ]

    aggregated_results = list(db.votes.aggregate(pipeline))

    # 🔹 Reformat results grouped by position
    results_by_position = {}

    for item in aggregated_results:
        position = item["_id"]["position"]
        candidate_id = str(item["_id"]["candidate_id"])  # Convert ObjectId to string
        votes = item["votes"]

        # Group candidates by position
        if position not in results_by_position:
            results_by_position[position] = []

        results_by_position[position].append({
            "position": position,
            "candidate_id": candidate_id,
            "votes": votes
        })

    return {"election_id": election_id, "results": results_by_position}


@app.get("/election-results/{election_id}")
def get_election_results(election_id: str):
    # Aggregate votes grouped by position and candidate, sorted by highest votes first
    votes = list(db.votes.aggregate([
        {"$match": {"election_id": election_id}},
        {"$group": {"_id": {"position": "$position", "candidate_id": "$candidate_id"}, "count": {"$sum": 1}}},
        {"$sort": {"_id.position": 1, "count": -1}}
    ]))

    results = {}
    for vote in votes:
        position = vote["_id"]["position"]
        candidate_id = vote["_id"]["candidate_id"]
        candidate = db.candidates.find_one({"_id": ObjectId(candidate_id)})

        if candidate:
            candidate_result = {
                "candidate_id": candidate_id,
                "candidate_name": candidate["name"],
                "vote_count": vote["count"]
            }
            if position not in results:
                results[position] = []
            results[position].append(candidate_result)

    return jsonable_encoder(results)


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


@app.get("/votes/by-department/{election_id}/{department}")
def get_votes_by_department(election_id: str, department: str):
    collection = db["votes"]
    votes = list(collection.find({"election_id": election_id, "department": department}))

    if not votes:
        raise HTTPException(status_code=404, detail="No votes found for this department in the given election")

    return votes


@app.get("/votes/top-candidates/{election_id}")
def get_top_candidates(election_id: str):
    collection = db["votes"]
    pipeline = [
        {"$match": {"election_id": election_id}},  # Filter by election_id
        {"$group": {
            "_id": "$candidate_id",
            "votes": {"$sum": 1},
            "position": {"$first": "$position"},
            "election_id": {"$first": "$election_id"}
        }},
        {"$sort": {"votes": -1}},  # Sort by votes
        {"$group": {
            "_id": "$position",
            "top_candidate": {"$first": "$$ROOT"}
        }},
        {"$replaceRoot": {"newRoot": "$top_candidate"}}
    ]
    results = list(collection.aggregate(pipeline))

    if not results:
        raise HTTPException(status_code=404, detail="No top candidates found for this election")

    return results


# Announcement Routes
@app.post("/announcements/")
def create_announcement(announcement: Announcement, election_id: str):
    collection = db["announcements"]
    announcement_data = {**announcement.dict(), "election_id": election_id}
    announcement_id = collection.insert_one(announcement_data).inserted_id
    return {"id": str(announcement_id)}


@app.get("/announcements/{election_id}")
def get_announcements(election_id: str):
    collection = db["announcements"]
    announcements = list(collection.find({"election_id": election_id}))

    return [{"id": str(a["_id"]), **{k: v for k, v in a.items() if k != "_id"}} for a in announcements]


@app.delete("/announcements/{announcement_id}")
def delete_announcement(announcement_id: str):
    collection = db["announcements"]
    result = collection.delete_one({"_id": ObjectId(announcement_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Announcement not found")
    return {"message": "Announcement deleted successfully"}
