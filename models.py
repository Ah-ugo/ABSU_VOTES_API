from datetime import datetime, timedelta
from pydantic import BaseModel


class Election(BaseModel):
    title: str
    description: str
    start_date: str
    end_date: str

class Candidate(BaseModel):
    election_id: str
    name: str
    party: str
    manifesto: str

class Vote(BaseModel):
    election_id: str
    candidate_id: str
    voter_id: str

class Announcement(BaseModel):
    election_id: str
    message: str
    date: str


class StudentRegister(BaseModel):
    first_name: str
    last_name: str
    matric_no: str
    profile_image: str
    department: str
    password: str

class AdminRegister(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str


class TokenData(BaseModel):
    matric_no: str = None
    email: str = None
    role: str
