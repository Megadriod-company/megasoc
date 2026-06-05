# ==============================================================================
# MegaSOC Enterprise XDR - Tier 1 Global Backend
# Features: ML UEBA, Stateful Correlation, MQL, Multi-Tenancy, Multi-Step SOAR
# ==============================================================================

import os
import io
import re
import json
import time
import email
import socket
import ssl
import hashlib
import datetime
import ipaddress
import urllib.parse
from email.policy import default
from typing import List, Optional, Dict, Any, Union
from collections import defaultdict

# Core Web & Async
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request, BackgroundTasks, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates

# Database
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Float, JSON, func, and_
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

# Security & Crypto
import bcrypt
from jose import JWTError, jwt

# Forensics
import requests
import dns.resolver
from bs4 import BeautifulSoup
import pefile
import PyPDF2
from PIL import Image
from PIL.ExifTags import TAGS
import tldextract

# Machine Learning & Data Processing (UEBA)
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    ML_ENABLED = True
except ImportError:
    ML_ENABLED = False
    print("[WARNING] scikit-learn, numpy, or pandas not installed. UEBA ML features will be disabled.")

# ==============================================================================
# 1. CONFIGURATION (ADAPTED FOR ROBUST CLOUD POOLING)
# ==============================================================================
SECRET_KEY = os.getenv("MEGASOC_SECRET_KEY", "MEGADROID_ENTERPRISE_XDR_TIER1_2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440 

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./megasoc_xdr.db")

# Automatically adapt connection strategy based on Database engine
if "sqlite" in DATABASE_URL:
    engine = create_engine(
        DATABASE_URL, 
        connect_args={"check_same_thread": False}
    )
else:
    # Production Supabase / pg8000 pooled connection parameters
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,   # Heartbeats database sockets before sending SQL queries
        pool_recycle=300,     # Safely retires connections older than 5 minutes
        pool_size=10,         # Keeps a baseline of connections ready
        max_overflow=20       # Allows bursting for high concurrent loads
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
app = FastAPI(title="MegaSOC XDR Platform", version="4.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

os.makedirs("templates", exist_ok=True)
templates = Jinja2Templates(directory="templates")

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try: return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError: return False

# ==============================================================================
# 2. XDR DATABASE SCHEMA (MULTI-TENANT & RELATIONAL)
# ==============================================================================
class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    license_tier = Column(String, default="Enterprise")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="analyst")
    is_active = Column(Boolean, default=True)

class Agent(Base):
    __tablename__ = "agents"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True)
    agent_uuid = Column(String, unique=True, index=True)
    hostname = Column(String, index=True)
    os_version = Column(String)
    ip_address = Column(String)
    mac_address = Column(String)
    last_checkin = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="online")
    isolation_status = Column(Boolean, default=False)
    agent_health = Column(String, default="Healthy")
    risk_score = Column(Float, default=0.0)

class EventLog(Base):
    __tablename__ = "event_logs"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True)
    agent_id = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    event_source = Column(String, index=True)
    event_id = Column(Integer, index=True)
    severity = Column(Integer, index=True) 
    user_context = Column(String, nullable=True)
    process_name = Column(String, nullable=True)
    command_line = Column(Text, nullable=True)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    file_hash = Column(String, nullable=True)
    raw_data = Column(Text)
    parsed_json = Column(JSON)
    mitre_tactic = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)

class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    title = Column(String)
    status = Column(String, default="Open")
    severity = Column(String)
    mitre_tactics = Column(String)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    title = Column(String)
    description = Column(Text)
    severity = Column(String)
    evidence = Column(JSON)
    trigger_log_id = Column(Integer, ForeignKey("event_logs.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="New")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    agent_id = Column(String, ForeignKey("agents.agent_uuid"))
    software_name = Column(String)
    version = Column(String)
    cve_id = Column(String)
    cvss_score = Column(Float)
    detected_at = Column(DateTime, default=datetime.datetime.utcnow)

class AutomationRule(Base):
    __tablename__ = "automation_rules"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    name = Column(String)
    condition_json = Column(JSON) 
    playbook_steps = Column(JSON)
    is_active = Column(Boolean, default=True)

class PlaybookState(Base):
    __tablename__ = "playbook_states"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    rule_id = Column(Integer, ForeignKey("automation_rules.id"))
    trigger_log_id = Column(Integer, ForeignKey("event_logs.id"))
    current_step = Column(Integer, default=1)
    status = Column(String, default="Running")

class IRTask(Base):
    __tablename__ = "ir_tasks"
    id = Column(Integer, primary_key=True, index=True)
    agent_uuid = Column(String, index=True)
    command = Column(String) 
    parameters = Column(JSON)
    status = Column(String, default="pending") 
    result_data = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    executed_at = Column(DateTime, nullable=True)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# ==============================================================================
# 3. MULTI-TENANCY AUTHENTICATION
# ==============================================================================
def create_access_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta if expires_delta else datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.username == username).first()
    if user is None: raise HTTPException(status_code=401, detail="User not found")
    return user

# ==============================================================================
# 4. UEBA MACHINE LEARNING ENGINE
# ==============================================================================
class UEBAEngine:
    @staticmethod
    def train_and_predict(tenant_id: int, db: Session):
        if not ML_ENABLED: return
        
        logs = db.query(EventLog.agent_id, EventLog.event_id).filter(EventLog.tenant_id == tenant_id).all()
        if len(logs) < 100: return
        
        df = pd.DataFrame(logs, columns=['agent_id', 'event_id'])
        pivot = df.pivot_table(index='agent_id', columns='event_id', aggfunc=len, fill_value=0)
        
        model = IsolationForest(contamination=0.05, random_state=42)
        predictions = model.fit_predict(pivot)
        anomalous_agents = pivot.index[predictions == -1].tolist()
        
        for agent_id in anomalous_agents:
            case = Case(tenant_id=tenant_id, title=f"UEBA Anomaly: Deviant Behavior on {agent_id}", severity="High", mitre_tactics='["T1087"]')
            db.add(case)
            db.commit()
            
            alert = Alert(tenant_id=tenant_id, case_id=case.id, title="ML Behavior Deviation", description="IsolationForest algorithm detected abnormal event execution frequency compared to baseline.", severity="High")
            db.add(alert)
            
            agent = db.query(Agent).filter(Agent.agent_uuid == agent_id).first()
            if agent: agent.risk_score += 25.0
            db.commit()

# ==============================================================================
# 5. STATEFUL CORRELATION ENGINE
# ==============================================================================
class CorrelationEngine:
    @staticmethod
    def evaluate_state(log: EventLog, db: Session):
        if log.event_id == 4624 and log.source_ip:
            five_mins_ago = log.timestamp - datetime.timedelta(minutes=5)
            failed_attempts = db.query(EventLog).filter(
                EventLog.tenant_id == log.tenant_id,
                EventLog.source_ip == log.source_ip,
                EventLog.event_id == 4625,
                EventLog.timestamp >= five_mins_ago
            ).count()
            
            if failed_attempts >= 5:
                case = Case(tenant_id=log.tenant_id, title=f"Successful Brute Force from {log.source_ip}", severity="Critical", mitre_tactics='["T1110"]')
                db.add(case)
                db.commit()
                alert = Alert(tenant_id=log.tenant_id, case_id=case.id, title="Stateful Correlation Triggered", description=f"{failed_attempts} failures followed by success.", severity="Critical", trigger_log_id=log.id)
                db.add(alert)
                db.commit()

# ==============================================================================
# 6. MQL (MEGA QUERY LANGUAGE) PARSER
# ==============================================================================
class MQLParser:
    @staticmethod
    def execute(query: str, tenant_id: int, db: Session) -> Dict[str, Any]:
        parts = [p.strip() for p in query.split('|')]
        search_part = parts[0].replace("search ", "").strip()
        
        sql = db.query(EventLog).filter(EventLog.tenant_id == tenant_id)
        
        if "=" in search_part:
            key, val = search_part.split("=")
            if key == "event_id": sql = sql.filter(EventLog.event_id == int(val))
            elif key == "source_ip": sql = sql.filter(EventLog.source_ip == val.strip('"\''))
        elif search_part:
            sql = sql.filter(EventLog.raw_data.ilike(f"%{search_part}%"))
            
        results = sql.order_by(EventLog.timestamp.desc()).limit(1000).all()
        
        if len(parts) > 1 and parts[1].startswith("stats count by"):
            group_by_field = parts[1].replace("stats count by ", "").strip()
            stats = defaultdict(int)
            for r in results:
                val = getattr(r, group_by_field, "Unknown")
                stats[str(val)] += 1
            return {"type": "stats", "data": [{"key": k, "count": v} for k, v in stats.items()]}
            
        return {"type": "logs", "data": [r.__dict__ for r in results[:100]]}

# ==============================================================================
# 7. VULNERABILITY & ATTACK SURFACE ENGINE
# ==============================================================================
class VulnerabilityEngine:
    @staticmethod
    def scan_software(agent_id: str, software_list: List[dict], tenant_id: int, db: Session):
        cve_db = {
            "Chrome": {"bad_version": "100.0", "cve": "CVE-2022-1096", "cvss": 8.8},
            "Apache": {"bad_version": "2.4.49", "cve": "CVE-2021-41773", "cvss": 9.8}
        }
        
        for sw in software_list:
            name = sw.get("name", "")
            ver = sw.get("version", "")
            
            if name in cve_db and ver.startswith(cve_db[name]["bad_version"]):
                vuln = Vulnerability(tenant_id=tenant_id, agent_id=agent_id, software_name=name, version=ver, cve_id=cve_db[name]["cve"], cvss_score=cve_db[name]["cvss"])
                db.add(vuln)
                
                case = Case(tenant_id=tenant_id, title=f"Critical Vuln {vuln.cve_id} on {agent_id}", severity="High")
                db.add(case)
                
                agent = db.query(Agent).filter(Agent.agent_uuid == agent_id).first()
                if agent: agent.risk_score += vuln.cvss_score * 5
                
        db.commit()

# ==============================================================================
# 8. MULTI-STEP SOAR ENGINE (STATE MACHINE)
# ==============================================================================
class StatefulSOAR:
    @staticmethod
    def trigger(log: EventLog, db: Session):
        rules = db.query(AutomationRule).filter(AutomationRule.tenant_id == log.tenant_id, AutomationRule.is_active == True).all()
        for rule in rules:
            match = True
            cond = rule.condition_json
            if "event_id" in cond and log.event_id != cond["event_id"]: match = False
            
            if match:
                state = PlaybookState(tenant_id=log.tenant_id, rule_id=rule.id, trigger_log_id=log.id)
                db.add(state)
                db.commit()
                StatefulSOAR.execute_next_step(state.id, db)

    @staticmethod
    def execute_next_step(state_id: int, db: Session):
        state = db.query(PlaybookState).filter(PlaybookState.id == state_id).first()
        if not state or state.status != "Running": return
        
        rule = db.query(AutomationRule).filter(AutomationRule.id == state.rule_id).first()
        steps = rule.playbook_steps
        
        if state.current_step > len(steps):
            state.status = "Completed"
            db.commit()
            return
            
        current_action = steps[state.current_step - 1]
        
        if current_action["action"] == "approval":
            state.status = "Pending_Approval"
            db.commit()
            return
            
        if current_action["action"] == "isolate":
            log = db.query(EventLog).filter(EventLog.id == state.trigger_log_id).first()
            task = IRTask(agent_uuid=log.agent_id, command="isolate_network", parameters={})
            db.add(task)
            
        state.current_step += 1
        db.commit()
        StatefulSOAR.execute_next_step(state.id, db)

# ==============================================================================
# 9. PHISHING & THREAT INTEL ENGINES
# ==============================================================================
class PhishingEngine:
    @staticmethod
    def analyze_email(raw_eml: bytes) -> Dict[str, Any]:
        msg = email.message_from_bytes(raw_eml, policy=default)
        headers = {k: v for k, v in msg.items()}
        from_addr = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        subject = msg.get("Subject", "")
        auth_results = msg.get("Authentication-Results", "").lower()
        
        body_text, html_body = "", ""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdisp = str(part.get('Content-Disposition'))
                if "attachment" in cdisp:
                    payload = part.get_payload(decode=True) or b""
                    attachments.append({
                        "name": part.get_filename(),
                        "size": len(payload),
                        "md5": hashlib.md5(payload).hexdigest(),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "is_executable": part.get_filename().endswith(('.exe', '.js', '.vbs', '.bat'))
                    })
                elif ctype == "text/plain": body_text += part.get_payload(decode=True).decode('utf-8', 'ignore')
                elif ctype == "text/html": html_body += part.get_payload(decode=True).decode('utf-8', 'ignore')
        else:
            body_text = msg.get_payload(decode=True).decode('utf-8', 'ignore')

        heuristics = {
            "spf_pass": "spf=pass" in auth_results,
            "dkim_pass": "dkim=pass" in auth_results,
            "dmarc_pass": "dmarc=pass" in auth_results,
            "reply_to_mismatch": reply_to and (from_addr.split('<')[-1].strip('>') != reply_to.split('<')[-1].strip('>')),
            "freemail_sender": any(fm in from_addr.lower() for fm in ["gmail.com", "yahoo.com", "hotmail.com", "aol.com"]),
            "multiple_received_hops": len(msg.get_all("Received", [])) > 3,
            "missing_message_id": "Message-ID" not in headers,
            "urgency_keywords_present": any(w in subject.lower() + body_text.lower() for w in ["urgent", "wire transfer", "invoice"]),
            "crypto_address_present": bool(re.search(r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$', body_text)),
            "contains_iframe": "<iframe" in html_body.lower(),
            "executable_attachment": any(a["is_executable"] for a in attachments)
        }
        
        return {
            "metadata": {"sender": from_addr, "subject": subject, "date": msg.get("Date")},
            "attachments": attachments,
            "heuristics": heuristics,
            "total_risk_score": sum([10 for k, v in heuristics.items() if v and isinstance(v, bool) and "pass" not in k])
        }

class ThreatIntelEngine:
    @staticmethod
    def comprehensive_ip_lookup(ip: str) -> Dict[str, Any]:
        results = {"ip": ip, "is_private": ipaddress.ip_address(ip).is_private}
        if results["is_private"]: return results
        
        try:
            geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            results["geo"] = geo
        except: pass

        try:
            otx = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", timeout=5).json()
            if "pulse_info" in otx: results["alienvault_otx"] = {"pulse_count": otx.get("pulse_info", {}).get("count", 0)}
        except: pass
        
        return results

    @staticmethod
    def domain_lookup(domain: str) -> Dict[str, Any]:
        results = {"domain": domain}
        dns_data = {}
        for rtype in ['A', 'MX', 'TXT', 'NS']:
            try: dns_data[rtype] = [str(r) for r in dns.resolver.resolve(domain, rtype)]
            except: dns_data[rtype] = []
        results["dns_records"] = dns_data
        
        ext = tldextract.extract(domain)
        results["domain_structure"] = {"subdomain": ext.subdomain, "domain": ext.domain, "suffix": ext.suffix}
        results["is_homograph_suspect"] = any(ord(c) > 127 for c in domain) 
        return results

# ==============================================================================
# 10. EXTENDED INCIDENT RESPONSE (IR) CAPABILITIES - 37 COMMANDS
# ==============================================================================
IR_CAPABILITIES = [
    "kill_process", "suspend_process", "resume_process", 
    "get_process_tree", "dump_process_memory", 
    "isolate_network", "unisolate_network", "block_ip_firewall",
    "get_active_connections", "get_dns_cache", "flush_dns",
    "get_routing_table", "get_arp_cache", "clear_arp_cache",
    "get_firewall_rules", "get_autoruns", "query_registry", "delete_registry_key",
    "get_scheduled_tasks", "delete_scheduled_task", "get_wmi_persistence",
    "get_local_users", "disable_local_user", "get_local_groups",
    "lock_user_session", "logoff_user", "get_services", "stop_service", "start_service", 
    "get_system_info", "reboot_host", "shutdown_host",
    "fetch_file", "upload_file", "delete_file", "quarantine_file",
    "execute_powershell"
]

# ==============================================================================
# 11. ADVANCED XDR API ENDPOINTS
# ==============================================================================
def run_background_engines(event_id: int, tenant_id: int):
    """Executes engines post-ingestion utilizing a fresh, thread-safe DB Session"""
    db = SessionLocal()
    try:
        log = db.query(EventLog).filter(EventLog.id == event_id).first()
        if log:
            CorrelationEngine.evaluate_state(log, db)
            StatefulSOAR.trigger(log, db)
            if log.id % 100 == 0: 
                UEBAEngine.train_and_predict(tenant_id, db)
    finally:
        db.close()

@app.post("/api/auth/register")
def register_user(username: str = Form(...), email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username exists")
    # Assume default tenant for new direct registrations
    tenant = db.query(Tenant).first()
    new_user = User(username=username, email=email, hashed_password=get_password_hash(password), tenant_id=tenant.id)
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect credentials")
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/siem/ingest")
def ingest_logs(background_tasks: BackgroundTasks, logs: List[dict], db: Session = Depends(get_db)):
    for log_data in logs:
        agent = db.query(Agent).filter(Agent.agent_uuid == log_data.get("agent_uuid")).first()
        tenant_id = agent.tenant_id if agent else 1 
        
        new_event = EventLog(
            tenant_id=tenant_id,
            agent_id=log_data.get("agent_uuid"),
            event_source=log_data.get("source"),
            event_id=log_data.get("event_id"),
            severity=log_data.get("severity", 1),
            source_ip=log_data.get("src_ip"),
            raw_data=log_data.get("raw_text", "")
        )
        db.add(new_event)
        db.commit()
        db.refresh(new_event)
        # Passing event_id fixes the DetachedInstanceError
        background_tasks.add_task(run_background_engines, new_event.id, tenant_id)
    return {"status": "success"}

@app.post("/api/agents/checkin")
def agent_checkin(request: Request, data: dict, db: Session = Depends(get_db)):
    agent_uuid = data.get("agent_uuid")
    agent = db.query(Agent).filter(Agent.agent_uuid == agent_uuid).first()
    
    # Safe overwrite without triggering duplicate kwargs
    client_ip = request.client.host
    data["ip_address"] = client_ip 
    
    if not agent:
        if "tenant_id" not in data:
            data["tenant_id"] = 1
        agent = Agent(**data)
        db.add(agent)
    else:
        agent.last_checkin = datetime.datetime.utcnow()
        agent.status = "online"
        agent.ip_address = client_ip
    
    pending_tasks = db.query(IRTask).filter(IRTask.agent_uuid == agent.agent_uuid, IRTask.status == "pending").all()
    tasks_to_send = [{"id": t.id, "cmd": t.command, "params": t.parameters} for t in pending_tasks]
    for t in pending_tasks: t.status = "dispatched"
    
    db.commit()
    return {"status": "ok", "tasks": tasks_to_send, "isolate": agent.isolation_status}

@app.post("/api/mql/search")
def mql_search(query: dict, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q_str = query.get("query", "")
    return MQLParser.execute(q_str, user.tenant_id, db)

@app.get("/api/cases")
def get_cases(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Case).filter(Case.tenant_id == user.tenant_id).order_by(Case.created_at.desc()).all()

@app.get("/api/siem/stats")
def siem_stats(db: Session = Depends(get_db)):
    total_events = db.query(EventLog).count()
    top_agents = db.query(EventLog.agent_id, func.count(EventLog.id)).group_by(EventLog.agent_id).limit(5).all()
    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(5).all()
    active_agents = db.query(Agent).filter(Agent.status == "online").count()
    return {
        "total_events": total_events,
        "active_agents": active_agents,
        "top_agents": [{"agent": a[0], "count": a[1]} for a in top_agents],
        "recent_alerts": recent_alerts
    }

@app.post("/api/agents/vuln_scan")
def ingest_vuln_scan(data: dict, db: Session = Depends(get_db)):
    agent_id = data.get("agent_uuid")
    software_list = data.get("software", [])
    agent = db.query(Agent).filter(Agent.agent_uuid == agent_id).first()
    if agent:
        VulnerabilityEngine.scan_software(agent_id, software_list, agent.tenant_id, db)
    return {"status": "scanned"}

@app.post("/api/ir/task")
async def create_ir_task(request: Request, db: Session = Depends(get_db)):
    agent_uuid = request.query_params.get("agent_uuid")
    command = request.query_params.get("command")
    
    try: params = await request.json()
    except Exception: params = {}
    
    if command not in IR_CAPABILITIES: raise HTTPException(status_code=400, detail="Invalid IR Command")
    
    task = IRTask(agent_uuid=agent_uuid, command=command, parameters=params)
    db.add(task)
    db.commit()
    return {"task_id": task.id, "status": "queued"}

@app.get("/api/ir/task/{task_id}")
def get_task_status(task_id: int, db: Session = Depends(get_db)):
    """Allows the frontend to poll for live command results instantly"""
    task = db.query(IRTask).filter(IRTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task_id": task.id, "status": task.status, "output": task.result_data}

@app.post("/api/agents/task_result")
def agent_task_result(result_data: dict, db: Session = Depends(get_db)):
    task = db.query(IRTask).filter(IRTask.id == result_data.get("task_id")).first()
    if task:
        task.status = result_data.get("status")
        task.result_data = result_data.get("output")
        task.executed_at = datetime.datetime.utcnow()
        db.commit()
        return {"status": "recorded"}
    raise HTTPException(status_code=404, detail="Task not found")

@app.post("/api/soar/approve_playbook")
def approve_playbook(state_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    state = db.query(PlaybookState).filter(PlaybookState.id == state_id, PlaybookState.tenant_id == user.tenant_id).first()
    if state and state.status == "Pending_Approval":
        state.status = "Running"
        state.current_step += 1
        db.commit()
        StatefulSOAR.execute_next_step(state.id, db)
        return {"status": "Playbook Resumed"}
    raise HTTPException(status_code=400, detail="Invalid playbook state")

@app.post("/api/forensics/analyze_email")
async def analyze_phishing_email(file: UploadFile = File(...)):
    raw = await file.read()
    return PhishingEngine.analyze_email(raw)

@app.get("/api/threat_intel/lookup")
def threat_intel_lookup(indicator: str, type: str = "ip"):
    if type == "ip": return ThreatIntelEngine.comprehensive_ip_lookup(indicator)
    if type == "domain": return ThreatIntelEngine.domain_lookup(indicator)
    return {"error": "Unsupported type"}

# ==============================================================================
# 12. PAGES
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
def read_home(request: Request):
    return templates.TemplateResponse(request, "home.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
def read_login(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
def read_register(request: Request):
    return templates.TemplateResponse(request, "register.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
def read_dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {"request": request})

@app.get("/siem-logs", response_class=HTMLResponse)
def read_siem(request: Request):
    return templates.TemplateResponse(request, "siem_logs.html", {"request": request})

@app.get("/incident-response", response_class=HTMLResponse)
def read_ir(request: Request):
    return templates.TemplateResponse(request, "incident_response.html", {"request": request})

@app.get("/threat-intel", response_class=HTMLResponse)
def read_ti(request: Request):
    return templates.TemplateResponse(request, "threat_intel.html", {"request": request})

@app.get("/soar-automation", response_class=HTMLResponse)
def read_soar(request: Request):
    return templates.TemplateResponse(request, "soar_automation.html", {"request": request})

@app.get("/phishing-analyzer", response_class=HTMLResponse)
def read_phishing(request: Request):
    return templates.TemplateResponse(request, "phishing_analyzer.html", {"request": request})

@app.get("/agent-management", response_class=HTMLResponse)
def read_agent_management(request: Request):
    return templates.TemplateResponse(request, "agent_management.html", {"request": request})

@app.get("/logo.png")
async def serve_logo():
    logo_path = os.path.join("templates", "logo.png")
    if not os.path.isfile(logo_path):
        raise HTTPException(status_code=404, detail="Logo not found")
    return FileResponse(logo_path, media_type="image/png")

# Initialize DB on Startup
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    if not db.query(Tenant).first():
        tenant = Tenant(name="Global_Enterprise_Alpha")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        
        db.add(User(tenant_id=tenant.id, username="admin", email="admin@megadroid.local", hashed_password=get_password_hash("admin123"), role="admin"))
        db.add(AutomationRule(
            tenant_id=tenant.id,
            name="Ransomware Containment (Human-in-Loop)",
            condition_json={"event_id": 4688},
            playbook_steps=[
                {"step": 1, "action": "alert"}, 
                {"step": 2, "action": "approval"},
                {"step": 3, "action": "isolate"}
            ]
        ))
        db.commit()
    db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
