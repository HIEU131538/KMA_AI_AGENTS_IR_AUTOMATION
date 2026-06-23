import logging
import time
import threading
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from typing import Optional

# ==========================================
# CẤU HÌNH LOGGING
# ==========================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ==========================================
# IMPORT GRAPH 
# ==========================================
from core.graph import soc_app as langgraph_app
from agent.nodes.extractor import node_extractor  # Pre-filter tier 1


# ==========================================
# KHỞI TẠO APP & BỘ NHỚ TOÀN CỤC
# ==========================================
app = FastAPI(title="KMA SOC AI Agent API", version="2.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # friend's system on Tailscale
    allow_methods=["*"],
    allow_headers=["*"],
)

# TODO Week Final: Replace in-memory list with Redis/SQLite for production persistence.
GLOBAL_TIMELINE_MEMORY = []
MAX_TIMELINE_SIZE = 500
_timeline_lock = threading.Lock()   # bảo vệ GLOBAL_TIMELINE_MEMORY khỏi race condition
_batch_context = threading.local()  # flag per-thread để phân biệt batch call vs live call

# ==========================================
# CHROMADB INTEGRITY MONITOR (Phase 3 defense)
# Chạy background — poll ChromaDB mỗi 30s để phát hiện document mới
# được inject từ bên ngoài (RAG Poisoning). Nếu phát hiện → tạo
# synthetic log event và đẩy qua pipeline để agent tự cảnh báo.
# ==========================================
_CHROMA_MONITOR_INTERVAL = 30          # giây
_KNOWN_DOC_IDS: set = set()            # track IDs đã biết
_TRUSTED_SOURCE_TYPES = {"admin_sigma_rule", "mitre_framework"}

def _chroma_monitor_loop():
    """Background thread: phát hiện document lạ inject vào ChromaDB."""
    import os
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings

    # Khởi tạo kết nối — dùng cùng path với Retriever
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        chroma_path = os.path.abspath(os.path.join(current_dir, "../chroma_db"))
        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        db = Chroma(persist_directory=chroma_path, embedding_function=embeddings)
        logger.info("[ChromaMonitor] Khởi động thành công.")
    except Exception as e:
        logger.error(f"[ChromaMonitor] Không thể khởi tạo: {e}")
        return

    # Lần đầu: ghi nhớ toàn bộ IDs hiện có là "sạch"
    try:
        all_existing = db.get()
        for doc_id in all_existing.get("ids", []):
            _KNOWN_DOC_IDS.add(doc_id)
        logger.info(f"[ChromaMonitor] Baseline: {len(_KNOWN_DOC_IDS)} documents tin cậy.")
    except Exception as e:
        logger.warning(f"[ChromaMonitor] Không thể lấy baseline: {e}")

    while True:
        time.sleep(_CHROMA_MONITOR_INTERVAL)
        try:
            current = db.get(include=["metadatas"])
            current_ids      = set(current.get("ids", []))
            current_metas    = {
                did: meta
                for did, meta in zip(
                    current.get("ids", []),
                    current.get("metadatas", [{}] * len(current.get("ids", [])))
                )
            }
            new_ids = current_ids - _KNOWN_DOC_IDS
            if not new_ids:
                continue

            # Có document mới — kiểm tra xem có đáng ngờ không
            suspicious_new = []
            for did in new_ids:
                meta  = current_metas.get(did, {})
                src   = meta.get("source_type", "")
                inj   = meta.get("injected_by", "")
                dtype = meta.get("document_type", "")
                suspicious = (
                    src not in _TRUSTED_SOURCE_TYPES
                    or inj not in (None, "", "sigma_ingest", "mitre_ingest", "admin_loader")
                    or dtype in ("policy_update", "sync_update")
                )
                if suspicious:
                    suspicious_new.append({"id": did, "source_type": src,
                                           "injected_by": inj, "document_type": dtype,
                                           "trust_score": meta.get("trust_score", 0)})
                _KNOWN_DOC_IDS.add(did)  # đánh dấu đã biết dù suspicious

            if suspicious_new:
                logger.warning(
                    f"[ChromaMonitor] PHÁT HIỆN {len(suspicious_new)} document nghi ngờ: {suspicious_new}"
                )
                # Tạo synthetic security event → đẩy vào pipeline
                synthetic_log = {
                    "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "source_ip":  "127.0.0.1",
                    "event_type": "rag_integrity_violation",
                    "message":    (
                        f"ChromaDB RAG Poisoning detected: {len(suspicious_new)} "
                        f"unauthorized document(s) injected. "
                        f"IDs: {[d['id'] for d in suspicious_new]}. "
                        f"Sources: {[d['source_type'] for d in suspicious_new]}."
                    ),
                    "suspicious_docs": suspicious_new,
                    "severity_hint":   "critical",
                }
                try:
                    # Gọi trực tiếp hàm trong module này (không import vòng)
                    _synthetic_input = LogInput(raw_log=synthetic_log)
                    analyze_log(_synthetic_input)
                    logger.info("[ChromaMonitor] Synthetic event đã được đẩy vào pipeline.")
                except Exception as push_err:
                    logger.error(f"[ChromaMonitor] Không thể push synthetic event: {push_err}")

        except Exception as poll_err:
            logger.warning(f"[ChromaMonitor] Lỗi poll: {poll_err}")

# GÓP Ý 2: BIẾN LƯU THỐNG KÊ INCIDENT ĐỂ DASHBOARD VẼ BIỂU ĐỒ
GLOBAL_INCIDENT_STATS = {
    "total_incidents": 0,   # LLM-analyzed logs
    "total_received": 0,    # Tất cả logs nhận được (kể cả pre-filtered)
    "noise_dropped": 0,     # Tier 0: obvious noise bị drop
    "clean_filtered": 0,    # Tier 1: clean (không có attack indicator)
    "pending_analysis": 0,  # Đang chờ LLM xử lý
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
}

# LIVE FEED: lưu tối đa 50 kết quả phân tích gần nhất để dashboard poll
RECENT_ANALYSIS_RESULTS: List[Dict[str, Any]] = []
MAX_RECENT_RESULTS = 50

# IP ACTIVITY LOG: track mọi IP xuất hiện (kể cả noise/clean-filtered)
# Đảm bảo IP đã từng thấy trong batch không bị clean-filter lần 2 → luôn vào LLM
IP_ACTIVITY_LOG: Dict[str, int] = {}

# ==========================================
# MODEL DỮ LIỆU
# ==========================================
class LogInput(BaseModel):
    raw_log: Dict[str, Any] = Field(..., description="Cục Log JSON từ SIEM/Dashboard")

class BatchLogInput(BaseModel):
    logs: List[Dict[str, Any]] = Field(..., description="Danh sách log JSON theo thứ tự thời gian")
    reset_memory: bool = Field(default=False, description="Reset memory trước khi xử lý batch")

class AnalysisResponse(BaseModel):
    incident_id: str
    severity: str
    confidence: float
    evidence_strength: float
    mitre_techniques: List[str]
    action_taken: str
    agent_mode: str
    knowledge_conflict: Optional[bool] = False
    attack_chain_stage: str
    attack_timeline: List[Dict[str, Any]]
    raw_ai_verdict: Dict[str, Any]
    investigation_notes: List[str]
    processing_time_ms: float

# ==========================================
# STARTUP: KHỞI ĐỘNG BACKGROUND MONITOR
# ==========================================
@app.on_event("startup")
def start_chroma_monitor():
    t = threading.Thread(target=_chroma_monitor_loop, daemon=True, name="ChromaMonitor")
    t.start()
    logger.info("[Startup] ChromaDB Integrity Monitor đã khởi động (daemon thread).")

# ==========================================
# CÁC ENDPOINT API
# ==========================================

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/stats")
def stats():
    return {
        "timeline_size": len(GLOBAL_TIMELINE_MEMORY),
        "recent_events": GLOBAL_TIMELINE_MEMORY[-10:]
    }

@app.get("/timeline")
def get_timeline():
    with _timeline_lock:
        return {
            "size": len(GLOBAL_TIMELINE_MEMORY),
            "events": list(GLOBAL_TIMELINE_MEMORY)
        }

@app.get("/incidents")
def get_incidents_summary():
    return {**GLOBAL_INCIDENT_STATS, "timeline_size": len(GLOBAL_TIMELINE_MEMORY)}

# LIVE FEED: Trả về tối đa 50 kết quả phân tích gần nhất
@app.get("/recent")
def get_recent_results():
    return {
        "count": len(RECENT_ANALYSIS_RESULTS),
        "results": RECENT_ANALYSIS_RESULTS
    }

# [THÊM MỚI] Góp ý 1: Reset Memory cực xịn cho lúc Demo
@app.post("/reset")
def reset_memory():
    logger.warning("[RESET] Toàn bộ memory bị xóa — được gọi từ dashboard hoặc external client.")
    global GLOBAL_TIMELINE_MEMORY
    global GLOBAL_INCIDENT_STATS
    global RECENT_ANALYSIS_RESULTS
    global IP_ACTIVITY_LOG

    GLOBAL_TIMELINE_MEMORY.clear()
    RECENT_ANALYSIS_RESULTS.clear()
    IP_ACTIVITY_LOG.clear()
    GLOBAL_INCIDENT_STATS = {
        "total_incidents": 0,
        "total_received": 0,
        "noise_dropped": 0,
        "clean_filtered": 0,
        "pending_analysis": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    return {
        "status": "success",
        "message": "Timeline memory, recent results, and incident stats cleared successfully."
    }

@app.post("/analyze", response_model=AnalysisResponse)
def analyze_log(payload: LogInput):
    global GLOBAL_TIMELINE_MEMORY
    global GLOBAL_INCIDENT_STATS
    
    start_time = time.time()
    logger.info(f"Đang xử lý log mới: {payload.raw_log}")

    GLOBAL_INCIDENT_STATS["total_received"] += 1
    GLOBAL_INCIDENT_STATS["pending_analysis"] += 1
    try:
        # Khởi tạo State với bộ nhớ Timeline
        initial_state = {
            "raw_log": payload.raw_log,
            "investigation_notes": ["API: Đã tiếp nhận Log."],
            "attack_timeline": GLOBAL_TIMELINE_MEMORY 
        }

        # Kích hoạt LangGraph
        final_state = langgraph_app.invoke(initial_state)

        # Lấy severity và evidence từ Analyzer
        severity_result = final_state.get("severity", "low").lower()
        # Clamp [0,1] — LLM đôi khi trả giá trị ngoài range (vd: 8.0)
        evidence_result = max(0.0, min(1.0, float(final_state.get("evidence_strength", 0.0))))

        # ── DETERMINISTIC OVERRIDE ──────────────────────────────────────────
        # Llama 3.1 8B không follow multi-condition logic đủ tin cậy.
        # Rule: auth_success sau HIGH/CRITICAL history từ cùng IP = CRITICAL
        # Đây là rule xác định hoàn toàn — không cần LLM phán quyết.
        _raw_event_type = str(payload.raw_log.get("event_type", "")).lower()
        _critical_override_applied = False
        if _raw_event_type in ("auth_success", "login_success"):
            _current_ip = final_state.get("source_ip", "") or payload.raw_log.get("source_ip", "")
            if _current_ip and _current_ip != "unknown_ip":
                _has_high_prior = any(
                    e.get("source_ip") == _current_ip
                    and e.get("severity", "").lower() in ("high", "critical")
                    for e in GLOBAL_TIMELINE_MEMORY  # history trước khi enrich event hiện tại
                )
                if _has_high_prior and severity_result != "critical":
                    logger.info(
                        f"[CRITICAL OVERRIDE] auth_success từ {_current_ip} "
                        f"có lịch sử HIGH → buộc CRITICAL (LLM trả {severity_result.upper()})"
                    )
                    severity_result = "critical"
                    evidence_result = max(evidence_result, 0.9)
                    _critical_override_applied = True

        # ── OPTION D: GHI ĐÈ REASONING khi CRITICAL override kích hoạt ────────
        # LLM 8B hallucinate "lịch sử IP trống" → thay bằng reasoning chính xác từ code
        if _critical_override_applied:
            _prior_events = [
                e for e in GLOBAL_TIMELINE_MEMORY
                if e.get("source_ip") == _current_ip
                and e.get("severity", "").lower() in ("high", "critical")
            ]
            _prior_desc = ", ".join(
                f"{e.get('event_type','?')} [{e.get('severity','?').upper()}]"
                for e in _prior_events[-3:]
            ) or "sự kiện nguy hiểm không xác định"
            _override_reasoning = (
                f"[Deterministic Override] IP {_current_ip} có {len(_prior_events)} tiền án nguy hiểm trước đó: "
                f"{_prior_desc}. Phát hiện {_raw_event_type} — Kill-chain xác nhận kẻ tấn công "
                f"đã vượt rào thành công. LLM verdict gốc bị override bởi kill-chain rule."
            )
            _mutable_ai = dict(final_state.get("raw_ai_verdict", {}))
            _mutable_ai["reasoning"] = _override_reasoning
            final_state = dict(final_state)
            final_state["raw_ai_verdict"] = _mutable_ai
        # ─────────────────────────────────────────────────────────────────────

        # Khi override kích hoạt, Responder đã chạy với severity cũ (LOW→IGNORE).
        # Tính lại action theo severity và evidence mới để trả về đúng.
        if _critical_override_applied:
            if evidence_result >= 0.90:
                _action_result = "NETWORK_BLOCK_FULL"
            elif evidence_result >= 0.70:
                _action_result = "BLOCK_IP"
            else:
                _action_result = "ALERT_OPERATOR"
            logger.info(f"[ACTION OVERRIDE] CRITICAL kill-chain confirmed → {_action_result}")
        else:
            _action_result = final_state.get("action_taken", "NONE").upper()
        # ────────────────────────────────────────────────────────────────────

        # Enrich sự kiện vừa phân tích (phần tử cuối) với severity đã xác định.
        # Dùng lock để tránh race condition khi nhiều log đến cùng lúc (burst từ partner).
        # Mutate in-place (.clear + .extend) thay vì reassign (= new_list) để giữ reference.
        updated_timeline = list(final_state.get("attack_timeline", []))
        if updated_timeline:
            last_event = dict(updated_timeline[-1])
            last_event["severity"] = severity_result
            last_event["evidence_strength"] = evidence_result
            updated_timeline[-1] = last_event
        with _timeline_lock:
            # Merge: giữ các event cũ đã có, chỉ thêm event của request này
            existing_ids = {e.get("correlation_id","") + e.get("event_timestamp","")
                            for e in GLOBAL_TIMELINE_MEMORY}
            for ev in updated_timeline:
                ev_key = ev.get("correlation_id","") + ev.get("event_timestamp","")
                if ev_key not in existing_ids:
                    GLOBAL_TIMELINE_MEMORY.append(ev)
                    existing_ids.add(ev_key)
                else:
                    # Cập nhật severity/evidence cho event đã có (enrichment)
                    for i, existing in enumerate(GLOBAL_TIMELINE_MEMORY):
                        if (existing.get("correlation_id","") + existing.get("event_timestamp","")) == ev_key:
                            GLOBAL_TIMELINE_MEMORY[i] = ev
                            break
            if len(GLOBAL_TIMELINE_MEMORY) > MAX_TIMELINE_SIZE:
                del GLOBAL_TIMELINE_MEMORY[:-MAX_TIMELINE_SIZE]

        # Cập nhật số liệu thống kê Incident
        GLOBAL_INCIDENT_STATS["total_incidents"] += 1
        if severity_result in GLOBAL_INCIDENT_STATS:
            GLOBAL_INCIDENT_STATS[severity_result] += 1

        process_time = round((time.time() - start_time) * 1000, 2)
        logger.info(f"Phân tích xong trong {process_time}ms. Severity: {severity_result.upper()}")

        _notes = list(final_state.get("investigation_notes", []))
        if _critical_override_applied:
            _notes.append(
                f"[CRITICAL OVERRIDE] LLM trả {final_state.get('severity','?').upper()} "
                f"(reasoning: '{final_state.get('raw_ai_verdict',{}).get('reasoning','?')[:80]}...') "
                f"— Deterministic kill-chain rule phát hiện auth_success sau HIGH từ IP "
                f"{_current_ip} → ép CRITICAL + evidence=0.9."
            )

        _response = AnalysisResponse(
            incident_id=final_state.get("correlation_id", "Unknown"),
            severity=severity_result.upper(),
            confidence=final_state.get("confidence_score", 0.0),
            evidence_strength=evidence_result,  # dùng post-override value cho nhất quán với action
            mitre_techniques=final_state.get("mitre_mapping", []),
            action_taken=_action_result,
            agent_mode=final_state.get("agent_mode", "autonomous").upper(),
            knowledge_conflict=final_state.get("knowledge_conflict", False) is True,
            attack_chain_stage=final_state.get("attack_chain_stage", ""),
            attack_timeline=GLOBAL_TIMELINE_MEMORY,
            raw_ai_verdict=final_state.get("raw_ai_verdict", {}),        # XAI
            investigation_notes=_notes,
            processing_time_ms=process_time
        )

        # Lưu vào Live Feed buffer — MỌI log qua LLM đều được ghi (kể cả từ /batch)
        _live_entry = _response.dict()
        _live_entry["source_ip"] = payload.raw_log.get("source_ip", "unknown")
        _live_entry["event_type"] = payload.raw_log.get("event_type", "unknown")
        _live_entry["received_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        RECENT_ANALYSIS_RESULTS.append(_live_entry)
        if len(RECENT_ANALYSIS_RESULTS) > MAX_RECENT_RESULTS:
            RECENT_ANALYSIS_RESULTS[:] = RECENT_ANALYSIS_RESULTS[-MAX_RECENT_RESULTS:]

        return _response

    except Exception as e:
        logger.error(f"Lỗi API: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        GLOBAL_INCIDENT_STATS["pending_analysis"] = max(0, GLOBAL_INCIDENT_STATS["pending_analysis"] - 1)


# ==========================================
# BATCH MODE: PHÂN TÍCH CHUỖI LOG
# Nhận List[log], xử lý tuần tự — log trước xây timeline cho log sau.
# ==========================================
@app.post("/analyze/batch")
def analyze_batch(payload: BatchLogInput):
    global GLOBAL_TIMELINE_MEMORY, GLOBAL_INCIDENT_STATS, RECENT_ANALYSIS_RESULTS

    if payload.reset_memory:
        logger.warning("[Batch] reset_memory=True bị CHẶN — gọi /reset riêng nếu cần xóa bộ nhớ.")

    if not payload.logs:
        raise HTTPException(status_code=400, detail="Danh sách logs không được để trống.")

    # event_type luôn phải qua LLM dù không có attack indicator (vì cần check kill-chain)
    _ALWAYS_ANALYZE = {"auth_success", "login_success", "auth_attempt", "login_attempt", "rag_integrity_violation"}
    # event_type rõ ràng là noise kỹ thuật → DROP ngay, không cần Extractor
    _OBVIOUS_NOISE  = {"health_check", "heartbeat", "metric_report", "asset_sync", "ping", "keep_alive"}

    results    = []
    batch_stats: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    prefilter_stats = {"noise_dropped": 0, "clean_filtered": 0, "llm_analyzed": 0}

    for i, raw_log in enumerate(payload.logs):
        _ev_type = str(raw_log.get("event_type", "")).lower()
        _src_ip  = str(raw_log.get("source_ip", ""))
        _t0      = time.time()

        # [Option A] Ghi nhận IP vào activity log TRƯỚC mọi quyết định filter
        # Kể cả noise và clean-filtered — đảm bảo log sau từ cùng IP không bị bỏ sót
        if _src_ip:
            IP_ACTIVITY_LOG[_src_ip] = IP_ACTIVITY_LOG.get(_src_ip, 0) + 1

        # ── TIER 0: obvious noise ─────────────────────────────────────────
        if _ev_type in _OBVIOUS_NOISE:
            prefilter_stats["noise_dropped"] += 1
            GLOBAL_INCIDENT_STATS["noise_dropped"] += 1
            GLOBAL_INCIDENT_STATS["total_received"] += 1
            logger.info(f"[Batch {i+1}] PRE-FILTER NOISE DROP: {_ev_type}")
            results.append({
                "pre_filtered": True, "filter_tier": "noise",
                "severity": "LOW", "action_taken": "IGNORE",
                "source_ip": raw_log.get("source_ip", "unknown"),
                "event_type": _ev_type, "evidence_strength": 0.0,
                "mitre_techniques": [], "incident_id": f"NOISE_{i}",
                "investigation_notes": [f"Pre-filter [Tier 0]: '{_ev_type}' là noise kỹ thuật. Bỏ qua."],
                "processing_time_ms": round((time.time() - _t0) * 1000, 2),
                "attack_timeline": [], "raw_ai_verdict": {},
                "confidence": 0.0, "attack_chain_stage": "none",
                "knowledge_conflict": False, "agent_mode": "PRE_FILTERED",
            })
            continue

        # ── TIER 1: Extractor (pure Python, ~0.1s, không dùng LLM) ────────
        try:
            _ext = node_extractor({"raw_log": raw_log, "investigation_notes": [],
                                   "attack_timeline": [], "source_ip": ""})
            _indicators = _ext.get("extracted_ioc", {}).get("attack_indicators", [])
        except Exception as _err:
            logger.warning(f"[Batch {i+1}] Extractor lỗi: {_err} → chuyển sang LLM.")
            _indicators = ["extractor_error"]  # conservative: luôn pass khi không chắc

        # Kiểm tra lịch sử IP trong timeline — IP đã từng HIGH/CRITICAL thì luôn vào LLM
        # dù log hiện tại trông bình thường (tránh bỏ sót bước leo thang sau tấn công)
        _ip_has_high_history = _src_ip and any(
            e.get("source_ip") == _src_ip
            and e.get("severity", "low").lower() in ("high", "critical")
            for e in GLOBAL_TIMELINE_MEMORY
        )
        # [Option A] IP đã xuất hiện trước đó trong batch (dù bị clean-filter) → vào LLM
        _ip_seen_before = bool(_src_ip) and IP_ACTIVITY_LOG.get(_src_ip, 0) > 1

        _needs_llm = bool(_indicators) or (_ev_type in _ALWAYS_ANALYZE) or _ip_has_high_history or _ip_seen_before

        if not _needs_llm:
            # Không có attack indicator + IP chưa có tiền án + không phải event đặc biệt → CLEAN
            prefilter_stats["clean_filtered"] += 1
            GLOBAL_INCIDENT_STATS["clean_filtered"] += 1
            GLOBAL_INCIDENT_STATS["total_received"] += 1
            batch_stats["low"] = batch_stats.get("low", 0) + 1
            logger.info(f"[Batch {i+1}] PRE-FILTER CLEAN: {_ev_type} từ {raw_log.get('source_ip','?')}")
            results.append({
                "pre_filtered": True, "filter_tier": "clean",
                "severity": "LOW", "action_taken": "IGNORE",
                "source_ip": raw_log.get("source_ip", "unknown"),
                "event_type": _ev_type, "evidence_strength": 0.0,
                "mitre_techniques": [], "incident_id": f"CLEAN_{i}",
                "investigation_notes": [
                    "Pre-filter [Tier 1]: Extractor không tìm thấy attack indicator.",
                    f"event_type='{_ev_type}' không nằm trong danh sách bắt buộc phân tích.",
                    f"IP {_src_ip} chưa từng xuất hiện trước đó trong batch này và không có lịch sử HIGH/CRITICAL.",
                    "LLM pipeline bỏ qua — tiết kiệm tài nguyên.",
                ],
                "processing_time_ms": round((time.time() - _t0) * 1000, 2),
                "attack_timeline": [], "raw_ai_verdict": {},
                "confidence": 0.0, "attack_chain_stage": "none",
                "knowledge_conflict": False, "agent_mode": "PRE_FILTERED",
            })
            continue

        # ── TIER 2: Full LLM pipeline (chỉ log thực sự đáng ngờ) ──────────
        prefilter_stats["llm_analyzed"] += 1
        logger.info(
            f"[Batch {i+1}/{len(payload.logs)}] LLM PIPELINE: {_ev_type} | indicators={_indicators}"
        )
        try:
            # Đánh dấu thread-local để analyze_log KHÔNG thêm vào Live Feed buffer
            _batch_context.from_batch = True
            result = analyze_log(LogInput(raw_log=raw_log))
            result_dict = result.dict()

            # [Option E] Nếu IP đã từng thấy trước đó (dù clean-filtered),
            # ghi note vào Audit Trail — KHÔNG chen vào reasoning để giữ LLM text sạch
            if _ip_seen_before:
                _total_seen = IP_ACTIVITY_LOG.get(_src_ip, 0) - 1  # lần xuất hiện trước
                _llm_count  = sum(
                    1 for e in GLOBAL_TIMELINE_MEMORY
                    if e.get("source_ip") == _src_ip
                )
                _clean_count = _total_seen - _llm_count
                _ip_note = (
                    f"[IP Activity] IP {_src_ip} đã xuất hiện {_total_seen} lần trước trong batch: "
                    f"{_llm_count} lần qua LLM phân tích sâu, "
                    f"{_clean_count} lần bị pre-filter (không có attack indicator)."
                )
                result_dict["investigation_notes"].append(_ip_note)

            results.append(result_dict)
            batch_stats[result.severity.lower()] = batch_stats.get(result.severity.lower(), 0) + 1
        except HTTPException as e:
            logger.error(f"[Batch {i+1}] Lỗi: {e.detail}")
            results.append({"error": e.detail, "log_index": i, "raw_log": raw_log})
        finally:
            _batch_context.from_batch = False  # reset flag sau mỗi log dù lỗi hay không

    return {
        "mode": "batch_with_prefilter",
        "total": len(payload.logs),
        "processed": len([r for r in results if "error" not in r]),
        "pre_filter_stats": prefilter_stats,
        "batch_summary": batch_stats,
        "final_timeline_size": len(GLOBAL_TIMELINE_MEMORY),
        "results": results
    }