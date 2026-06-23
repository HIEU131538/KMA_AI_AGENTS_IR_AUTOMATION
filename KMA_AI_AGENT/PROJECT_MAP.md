# PROJECT_MAP.md

# KMA SOC AI Agent

## System Overview

Hệ thống được xây dựng bằng LangGraph.

Mỗi node nhận và trả về dữ liệu thông qua:

SOCAgentState

Không sử dụng memory của LLM để lưu trạng thái điều tra.

Tất cả dữ liệu điều tra phải đi qua state.

---

# Processing Pipeline

Raw Log
↓
Extractor
↓
Correlator
↓
Retriever
↓
Analyzer
↓
Responder
↓
Report

---

# 1. Extractor

File:
extractor.py

Nhiệm vụ:

* Parse log JSON
* Trích xuất IOC
* Chuẩn hóa dữ liệu

Output:

* source_ip
* destination_ip
* username
* event_type
* timestamp
* raw_log

Không thực hiện correlation.

Không đánh giá mức độ nguy hiểm.

---

# 2. Correlator

File:
correlator.py

Nhiệm vụ:

* Xác định Incident ID
* Xây dựng Attack Timeline
* Tìm các sự kiện liên quan
* Xác định Attack Stage

Input:

* raw_log
* source_ip
* timestamp

Output:

* incident_id
* attack_timeline
* attack_stage
* incident_severity
* is_suspicious

Quan trọng:

attack_timeline chỉ được chứa các sự kiện trước thời điểm hiện tại.

Không được thêm current_event vào attack_timeline.

Current Event phải được lưu riêng.

Ví dụ đúng:

attack_timeline = [
event_1,
event_2
]

current_event = event_3

Ví dụ sai:

attack_timeline = [
event_1,
event_2,
event_3
]

current_event = event_3

Điều này gây ra bug Ghost Data.

---

# 3. Retriever

File:
retriever.py

Nhiệm vụ:

* Tra cứu Sigma
* Tra cứu MITRE Context
* Truy xuất tài liệu RAG

Output:

* retrieved_docs

Lưu ý:

RAG chỉ là tài liệu tham khảo.

Không phải bằng chứng.

---

# 4. Analyzer

File:
analyzer.py

Model:

Llama 3.1

Input:

* raw_log
* attack_timeline
* attack_stage
* incident_severity
* retrieved_docs

Output:

* severity
* confidence_score
* evidence_strength
* reasoning
* mitre_mapping
* knowledge_conflict

Nguyên tắc:

Raw Log là nguồn sự thật duy nhất.

Nếu Log và RAG mâu thuẫn:

Tin Log.

Analyzer không được tự tạo IOC mới.

Analyzer không được tự suy đoán hành vi không xuất hiện trong log.

---

# 5. Responder

File:
responder.py

Input:

* severity
* evidence_strength
* knowledge_conflict
* source_ip

Output:

* action_taken
* response_reason

Responder không thực hiện phân tích.

Responder chỉ thực thi policy.

Severity do Analyzer quyết định.

---

# Incident Memory

Có 2 loại bộ nhớ:

## Incident Context

Dùng cho phiên điều tra hiện tại.

Ví dụ:

* attack_timeline
* attack_stage

Dữ liệu này chỉ tồn tại trong incident hiện tại.

---

## Attacker Reputation

Dùng lâu dài.

Ví dụ:

* previous_incidents
* attack_count
* risk_score
* first_seen
* last_seen

Có thể lưu bằng:

* SQLite
* Redis
* PostgreSQL
* JSON Database

Không được trộn Attacker Reputation vào attack_timeline.

---

# Known Bug

## Ghost Data

Triệu chứng:

Analyzer nhận định:

"IP này đã từng tấn công trước đó"

trong khi đây là log đầu tiên.

Nghi ngờ:

current_event đang bị chèn vào attack_timeline.

Ưu tiên debug:

1. main.py
2. state.py
3. correlator.py
4. analyzer.py

Không sửa Analyzer trước khi xác minh Correlator.
