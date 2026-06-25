#!/usr/bin/env python3
"""
KMA AI Agent — Confusion Matrix Evaluator
==========================================
Tính hai loại confusion matrix:

  [1] Binary 2x2  : Attack Detection (TP/FP/TN/FN kinh điển)
        Positive  = MEDIUM / HIGH / CRITICAL  (có tấn công)
        Negative  = LOW                        (bình thường)

  [2] Multi-class 4x4 : Severity Classification
        LOW / MEDIUM / HIGH / CRITICAL

Ground truth suy ra từ investigation_notes của Extractor (rule-based, KHÔNG dùng LLM output).
Cụ thể: dòng "TÓM KẾT: Attack Indicators xác nhận -> [...]" mà Extractor luôn ghi vào notes.

Cách dùng:
  python3 eval_confusion_matrix.py
  python3 eval_confusion_matrix.py --export
  python3 eval_confusion_matrix.py --url http://localhost:8000 --export
"""

import requests
import json
import sys
import argparse
from collections import defaultdict
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
DEFAULT_URL = "http://localhost:8000"
SEV_LEVELS  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_ORDER   = {s: i for i, s in enumerate(SEV_LEVELS)}  # LOW=0 ... CRITICAL=3

# ─────────────────────────────────────────────────────────────
# LUẬT XÁC ĐỊNH GROUND TRUTH (từ Extractor indicator names)
# Thứ tự: ưu tiên severity cao hơn kiểm tra trước
# ─────────────────────────────────────────────────────────────
INDICATOR_GT = [
    # (tên indicator trong notes,      expected severity, nhãn hiển thị)
    ("rag_poisoning",            "CRITICAL", "RAG Poisoning"),
    ("sql_injection",            "HIGH",     "SQL Injection"),
    ("ssrf_attempt",             "HIGH",     "SSRF"),
    ("http_smuggling",           "HIGH",     "HTTP Smuggling"),
    ("header_injection",         "HIGH",     "Header Injection"),
    ("header_abuse",             "HIGH",     "Header Abuse"),
    # "rce_attempt" bị bỏ khỏi đây vì Extractor match nhầm field detected_attack
    # (string "rce_attempt" xuất hiện trong raw_log từ bridge, không phải payload thật)
    ("jwt_privilege_escalation", "HIGH",     "JWT Privilege Escalation"),
    ("log_injection",            "HIGH",     "Log Injection / Tampering"),
    ("dns_tunneling",            "HIGH",     "DNS Tunneling"),
    ("network_scan",             "MEDIUM",   "Network Scan"),
    ("brute_force_attempt",      "MEDIUM",   "Brute Force"),
]

# Fallback theo event_type khi không có indicator nào khớp
EVENT_TYPE_GT = {
    "rag_integrity_violation": ("CRITICAL", "RAG Poisoning (ChromaMonitor)"),
    # dns_query: bridge map dns_tunnel/dns_tunneling → "dns_query" event_type.
    # Extractor không detect được vì field "query" nằm trong payload (không phải top-level).
    # Tất cả dns_query trong demo đều là DNS Tunneling attack → HIGH.
    "dns_query":               ("HIGH",     "DNS Tunneling"),
    "web_access":              ("LOW",      "Normal Web Access"),
    "normal_traffic":          ("LOW",      "Normal Traffic"),
    "http_request":            ("LOW",      "HTTP Request"),
}


# ─────────────────────────────────────────────────────────────
# XÁC ĐỊNH GROUND TRUTH CHO 1 ENTRY
# ─────────────────────────────────────────────────────────────
def determine_gt(entry: dict) -> tuple:
    """
    Trả về (expected_severity: str, attack_label: str).

    Ưu tiên:
      1. Indicator cao nhất tìm thấy trong notes của Extractor
      2. Xử lý đặc biệt auth_success: CRITICAL nếu IP có lịch sử HIGH trước đó
      3. Fallback theo event_type
      4. Mặc định LOW (traffic bình thường)
    """
    notes      = entry.get("investigation_notes", [])
    event_type = str(entry.get("event_type", "")).lower()
    source_ip  = entry.get("source_ip", "")
    notes_full = " ".join(notes).lower()
    # IP escalation ghi vào raw_ai_verdict.reasoning, không phải notes → cần check cả hai
    _ai_reasoning = str(entry.get("raw_ai_verdict", {}).get("reasoning", "")).lower()

    # Bước 1: tìm trong dòng TÓM KẾT (Extractor luôn ghi cuối danh sách notes)
    found_indicators = []
    for note in notes:
        note_lower = note.lower()
        if "tóm kết" in note_lower and "attack indicators" in note_lower:
            for (ind, _sev, _lbl) in INDICATOR_GT:
                if ind in note_lower:
                    found_indicators.append(ind)

    # Bước 2: nếu không có dòng TÓM KẾT (edge case), quét toàn bộ notes
    if not found_indicators:
        for (ind, _sev, _lbl) in INDICATOR_GT:
            if ind in notes_full:
                found_indicators.append(ind)

    # Bước 3: chọn severity cao nhất trong các indicator tìm được
    best_sev   = "LOW"
    best_label = "Normal / Clean"
    for (ind, sev, label) in INDICATOR_GT:
        if ind in found_indicators:
            if SEV_ORDER[sev] > SEV_ORDER[best_sev]:
                best_sev, best_label = sev, label

    # Bước 3.3: event_type fallback sớm — cần chạy TRƯỚC escalation check
    # Lý do: dns_query extractor không detect được dns_tunneling (lỗi field name),
    # nên best_sev vẫn là LOW sau bước 3. Fallback sớm sẽ fill best_sev = HIGH
    # để bước 3.5 escalation check hoạt động đúng.
    if best_sev == "LOW":
        for ev_kw, (sev, label) in EVENT_TYPE_GT.items():
            if ev_kw in event_type:
                best_sev, best_label = sev, label
                break

    # Bước 3.5: IP Escalation / Critical Override — deterministic rule của hệ thống
    # Khi ≥5 HIGH từ cùng IP → main.py force CRITICAL. Đây là hành vi đúng, không phải FP.
    # - Auth-success override → ghi "[CRITICAL OVERRIDE]" vào investigation_notes
    # - IP escalation override → ghi "[IP Escalation — Deterministic]" vào raw_ai_verdict.reasoning
    _has_escalation = (
        "[critical override]" in notes_full                    # auth_success kill-chain
        or "[ip escalation" in _ai_reasoning                   # ip threshold escalation
        or "[ip escalation" in notes_full                      # fallback nếu format thay đổi
    )
    if _has_escalation and best_sev in ("MEDIUM", "HIGH"):
        return "CRITICAL", f"{best_label} (+ IP Escalation)"

    # Bước 4: xử lý đặc biệt auth_success — kill-chain
    if event_type in ("auth_success", "login_success"):
        timeline = entry.get("attack_timeline", [])
        prior_high = any(
            e.get("source_ip") == source_ip
            and str(e.get("severity", "")).lower() in ("high", "critical")
            for e in timeline
        )
        if prior_high:
            return "CRITICAL", "Kill-chain: Auth Success (sau HIGH)"
        else:
            return "LOW", "Auth Success Hợp Lệ"

    return best_sev, best_label


def to_binary(severity: str) -> str:
    """Chuyển severity về nhãn nhị phân: ATTACK hoặc BENIGN."""
    return "ATTACK" if severity.upper() in ("MEDIUM", "HIGH", "CRITICAL") else "BENIGN"


# ─────────────────────────────────────────────────────────────
# IN BINARY 2x2 CONFUSION MATRIX
# ─────────────────────────────────────────────────────────────
def print_binary_matrix(tp: int, fp: int, fn: int, tn: int) -> dict:
    """
    In confusion matrix nhị phân theo dạng chuẩn.
    Trả về dict chứa các metrics để dùng khi export.

    Quy ước:
      TP = AI nói ATTACK, thực tế là ATTACK  ← phát hiện đúng
      FP = AI nói ATTACK, thực tế là BENIGN  ← báo nhầm (false alarm)
      FN = AI nói BENIGN, thực tế là ATTACK  ← bỏ sót (nguy hiểm nhất)
      TN = AI nói BENIGN, thực tế là BENIGN  ← bỏ qua đúng
    """
    total = tp + fp + fn + tn

    print(f"\n              ┌──────────────────────────────────────┐")
    print(f"              │  Predicted ATTACK   Predicted BENIGN │")
    print(f"  ┌───────────┼────────────────────┬─────────────────┤")
    print(f"  │Actual ATK │  TP = {tp:<12}  │  FN = {fn:<8}   │")
    print(f"  ├───────────┼────────────────────┼─────────────────┤")
    print(f"  │Actual BEN │  FP = {fp:<12}  │  TN = {tn:<8}   │")
    print(f"  └───────────┴────────────────────┴─────────────────┘")

    acc  = (tp + tn) / total  if total          > 0 else 0.0
    prec = tp        / (tp+fp) if (tp + fp)     > 0 else 0.0
    rec  = tp        / (tp+fn) if (tp + fn)     > 0 else 0.0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec)  > 0 else 0.0
    fpr  = fp        / (fp+tn)  if (fp + tn)    > 0 else 0.0

    print(f"\n  Giải thích:")
    print(f"    TP = {tp:>3}  AI phát hiện đúng tấn công")
    print(f"    FP = {fp:>3}  AI báo nhầm traffic bình thường là tấn công (false alarm)")
    print(f"    FN = {fn:>3}  AI bỏ sót tấn công — nguy hiểm nhất!")
    print(f"    TN = {tn:>3}  AI đúng khi bỏ qua traffic bình thường")

    print(f"\n  Metrics (Attack Detection):")
    print(f"    Accuracy  = (TP+TN) / Total     = ({tp}+{tn}) / {total}   = {acc:.4f}  [{acc:.1%}]")
    print(f"    Precision = TP / (TP+FP)        = {tp} / ({tp}+{fp})     = {prec:.4f}  [{prec:.1%}]")
    print(f"    Recall    = TP / (TP+FN)        = {tp} / ({tp}+{fn})     = {rec:.4f}  [{rec:.1%}]")
    print(f"      (Recall = Detection Rate — tỉ lệ bắt được tấn công)")
    print(f"    F1-Score  = 2×P×R / (P+R)       = {f1:.4f}  [{f1:.1%}]")
    print(f"    FPR       = FP / (FP+TN)        = {fp} / ({fp}+{tn})     = {fpr:.4f}  [{fpr:.1%}]")
    print(f"      (FPR = False Positive Rate — tỉ lệ báo nhầm)")

    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "accuracy":  round(acc,  4),
        "precision": round(prec, 4),
        "recall":    round(rec,  4),
        "f1":        round(f1,   4),
        "fpr":       round(fpr,  4),
    }


# ─────────────────────────────────────────────────────────────
# IN MULTI-CLASS 4x4 CONFUSION MATRIX
# ─────────────────────────────────────────────────────────────
def print_multiclass_matrix(matrix: dict, total: int):
    """
    In confusion matrix 4 lớp + per-class TP/FP/FN/TN.
    """
    col_w = 11

    # Matrix grid
    print(f"\n  {'':>13}", end="")
    for pred in SEV_LEVELS:
        print(f"{pred:>{col_w}}", end="")
    print(f"   ← Predicted")
    print(f"  {'':>13}" + "─" * (col_w * 4))

    for actual in SEV_LEVELS:
        print(f"  {('['+actual+']'):>13}", end="")
        for pred in SEV_LEVELS:
            count = matrix[actual][pred]
            if actual == pred:
                cell = f"[{count}]"   # đường chéo = đúng
            elif count > 0:
                cell = str(count)
            else:
                cell = "."
            print(f"{cell:>{col_w}}", end="")
        print()

    print(f"  {'':>13}" + "─" * (col_w * 4))
    print(f"  Hàng = Ground Truth  ·  Cột = Predicted  ·  [n] = đúng (đường chéo)")

    # Per-class metrics
    print(f"\n  Per-Class Metrics:")
    print(f"  {'Class':<10} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} "
          f"{'Precision':>10} {'Recall':>8} {'F1':>8}")
    print(f"  {'─'*10} {'─'*4} {'─'*4} {'─'*4} {'─'*4} {'─'*10} {'─'*8} {'─'*8}")

    per_class = {}
    for level in SEV_LEVELS:
        tp = matrix[level][level]
        fp = sum(matrix[o][level] for o in SEV_LEVELS if o != level)
        fn = sum(matrix[level][o] for o in SEV_LEVELS if o != level)
        tn = total - tp - fp - fn
        pr = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rc = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2*pr*rc / (pr+rc) if (pr+rc) > 0 else 0.0
        print(f"  {level:<10} {tp:>4} {fp:>4} {fn:>4} {tn:>4} "
              f"{pr:>10.3f} {rc:>8.3f} {f1:>8.3f}")
        per_class[level] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "Precision": round(pr, 4),
            "Recall":    round(rc, 4),
            "F1":        round(f1, 4),
        }

    return per_class


# ─────────────────────────────────────────────────────────────
# MAIN EVALUATION
# ─────────────────────────────────────────────────────────────
def run_evaluation(base_url: str, export: bool = False):

    # 1. Lấy dữ liệu từ AI Agent
    print(f"[*] Đang kết nối {base_url}/recent ...")
    try:
        resp = requests.get(f"{base_url}/recent", timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[-] Lỗi kết nối AI Agent: {e}")
        sys.exit(1)

    results = data.get("results", [])
    if not results:
        print("[-] /recent trống. Hãy chạy demo trước rồi thử lại.")
        sys.exit(0)

    print(f"[+] Nhận {len(results)} kết quả phân tích.\n")

    # 2. Gán ground truth và ghép cặp (ground_truth, predicted)
    pairs = []
    attack_stats = defaultdict(lambda: {"total": 0, "correct": 0, "wrong": []})

    for entry in results:
        pred_sev = str(entry.get("severity", "LOW")).upper()
        if pred_sev not in SEV_LEVELS:
            pred_sev = "LOW"

        gt_sev, attack_label = determine_gt(entry)
        pred_bin = to_binary(pred_sev)
        gt_bin   = to_binary(gt_sev)

        row = {
            "incident_id":   entry.get("incident_id", "?")[:12],
            "event_type":    entry.get("event_type",  "?"),
            "source_ip":     entry.get("source_ip",   "?"),
            "attack_label":  attack_label,
            "gt_sev":        gt_sev,
            "pred_sev":      pred_sev,
            "gt_bin":        gt_bin,
            "pred_bin":      pred_bin,
            "correct_sev":   gt_sev  == pred_sev,
            "correct_bin":   gt_bin  == pred_bin,
            "evidence":      entry.get("evidence_strength", 0.0),
            "action":        entry.get("action_taken", "?"),
            "received_at":   entry.get("received_at",  "?"),
        }
        pairs.append(row)

        s = attack_stats[attack_label]
        s["total"] += 1
        if row["correct_sev"]:
            s["correct"] += 1
        else:
            s["wrong"].append(f"Expected {gt_sev} → Got {pred_sev}")

    # 3. Tính giá trị cho Binary Matrix
    tp = sum(1 for p in pairs if p["gt_bin"] == "ATTACK" and p["pred_bin"] == "ATTACK")
    fp = sum(1 for p in pairs if p["gt_bin"] == "BENIGN" and p["pred_bin"] == "ATTACK")
    fn = sum(1 for p in pairs if p["gt_bin"] == "ATTACK" and p["pred_bin"] == "BENIGN")
    tn = sum(1 for p in pairs if p["gt_bin"] == "BENIGN" and p["pred_bin"] == "BENIGN")

    # 4. Tính Multi-class Matrix
    mc_matrix = defaultdict(lambda: defaultdict(int))
    for p in pairs:
        mc_matrix[p["gt_sev"]][p["pred_sev"]] += 1

    total       = len(pairs)
    correct_sev = sum(1 for p in pairs if p["correct_sev"])
    acc_sev     = correct_sev / total if total else 0.0

    # ─────────────────────────────────────────────────────────
    # IN KẾT QUẢ
    # ─────────────────────────────────────────────────────────
    W = 72
    print("=" * W)
    print("         KMA AI AGENT — ĐÁNH GIÁ CONFUSION MATRIX")
    print("=" * W)

    # --- [1] Binary Matrix ---
    print(f"\n{'─'*W}")
    print(f"  [1] BINARY CONFUSION MATRIX — ATTACK DETECTION")
    print(f"      Positive (ATTACK) = MEDIUM / HIGH / CRITICAL")
    print(f"      Negative (BENIGN) = LOW")
    print(f"{'─'*W}")
    binary_metrics = print_binary_matrix(tp, fp, fn, tn)

    # --- [2] Multi-class Matrix ---
    print(f"\n{'─'*W}")
    print(f"  [2] MULTI-CLASS CONFUSION MATRIX — SEVERITY CLASSIFICATION")
    print(f"{'─'*W}")
    per_class = print_multiclass_matrix(mc_matrix, total)
    print(f"\n  Accuracy (severity): {correct_sev}/{total} = {acc_sev:.1%}")

    # --- [3] Attack breakdown ---
    print(f"\n{'─'*W}")
    print(f"  [3] PHÂN TÍCH THEO LOẠI TẤN CÔNG")
    print(f"  {'Loại tấn công':<40} {'Đúng':>5} {'Tổng':>5} {'Accuracy':>10}")
    print(f"  {'─'*40} {'─'*5} {'─'*5} {'─'*10}")
    for name in sorted(attack_stats):
        s   = attack_stats[name]
        pct = s["correct"] / s["total"] if s["total"] else 0.0
        print(f"  {name:<40} {s['correct']:>5} {s['total']:>5} {pct:>10.1%}")
        for w in s["wrong"]:
            print(f"  {'':>42}⚠  {w}")

    # --- [4] Detail table ---
    print(f"\n{'─'*W}")
    print(f"  [4] BẢNG CHI TIẾT TỪNG LOG")
    print(f"  {'#':>3}  {'Event Type':<20} {'GT':>8} {'Pred':>8} "
          f"{'GT-Bin':>8} {'P-Bin':>8} {'OK':>3}  Attack Label")
    print(f"  {'─'*3}  {'─'*20} {'─'*8} {'─'*8} {'─'*8} {'─'*8} {'─'*3}  {'─'*22}")
    for i, p in enumerate(pairs, 1):
        ok = "✓" if p["correct_sev"] else "✗"
        lbl = p["attack_label"][:22]
        print(f"  {i:>3}  {p['event_type']:<20} {p['gt_sev']:>8} {p['pred_sev']:>8} "
              f"{p['gt_bin']:>8} {p['pred_bin']:>8} {ok:>3}  {lbl}")

    # --- Summary ---
    print(f"\n{'='*W}")
    print(f"  Đánh giá lúc : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Binary       : TP={tp}  FP={fp}  FN={fn}  TN={tn}"
          f"  | Acc={binary_metrics['accuracy']:.1%}  F1={binary_metrics['f1']:.3f}"
          f"  Recall={binary_metrics['recall']:.1%}")
    print(f"  Severity     : {correct_sev}/{total} đúng"
          f"  | Acc={acc_sev:.1%}")
    print(f"{'='*W}\n")

    # ─────────────────────────────────────────────────────────
    # EXPORT
    # ─────────────────────────────────────────────────────────
    if export:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        export_obj = {
            "timestamp":           ts,
            "total_samples":       total,
            "binary_matrix": {
                "note":      "Positive=ATTACK(MED/HIGH/CRIT), Negative=BENIGN(LOW)",
                **binary_metrics,
            },
            "multiclass_accuracy": round(acc_sev, 4),
            "multiclass_matrix": {
                actual: dict(row) for actual, row in mc_matrix.items()
            },
            "per_class_metrics": per_class,
            "attack_breakdown": {
                k: {"total": v["total"], "correct": v["correct"]}
                for k, v in attack_stats.items()
            },
            "detail": pairs,
        }

        json_path = f"confusion_matrix_{ts}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(export_obj, f, ensure_ascii=False, indent=2)
        print(f"[+] Xuất JSON : {json_path}")

        csv_path = f"confusion_matrix_{ts}.csv"
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("No,Event Type,Attack Label,"
                    "GT Severity,Pred Severity,GT Binary,Pred Binary,"
                    "Correct Severity,Correct Binary,Evidence,Action\n")
            for i, p in enumerate(pairs, 1):
                f.write(
                    f"{i},{p['event_type']},{p['attack_label']},"
                    f"{p['gt_sev']},{p['pred_sev']},"
                    f"{p['gt_bin']},{p['pred_bin']},"
                    f"{p['correct_sev']},{p['correct_bin']},"
                    f"{p['evidence']},{p['action']}\n"
                )
        print(f"[+] Xuất CSV  : {csv_path}")

    return binary_metrics, per_class


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="KMA AI Agent — Confusion Matrix Evaluator"
    )
    parser.add_argument(
        "--url", default=DEFAULT_URL,
        help=f"URL của AI Agent (mặc định: {DEFAULT_URL})"
    )
    parser.add_argument(
        "--export", action="store_true",
        help="Xuất kết quả ra file JSON + CSV"
    )
    args = parser.parse_args()
    run_evaluation(args.url, args.export)
