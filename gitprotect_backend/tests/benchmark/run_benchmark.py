"""
GitProtect MVP - Task S3-04b / S3-04c / S3-04d (PBI-12 / T05DB30)
Kịch bản tự động hóa Benchmark 200 mẫu thử & Đo lường thời gian quét (NFR-02, NFR-03).
Phụ trách: TV4 (Trần Minh Ân) & TV3 (Vũ Trần Anh Hoàng).
"""

import json
import os
import sys
import time

# Thêm đường dẫn gốc để import modules
current_dir = os.path.dirname(os.path.abspath(__file__))
# Tìm project root chứa thư mục app
dir_cursor = current_dir
project_root = current_dir
while dir_cursor and dir_cursor != os.path.dirname(dir_cursor):
    if os.path.exists(os.path.join(dir_cursor, "main.py")) and os.path.exists(os.path.join(dir_cursor, "app")):
        project_root = dir_cursor
        break
    dir_cursor = os.path.dirname(dir_cursor)

if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.modules.engine.service import DetectionEngineService


def run_benchmark():
    dataset_path = os.path.join(current_dir, "dataset_200.json")
    if not os.path.exists(dataset_path):
        # Fallback thử đường dẫn khác
        dataset_path = os.path.join(project_root, "tests", "benchmark_dataset_200.json")

    with open(dataset_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    total_samples = len(samples)
    tp = 0  # True Positive: Secret thật và hệ thống phát hiện
    fn = 0  # False Negative: Secret thật nhưng bị bỏ sót
    fp = 0  # False Positive: Chuỗi an toàn nhưng bị báo nhầm
    tn = 0  # True Negative: Chuỗi an toàn và hệ thống bỏ qua chuẩn xác

    start_total_time = time.perf_counter()
    sample_timings = []

    results_detail = []

    for item in samples:
        t0 = time.perf_counter()
        eval_res = DetectionEngineService.evaluate_snippet(item["content"], item["file_path"])
        elapsed_item_ms = (time.perf_counter() - t0) * 1000
        sample_timings.append(elapsed_item_ms)

        is_detected = eval_res["is_leaked"]
        expected = item["expected_leaked"]

        status = ""
        if expected and is_detected:
            tp += 1
            status = "TP"
        elif expected and not is_detected:
            fn += 1
            status = "FN"
        elif not expected and is_detected:
            fp += 1
            status = "FP"
        else:
            tn += 1
            status = "TN"

        results_detail.append({
            "id": item["id"],
            "type": item["type"],
            "rule": item.get("rule", ""),
            "status": status,
            "time_ms": round(elapsed_item_ms, 2)
        })

    total_time_seconds = time.perf_counter() - start_total_time
    avg_time_ms = sum(sample_timings) / len(sample_timings) if sample_timings else 0

    # Tính toán các chỉ số an toàn thông tin theo chuẩn NFR-03
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
    fpr = (fp / (fp + tn) * 100) if (fp + tn) > 0 else 0
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

    # Kiểm tra tiêu chuẩn chấp nhận NFR-02 và NFR-03
    nfr03_recall_pass = recall >= 90.0
    nfr03_precision_pass = precision >= 85.0
    nfr03_fpr_pass = fpr <= 15.0
    nfr02_time_pass = total_time_seconds < 10.0  # 200 mẫu xử lý trong < 10 giây

    report = {
        "benchmark_summary": {
            "total_samples": total_samples,
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "true_negatives": tn,
            "recall_pct": round(recall, 2),
            "precision_pct": round(precision, 2),
            "false_positive_rate_pct": round(fpr, 2),
            "f1_score": round(f1_score, 2),
            "total_execution_time_seconds": round(total_time_seconds, 3),
            "average_time_per_sample_ms": round(avg_time_ms, 2),
        },
        "acceptance_criteria_verification": {
            "NFR-03_Recall_ge_90_pct": {
                "threshold": ">= 90.0%",
                "actual": f"{round(recall, 2)}%",
                "passed": nfr03_recall_pass
            },
            "NFR-03_Precision_ge_85_pct": {
                "threshold": ">= 85.0%",
                "actual": f"{round(precision, 2)}%",
                "passed": nfr03_precision_pass
            },
            "NFR-03_FPR_le_15_pct": {
                "threshold": "<= 15.0%",
                "actual": f"{round(fpr, 2)}%",
                "passed": nfr03_fpr_pass
            },
            "NFR-02_Batch_Scan_Time_le_10s": {
                "threshold": "< 10.0s",
                "actual": f"{round(total_time_seconds, 3)}s",
                "passed": nfr02_time_pass
            }
        }
    }

    # In kết quả trực quan ra console
    print("=" * 70)
    print("  GITPROTECT BENCHMARK SUITE - 200 MẪU THỬ CHUẨN (PBI-12 / T05DB30)")
    print("=" * 70)
    print(f" Tổng số mẫu kiểm thử: {total_samples}")
    print(f" • True Positives (TP) : {tp:3d} / 100")
    print(f" • False Negatives (FN): {fn:3d} / 100")
    print(f" • False Positives (FP): {fp:3d} / 100")
    print(f" • True Negatives (TN) : {tn:3d} / 100")
    print("-" * 70)
    print(f" ► Recall (Độ bao phủ)        : {recall:6.2f}% (Yêu cầu: >= 90.0%) -> {'[PASS ✓]' if nfr03_recall_pass else '[FAIL ✗]'}")
    print(f" ► Precision (Độ chính xác)   : {precision:6.2f}% (Yêu cầu: >= 85.0%) -> {'[PASS ✓]' if nfr03_precision_pass else '[FAIL ✗]'}")
    print(f" ► FPR (Tỷ lệ báo động sai)  : {fpr:6.2f}% (Yêu cầu: <= 15.0%) -> {'[PASS ✓]' if nfr03_fpr_pass else '[FAIL ✗]'}")
    print(f" ► Thời gian quét 200 mẫu     : {total_time_seconds:6.3f}s (Yêu cầu NFR-02: < 10.0s) -> {'[PASS ✓]' if nfr02_time_pass else '[FAIL ✗]'}")
    print(f" ► Tốc độ trung bình / mẫu    : {avg_time_ms:6.2f} ms")
    print("=" * 70)

    # Lưu báo cáo nghiệm thu định dạng JSON và Markdown
    report_json_path = os.path.join(project_root, "BENCHMARK_REPORT.json")
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return report


if __name__ == "__main__":
    report = run_benchmark()
