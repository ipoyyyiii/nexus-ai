"""
FALSE POSITIVE RATE TEST SUITE
===============================
Measure FP rate of the detection engine.

Usage:
    python tests/test_fp_rate.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engines.response_differ import ResponseDiffer
import hashlib


def create_mock_response(status_code: int, body: str, headers: dict = None) -> dict:
    """Create mock response for testing."""
    return {
        "status_code": status_code,
        "body": body,
        "body_length": len(body),
        "body_hash": hashlib.md5(body.encode()).hexdigest(),
        "headers": headers or {},
        "content_type": "text/html",
        "redirect_url": "",
        "response_time": None,
    }


def _run_false_positives():
    """Test cases that should NOT be flagged as vulnerabilities."""
    differ = ResponseDiffer()
    
    # Safe responses that should NOT trigger findings
    safe_cases = [
        # Normal 200 response
        {
            "name": "Normal 200 response",
            "baseline": create_mock_response(200, "<html><body>Hello World</body></html>"),
            "test": create_mock_response(200, "<html><body>Hello World</body></html>"),
            "payload": "test",
            "expected": "safe",
        },
        # Error page that looks like vulnerability but isn't
        {
            "name": "Laravel error page (should be filtered)",
            "baseline": create_mock_response(200, "<html><body>Normal page</body></html>"),
            "test": create_mock_response(500, "Whoops! Something went wrong. Laravel error page with stacktrace and debug info."),
            "payload": "' OR '1'='1",
            "expected": "safe",
        },
        # Payload reflected but escaped
        {
            "name": "Payload reflected but HTML escaped",
            "baseline": create_mock_response(200, "<html><body>Search results</body></html>"),
            "test": create_mock_response(200, "<html><body>Search results for: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>"),
            "payload": "<script>alert(1)</script>",
            "expected": "safe",
        },
        # Same response with different timing
        {
            "name": "Same response, just slower",
            "baseline": create_mock_response(200, "<html><body>Data</body></html>"),
            "test": create_mock_response(200, "<html><body>Data</body></html>"),
            "payload": "' OR SLEEP(5)--",
            "expected": "safe",
        },
        # 500 error but consistent error template
        {
            "name": "Consistent 500 error page",
            "baseline": create_mock_response(500, "Internal Server Error - Apache/2.4.41"),
            "test": create_mock_response(500, "Internal Server Error - Apache/2.4.41"),
            "payload": "' OR '1'='1",
            "expected": "safe",
        },
    ]
    
    results = {"passed": 0, "failed": 0, "details": []}
    
    for case in safe_cases:
        diff = differ.compare(case["baseline"], case["test"], payload=case["payload"])
        
        is_safe = diff["severity"] == "safe" or diff["vulnerability_score"] < 0.3
        
        if is_safe == (case["expected"] == "safe"):
            results["passed"] += 1
            results["details"].append(f"✅ {case['name']}: PASS (score={diff['vulnerability_score']:.2f})")
        else:
            results["failed"] += 1
            results["details"].append(f"❌ {case['name']}: FAIL (score={diff['vulnerability_score']:.2f}, expected={case['expected']})")
    
    return results


def _run_true_positives():
    """Test cases that SHOULD be flagged as vulnerabilities."""
    differ = ResponseDiffer()
    
    # Vulnerable responses that SHOULD trigger findings
    vulnerable_cases = [
        # SQL error in response
        {
            "name": "SQL error in response",
            "baseline": create_mock_response(200, "<html><body>Normal</body></html>"),
            "test": create_mock_response(500, "You have an error in your SQL syntax near 'OR' at line 1"),
            "payload": "' OR '1'='1",
            "expected": "vulnerable",
        },
        # XSS payload reflected unescaped
        {
            "name": "XSS payload reflected unescaped",
            "baseline": create_mock_response(200, "<html><body>Search</body></html>"),
            "test": create_mock_response(200, '<html><body>Search: <script>alert(1)</script></body></html>'),
            "payload": "<script>alert(1)</script>",
            "expected": "vulnerable",
        },
        # File content exposed
        {
            "name": "File content exposed (LFI)",
            "baseline": create_mock_response(200, "<html><body>Normal</body></html>"),
            "test": create_mock_response(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"),
            "payload": "../../../etc/passwd",
            "expected": "vulnerable",
        },
        # Template evaluation result
        {
            "name": "Template evaluation (SSTI)",
            "baseline": create_mock_response(200, "<html><body>Template</body></html>"),
            "test": create_mock_response(200, "<html><body>49</body></html>"),
            "payload": "{{7*7}}",
            "expected": "vulnerable",
        },
    ]
    
    results = {"passed": 0, "failed": 0, "details": []}
    
    for case in vulnerable_cases:
        diff = differ.compare(case["baseline"], case["test"], payload=case["payload"])
        
        is_vulnerable = diff["severity"] in ["critical", "high"] or diff["vulnerability_score"] >= 0.5
        
        if is_vulnerable == (case["expected"] == "vulnerable"):
            results["passed"] += 1
            results["details"].append(f"✅ {case['name']}: PASS (score={diff['vulnerability_score']:.2f})")
        else:
            results["failed"] += 1
            results["details"].append(f"❌ {case['name']}: FAIL (score={diff['vulnerability_score']:.2f}, expected={case['expected']})")
    
    return results


def test_false_positives():
    results = _run_false_positives()
    assert results["failed"] == 0, results["details"]


def test_true_positives():
    results = _run_true_positives()
    assert results["failed"] == 0, results["details"]


def run_all_tests():
    """Run all tests and calculate FP rate."""
    print("=" * 60)
    print("FALSE POSITIVE RATE TEST SUITE")
    print("=" * 60)
    print()
    
    # Test false positives
    print("Testing False Positives (should NOT be flagged)...")
    fp_results = _run_false_positives()
    print(f"Results: {fp_results['passed']}/{fp_results['passed'] + fp_results['failed']} passed")
    for detail in fp_results["details"]:
        print(f"  {detail}")
    print()
    
    # Test true positives
    print("Testing True Positives (SHOULD be flagged)...")
    tp_results = _run_true_positives()
    print(f"Results: {tp_results['passed']}/{tp_results['passed'] + tp_results['failed']} passed")
    for detail in tp_results["details"]:
        print(f"  {detail}")
    print()
    
    # Calculate rates
    total_tests = fp_results["passed"] + fp_results["failed"] + tp_results["passed"] + tp_results["failed"]
    false_positives = fp_results["failed"]  # Cases that should be safe but were flagged
    false_negatives = tp_results["failed"]  # Cases that should be vulnerable but weren't flagged
    
    fp_rate = (false_positives / (fp_results["passed"] + fp_results["failed"])) * 100 if (fp_results["passed"] + fp_results["failed"]) > 0 else 0
    fn_rate = (false_negatives / (tp_results["passed"] + tp_results["failed"])) * 100 if (tp_results["passed"] + tp_results["failed"]) > 0 else 0
    accuracy = ((fp_results["passed"] + tp_results["passed"]) / total_tests) * 100 if total_tests > 0 else 0
    
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {total_tests}")
    print(f"False Positive Rate: {fp_rate:.1f}% ({false_positives} FP out of {fp_results['passed'] + fp_results['failed']})")
    print(f"False Negative Rate: {fn_rate:.1f}% ({false_negatives} FN out of {tp_results['passed'] + tp_results['failed']})")
    print(f"Overall Accuracy: {accuracy:.1f}%")
    print()
    
    if fp_rate < 10:
        print("✅ FP rate is GOOD (< 10%)")
    elif fp_rate < 20:
        print("⚠️ FP rate is ACCEPTABLE (10-20%)")
    else:
        print("❌ FP rate is HIGH (> 20%) - needs improvement")
    
    return {
        "fp_rate": fp_rate,
        "fn_rate": fn_rate,
        "accuracy": accuracy,
        "total_tests": total_tests,
    }


if __name__ == "__main__":
    results = run_all_tests()
