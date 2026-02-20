"""
quick_test.py — Automated test suite for VerifyFirst backend
Run before hackathon to verify everything works
"""

import requests
import time

BACKEND = "http://127.0.0.1:8000"

# Test URLs
TESTS = [
    # (url, expected_category, description)
    ("https://meganmacylesolutions.com/secure/login.onlinebanking.suntrust.com/online.htm", "dangerous", "Blacklist - Banking phishing"),
    ("http://jissr.org/mapping/onedrivelogon.php", "dangerous", "Blacklist - OneDrive phishing"),
    ("https://github.com", "safe", "Legitimate - GitHub"),
    ("https://www.microsoft.com", "safe", "Legitimate - Microsoft"),
    ("https://docs.python.org", "safe", "Legitimate - Python Docs"),
    ("http://192.168.1.1/admin/login", "suspicious", "IP address + keywords"),
    ("http://example-login-verify.tk/secure", "suspicious", "Suspicious domain + keywords"),
]

def test_backend():
    """Run all tests and report results"""
    print("=" * 70)
    print("  VerifyFirst — Pre-Hackathon Test Suite")
    print("=" * 70)
    
    # Check backend health
    try:
        health = requests.get(f"{BACKEND}/health", timeout=2).json()
        print(f"\n✅ Backend Status: {health['status'].upper()}")
        print(f"   Cache Size: {health.get('cache_size', 0)}")
    except Exception as e:
        print(f"\n❌ Backend OFFLINE: {e}")
        print("   Run: python backend/main.py")
        return
    
    # Run tests
    print(f"\n{'='*70}")
    print("Running URL Analysis Tests...")
    print(f"{'='*70}\n")
    
    passed = 0
    failed = 0
    
    for url, expected, description in TESTS:
        try:
            start = time.time()
            response = requests.post(
                f"{BACKEND}/analyze",
                json={"url": url},
                timeout=5
            )
            elapsed = (time.time() - start) * 1000
            
            result = response.json()
            category = result.get("category", "unknown")
            score = result.get("risk_score", 0)
            
            # Check if result matches expectation
            if category == expected:
                status = "✅ PASS"
                passed += 1
                color = "green"
            else:
                status = "❌ FAIL"
                failed += 1
                color = "red"
            
            print(f"{status} | {description}")
            print(f"      URL: {url[:60]}...")
            print(f"      Expected: {expected} | Got: {category} | Score: {score} | Time: {elapsed:.0f}ms")
            print()
            
        except Exception as e:
            print(f"❌ ERROR | {description}")
            print(f"      {str(e)}")
            print()
            failed += 1
    
    # Summary
    print(f"{'='*70}")
    print(f"Test Results: {passed} passed, {failed} failed")
    print(f"{'='*70}")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! Ready for hackathon!")
    else:
        print(f"\n⚠️  {failed} test(s) failed. Review results above.")
    
    # Get stats
    try:
        stats = requests.get(f"{BACKEND}/stats", timeout=2).json()
        print(f"\n📊 Backend Statistics:")
        print(f"   Dangerous: {stats.get('dangerous', 0)}")
        print(f"   Suspicious: {stats.get('suspicious', 0)}")
        print(f"   Safe: {stats.get('safe', 0)}")
    except:
        pass
    
    print("\n" + "="*70)
    print("Next Steps:")
    print("  1. Load extension: chrome://extensions → Load unpacked → select 'extension' folder")
    print("  2. Test URLs in Chrome browser")
    print("  3. Review TESTING_GUIDE.md for full test suite")
    print("="*70 + "\n")


if __name__ == "__main__":
    test_backend()
