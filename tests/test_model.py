import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.predict import predict, IOC_TYPE_MAP
import numpy as np

def test_predict_ip_c2():
    result = predict("192.168.1.100", "ip", confidence=80, is_c2=1)
    assert result["label"] in ["Critical", "High", "Medium", "Low"]
    assert "explanation" in result
    print(f"Test passed: {result}")

def test_predict_healthcare():
    result = predict("malicious-hacker.com", "domain", confidence=70, is_healthcare=1)
    assert result["label"] in ["Critical", "High", "Medium", "Low"]
    print(f"Test passed: {result}")

def test_ioc_type_map():
    assert IOC_TYPE_MAP["ip"] == 0
    assert IOC_TYPE_MAP["domain"] == 1
    assert IOC_TYPE_MAP["url"] == 2
    print("IOC type map test passed")

if __name__ == "__main__":
    print("Running tests...")
    test_ioc_type_map()
    test_predict_ip_c2()
    test_predict_healthcare()
    print("All tests passed!")