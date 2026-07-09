import pytest
from src.adapters.interface import AdapterResult, AdapterResultStatus
from src.adapters.camera_security import create_camera_security_adapter


class TestCameraSecurityInterpretResult:
    @pytest.fixture
    def adapter(self):
        return create_camera_security_adapter({})

    def test_interpret_string_findings(self, adapter):
        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "target": "192.168.1.50",
                "open_ports": [{"port": 554, "service": "RTSP"}],
                "findings": [
                    "⚠️ RTSP VULNERABILITY: Anonymous RTSP stream accessible",
                    "✓ HTTP interface requires authentication",
                ],
                "vulnerabilities_detected": True,
            },
            metadata={},
        )

        text = adapter.interpret_result(result)
        assert "554/RTSP" in text
        assert "Anonymous RTSP" in text
        assert "CRITICAL" in text
