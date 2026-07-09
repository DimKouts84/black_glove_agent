import pytest
from unittest.mock import MagicMock, patch

from src.adapters.ssl_check import SslCheckAdapter
from src.adapters.interface import AdapterResultStatus


class TestSslCheckAdapter:
    def test_target_resolves_to_host(self):
        adapter = SslCheckAdapter({})
        params = {"target": "example.com"}
        adapter.validate_params(params)
        assert params["host"] == "example.com"

    @patch("src.adapters.ssl_check.socket.create_connection")
    @patch("src.adapters.ssl_check.ssl.create_default_context")
    def test_execute_returns_cert_metadata(self, mock_ctx, mock_conn):
        ssock = MagicMock()
        ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "version": 3,
            "serialNumber": "ABC",
            "notBefore": "Jan 01 00:00:00 2020 GMT",
            "notAfter": "Jan 01 00:00:00 2030 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        ssock.getpeercert.return_value = ssock.getpeercert.return_value
        ssock.__enter__ = MagicMock(return_value=ssock)
        ssock.__exit__ = MagicMock(return_value=False)

        sock = MagicMock()
        sock.__enter__ = MagicMock(return_value=ssock)
        sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = sock

        ctx = MagicMock()
        ctx.wrap_socket.return_value = ssock
        mock_ctx.return_value = ctx

        adapter = SslCheckAdapter({})
        result = adapter.execute({"host": "example.com"})

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["trust_validated"] is False
        assert result.data["subject"]["commonName"] == "example.com"

    @patch("src.adapters.ssl_check.datetime")
    @patch("src.adapters.ssl_check.socket.create_connection")
    @patch("src.adapters.ssl_check.ssl.create_default_context")
    def test_expired_cert_flag(self, mock_ctx, mock_conn, mock_dt):
        import datetime as real_dt

        mock_dt.datetime.strptime = real_dt.datetime.strptime
        mock_dt.datetime.now.return_value = real_dt.datetime(2025, 6, 1, tzinfo=real_dt.timezone.utc)

        ssock = MagicMock()
        ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "Jan 01 00:00:00 2020 GMT",
            "notAfter": "Jan 01 00:00:00 2024 GMT",
        }
        ssock.__enter__ = MagicMock(return_value=ssock)
        ssock.__exit__ = MagicMock(return_value=False)

        sock = MagicMock()
        sock.__enter__ = MagicMock(return_value=ssock)
        sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = sock

        ctx = MagicMock()
        ctx.wrap_socket.return_value = ssock
        mock_ctx.return_value = ctx

        adapter = SslCheckAdapter({})
        result = adapter.execute({"host": "example.com"})

        assert result.data["is_expired"] is True
