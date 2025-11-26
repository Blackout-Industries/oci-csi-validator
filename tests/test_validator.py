"""
Unit tests for OCI CSI VolumeAttachment Validator
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch
from kubernetes.client.rest import ApiException

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from oci_csi_validator import (
    VolumeAttachmentInfo,
    ValidationReport,
    ConfigValidator,
    KubernetesClient,
    VolumeAttachmentValidator
)


class TestVolumeAttachmentInfo:
    """Test VolumeAttachmentInfo dataclass."""

    def test_age_human_hours(self):
        """Test human-readable age formatting for hours."""
        att = VolumeAttachmentInfo(
            name="test-att",
            node_name="node-1",
            pv_name="pv-1",
            age_seconds=7200,  # 2 hours
            attacher="csi.oraclecloud.com",
            is_orphaned=False
        )
        assert att.age_human == "2h0m"

    def test_age_human_minutes(self):
        """Test human-readable age formatting for minutes."""
        att = VolumeAttachmentInfo(
            name="test-att",
            node_name="node-1",
            pv_name="pv-1",
            age_seconds=1800,  # 30 minutes
            attacher="csi.oraclecloud.com",
            is_orphaned=False
        )
        assert att.age_human == "30m"

    def test_to_dict(self):
        """Test dictionary conversion."""
        att = VolumeAttachmentInfo(
            name="test-att",
            node_name="node-1",
            pv_name="pv-1",
            age_seconds=3600,
            attacher="csi.oraclecloud.com",
            is_orphaned=True
        )
        data = att.to_dict()
        assert data['name'] == "test-att"
        assert data['is_orphaned'] is True
        assert data['age_human'] == "1h0m"


class TestConfigValidator:
    """Test configuration validation."""

    @patch.dict('os.environ', {
        'OCI_COMPARTMENT_ID': 'ocid1.compartment.oc1..test'
    })
    @patch('oci_csi_validator.Path.exists', return_value=False)
    def test_load_config_success(self, mock_exists):
        """Test successful config loading."""
        config = ConfigValidator.load_config()
        assert config['compartment_id'] == 'ocid1.compartment.oc1..test'
        assert 'k8s_context' in config

    @patch.dict('os.environ', {}, clear=True)
    @patch('oci_csi_validator.Path.exists', return_value=False)
    def test_load_config_missing_required(self, mock_exists):
        """Test error on missing required config."""
        with pytest.raises(ValueError) as exc_info:
            ConfigValidator.load_config()
        assert "OCI_COMPARTMENT_ID is required" in str(exc_info.value)


class TestKubernetesClient:
    """Test Kubernetes client wrapper."""

    @patch('oci_csi_validator.config.load_kube_config')
    @patch('oci_csi_validator.config.list_kube_config_contexts')
    @patch('oci_csi_validator.client.StorageV1Api')
    @patch('oci_csi_validator.client.CoreV1Api')
    def test_init_with_context(
        self,
        mock_core,
        mock_storage,
        mock_list_ctx,
        mock_load
    ):
        """Test initialization with explicit context."""
        mock_list_ctx.return_value = (None, {'name': 'test-context'})

        k8s_client = KubernetesClient(context='test-context')

        mock_load.assert_called_once_with(context='test-context')
        assert k8s_client.context == 'test-context'

    @patch('oci_csi_validator.config.load_kube_config')
    def test_init_connection_error(self, mock_load):
        """Test error handling on connection failure."""
        mock_load.side_effect = Exception("Connection failed")

        with pytest.raises(Exception) as exc_info:
            KubernetesClient()
        assert "Connection failed" in str(exc_info.value)

    def test_get_active_nodes(self):
        """Test getting active nodes."""
        # Mock client
        mock_client = Mock()
        mock_node1 = Mock()
        mock_node1.metadata.name = "node-1"
        mock_node2 = Mock()
        mock_node2.metadata.name = "node-2"

        mock_response = Mock()
        mock_response.items = [mock_node1, mock_node2]
        mock_client.core_v1.list_node.return_value = mock_response

        # Patch initialization
        with patch.object(KubernetesClient, '__init__', lambda x, context=None: None):
            k8s_client = KubernetesClient()
            k8s_client.core_v1 = mock_client.core_v1

            nodes = k8s_client.get_active_nodes()
            assert nodes == {"node-1", "node-2"}

    def test_get_volume_attachments(self):
        """Test getting volume attachments."""
        # Mock attachment
        mock_att = Mock()
        mock_att.metadata.name = "att-1"
        mock_att.metadata.creation_timestamp = datetime.now(timezone.utc)
        mock_att.spec.node_name = "node-1"
        mock_att.spec.source.persistent_volume_name = "pv-1"
        mock_att.spec.attacher = "csi.oraclecloud.com"

        mock_response = Mock()
        mock_response.items = [mock_att]

        mock_client = Mock()
        mock_client.storage_v1.list_volume_attachment.return_value = mock_response

        with patch.object(KubernetesClient, '__init__', lambda x, context=None: None):
            k8s_client = KubernetesClient()
            k8s_client.storage_v1 = mock_client.storage_v1

            attachments = k8s_client.get_volume_attachments()
            assert len(attachments) == 1
            assert attachments[0].name == "att-1"
            assert attachments[0].node_name == "node-1"


class TestVolumeAttachmentValidator:
    """Test validation logic."""

    def test_validate_no_orphans(self):
        """Test validation with no orphaned attachments."""
        # Mock K8s client
        mock_k8s = Mock()
        mock_k8s.context = "test-context"
        mock_k8s.get_active_nodes.return_value = {"node-1", "node-2"}

        att1 = VolumeAttachmentInfo(
            name="att-1",
            node_name="node-1",
            pv_name="pv-1",
            age_seconds=3600,
            attacher="csi.oraclecloud.com",
            is_orphaned=False
        )
        mock_k8s.get_volume_attachments.return_value = [att1]

        validator = VolumeAttachmentValidator(
            k8s_client=mock_k8s,
            compartment_id="test-compartment"
        )

        report = validator.validate()

        assert report.total_attachments == 1
        assert report.active_nodes == 2
        assert len(report.orphaned_attachments) == 0
        assert report.healthy_attachments == 1

    def test_validate_with_orphans(self):
        """Test validation with orphaned attachments."""
        # Mock K8s client
        mock_k8s = Mock()
        mock_k8s.context = "test-context"
        mock_k8s.get_active_nodes.return_value = {"node-1"}

        att1 = VolumeAttachmentInfo(
            name="att-1",
            node_name="node-1",
            pv_name="pv-1",
            age_seconds=3600,
            attacher="csi.oraclecloud.com",
            is_orphaned=False
        )
        att2 = VolumeAttachmentInfo(
            name="att-2",
            node_name="node-missing",
            pv_name="pv-2",
            age_seconds=7200,
            attacher="csi.oraclecloud.com",
            is_orphaned=False
        )
        mock_k8s.get_volume_attachments.return_value = [att1, att2]

        validator = VolumeAttachmentValidator(
            k8s_client=mock_k8s,
            compartment_id="test-compartment"
        )

        report = validator.validate()

        assert report.total_attachments == 2
        assert len(report.orphaned_attachments) == 1
        assert report.orphaned_attachments[0].name == "att-2"
        assert report.healthy_attachments == 1

    def test_cleanup_orphaned_success(self):
        """Test successful cleanup of orphaned attachments."""
        # Mock K8s client
        mock_k8s = Mock()
        mock_k8s.get_active_nodes.return_value = {"node-1"}
        mock_k8s.delete_volume_attachment.return_value = True

        att_orphaned = VolumeAttachmentInfo(
            name="att-orphaned",
            node_name="node-missing",
            pv_name="pv-1",
            age_seconds=3600,
            attacher="csi.oraclecloud.com",
            is_orphaned=True
        )

        validator = VolumeAttachmentValidator(
            k8s_client=mock_k8s,
            compartment_id="test-compartment"
        )

        results = validator.cleanup_orphaned([att_orphaned], skip_confirmation=True)

        assert results['deleted'] == 1
        assert results['failed'] == 0
        assert results['skipped'] == 0
        mock_k8s.delete_volume_attachment.assert_called_once_with("att-orphaned")

    def test_cleanup_orphaned_node_reappears(self):
        """Test cleanup skips if node reappears."""
        # Mock K8s client - node reappears during re-validation
        mock_k8s = Mock()
        mock_k8s.get_active_nodes.return_value = {"node-1", "node-reappeared"}

        att_orphaned = VolumeAttachmentInfo(
            name="att-orphaned",
            node_name="node-reappeared",
            pv_name="pv-1",
            age_seconds=3600,
            attacher="csi.oraclecloud.com",
            is_orphaned=True
        )

        validator = VolumeAttachmentValidator(
            k8s_client=mock_k8s,
            compartment_id="test-compartment"
        )

        results = validator.cleanup_orphaned([att_orphaned], skip_confirmation=True)

        assert results['deleted'] == 0
        assert results['failed'] == 0
        assert results['skipped'] == 1


class TestValidationReport:
    """Test validation report dataclass."""

    def test_to_dict(self):
        """Test report serialization."""
        att = VolumeAttachmentInfo(
            name="att-1",
            node_name="node-missing",
            pv_name="pv-1",
            age_seconds=3600,
            attacher="csi.oraclecloud.com",
            is_orphaned=True
        )

        report = ValidationReport(
            total_attachments=10,
            active_nodes=5,
            orphaned_attachments=[att],
            healthy_attachments=9,
            compartment_id="test-comp",
            k8s_context="test-ctx",
            scan_timestamp="2025-01-01T00:00:00Z"
        )

        data = report.to_dict()
        assert data['orphaned_count'] == 1
        assert data['healthy_count'] == 9
        assert len(data['orphaned_attachments']) == 1
        assert data['orphaned_attachments'][0]['name'] == "att-1"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
