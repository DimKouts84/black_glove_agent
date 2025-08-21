"""
Tests for Deployment Scripts

This module contains tests for the deployment preparation scripts.
"""

import pytest
import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestDeploymentScripts:
    """Test cases for deployment scripts."""
    
    def test_deployment_scripts_exist(self):
        """Test that deployment scripts exist."""
        deploy_sh = Path("scripts/deploy.sh")
        deploy_bat = Path("scripts/deploy.bat")
        
        assert deploy_sh.exists(), "deploy.sh should exist"
        assert deploy_bat.exists(), "deploy.bat should exist"
    
    def test_deployment_scripts_are_readable(self):
        """Test that deployment scripts are readable."""
        deploy_sh = Path("scripts/deploy.sh")
        deploy_bat = Path("scripts/deploy.bat")
        
        assert os.access(deploy_sh, os.R_OK), "deploy.sh should be readable"
        assert os.access(deploy_bat, os.R_OK), "deploy.bat should be readable"
    
    def test_deployment_scripts_content(self):
        """Test that deployment scripts contain expected content."""
        # Test bash script
        deploy_sh_content = Path("scripts/deploy.sh").read_text(encoding='utf-8')
        assert "Black Glove Deployment Script" in deploy_sh_content
        assert "deployment package" in deploy_sh_content
        assert "tar -czf" in deploy_sh_content
        
        # Test batch script
        deploy_bat_content = Path("scripts/deploy.bat").read_text(encoding='utf-8')
        # Check for key content (avoiding emoji encoding issues)
        assert "Black Glove Deployment Script" in deploy_bat_content or "Black Glove" in deploy_bat_content
        assert "deployment package" in deploy_bat_content
        assert "xcopy" in deploy_bat_content
    
    def test_deployment_scripts_shebang(self):
        """Test that bash script has correct shebang."""
        deploy_sh_content = Path("scripts/deploy.sh").read_text(encoding='utf-8')
        assert deploy_sh_content.startswith("#!/bin/bash")
    
    def test_deployment_scripts_executable_lines(self):
        """Test that scripts contain key executable lines."""
        deploy_sh_content = Path("scripts/deploy.sh").read_text(encoding='utf-8')
        deploy_bat_content = Path("scripts/deploy.bat").read_text(encoding='utf-8')
        
        # Bash script should have key commands
        assert "mkdir -p" in deploy_sh_content
        assert "cp -r" in deploy_sh_content
        assert "pip freeze" in deploy_sh_content
        
        # Batch script should have key commands
        assert "mkdir" in deploy_bat_content
        assert "xcopy" in deploy_bat_content
        assert "pip freeze" in deploy_bat_content


if __name__ == "__main__":
    pytest.main([__file__])
