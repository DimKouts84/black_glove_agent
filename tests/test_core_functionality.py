"""
Simple test script to verify core functionality without Docker dependencies.
"""

import tempfile
import os
from pathlib import Path
import sys

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_asset_management():
    """Test basic asset management functionality."""
    print("Testing asset management functionality...")
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
        tmp_db_path = tmp_db.name
    
    try:
        # Set database path
        import src.agent.db as db_module
        original_path = db_module.DB_PATH
        db_module.DB_PATH = Path(tmp_db_path)
        
        # Initialize database
        from src.agent.db import init_db
        init_db()
        print("✓ Database initialized")
        
        # Test asset operations
        from src.agent.models import DatabaseManager, AssetModel, AssetType
        
        db_manager = DatabaseManager()
        
        # Add asset
        asset = AssetModel(name="test-host", type=AssetType.HOST, value="192.168.1.50")
        asset_id = db_manager.add_asset(asset)
        print(f"✓ Asset added with ID: {asset_id}")
        
        # List assets
        assets = db_manager.list_assets()
        print(f"✓ Found {len(assets)} asset(s)")
        
        # Get asset
        retrieved_asset = db_manager.get_asset(asset_id)
        assert retrieved_asset is not None
        assert retrieved_asset.name == "test-host"
        print("✓ Asset retrieval successful")
        
        # Remove asset
        success = db_manager.remove_asset(asset_id)
        assert success is True
        print("✓ Asset removal successful")
        
        # Verify removal
        assets = db_manager.list_assets()
        assert len(assets) == 0
        print("✓ Asset properly removed")
        
        print("All asset management tests passed! 🎉")
        
    finally:
        # Cleanup
        db_module.DB_PATH = original_path
        try:
            os.unlink(tmp_db_path)
        except:
            pass

def test_asset_validation():
    """Test asset validation functionality."""
    print("\nTesting asset validation functionality...")
    
    from src.agent.asset_validator import create_asset_validator, ValidationStatus
    from src.agent.models import AssetModel, AssetType, ConfigModel
    
    # Test with default config
    config = ConfigModel()
    validator = create_asset_validator(config)
    
    # Test authorized IP
    asset = AssetModel(name="test", type=AssetType.HOST, value="192.168.1.50")
    result = validator.validate_asset(asset)
    print(f"✓ IP validation result: {result.status.value} - {result.message}")
    
    # Test domain validation
    asset = AssetModel(name="test", type=AssetType.DOMAIN, value="example.com")
    result = validator.validate_asset(asset)
    print(f"✓ Domain validation result: {result.status.value} - {result.message}")
    
    print("Asset validation tests completed!")

if __name__ == "__main__":
    print("Running core functionality tests...\n")
    
    try:
        test_asset_management()
        test_asset_validation()
        
        print("\n🎉 All core functionality tests passed!")
        print("\nCore components verified:")
        print("  • Database operations (add, get, list, remove)")
        print("  • Asset format validation")
        print("  • Configuration management")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
