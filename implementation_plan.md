# Implementation Plan

[Overview]
Implement comprehensive asset management functionality including CLI commands for adding, removing, and listing assets with robust validation against allowlists and integration with the existing database system.

[Types]  
Define enhanced asset management types including validation rules, asset history tracking, and configuration options.

Detailed type definitions:
- AssetValidationResult: Contains validation status, errors, and suggestions
- AllowlistEntry: Represents authorized IP ranges and domains
- AssetHistoryEntry: Tracks asset modifications and operations
- AssetManagementConfig: Configuration for asset validation and management

[Files]
Create and modify files to implement asset management functionality.

New files to create:
- src/agent/asset_validator.py: Asset validation logic and allowlist management
- src/utils/allowlist.py: Allowlist loading and management utilities
- tests/test_asset_management.py: Comprehensive tests for asset management
- tests/test_asset_validator.py: Tests for validation logic

Existing files to modify:
- src/agent/cli.py: Add remove-asset command and enhance existing commands
- src/agent/models.py: Add asset history and validation models
- src/agent/db.py: Add asset removal and history tracking functions
- docs/ARCHITECTURE.md: Update asset management documentation
- examples/workflows.md: Add asset management examples

[Functions]
Implement new functions for asset management operations and enhance existing ones.

New functions in src/agent/asset_validator.py:
- `AssetValidator.__init__()`: Initialize validator with configuration
- `AssetValidator.validate_ip()`: Validate IP addresses against allowlists
- `AssetValidator.validate_domain()`: Validate domains against allowlists
- `AssetValidator.validate_asset()`: Comprehensive asset validation
- `AssetValidator.load_allowlists()`: Load allowlists from configuration
- `AssetValidator.is_authorized_target()`: Check if target is authorized

New functions in src/agent/cli.py:
- `remove_asset()`: Remove an asset from the database
- `AssetValidator integration`: Integrate validation into add_asset command

Modified functions in src/agent/db.py:
- `remove_asset()`: Add asset removal functionality
- `get_asset_history()`: Track asset modifications
- `archive_asset()`: Soft delete option for assets

[Classes]
Create new classes for asset validation and management.

New classes in src/agent/asset_validator.py:
- `AssetValidator`: Main validation class with allowlist checking
- `AllowlistManager`: Manage IP ranges and domain allowlists
- `ValidationResult`: Standardized validation result structure

Modified classes in src/agent/models.py:
- `AssetModel`: Add validation and history tracking
- `ConfigModel`: Add asset management configuration options

[Dependencies]
Add necessary dependencies for asset validation and management.

New packages to consider:
- publicsuffix2>=2.20191223: For domain validation (if needed)
- ipaddress>=1.0.23: Already included for IP validation
- pydantic>=2.0.0: Already included for data validation

[Testing]
Create comprehensive test suite for asset management functionality.

Test files to create:
- tests/test_asset_management.py: CLI command and workflow tests
- tests/test_asset_validator.py: Validation logic and allowlist tests

Test cases required:
- CLI command success and failure scenarios
- IP and domain validation against various allowlists
- Asset addition, removal, and listing operations
- Database integration and error handling
- Edge cases and invalid input handling
- Allowlist configuration and loading tests

[Implementation Order]
Follow logical sequence to build interconnected components with minimal conflicts.

1. Create asset validator and allowlist management (src/agent/asset_validator.py)
2. Enhance models with validation and history tracking (src/agent/models.py)
3. Add database functions for asset removal and history (src/agent/db.py)
4. Implement CLI commands for asset management (src/agent/cli.py)
5. Create comprehensive test suite (tests/test_asset_management.py)
6. Update documentation (docs/ARCHITECTURE.md, examples/workflows.md)
7. Integration testing and validation
