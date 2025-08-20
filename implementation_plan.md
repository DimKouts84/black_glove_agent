# Implementation Plan

[Overview]
Establish the foundational structure for the Black Glove pentest agent by creating the required directory structure, implementing the `agent init` command, and initializing the SQLite database according to the specifications in sections 10 and 15 of the requirements document.

[Types]  
Directory paths: string values representing file system paths
SQLite schema: tables with defined columns and constraints
Configuration options: YAML key-value pairs for agent settings

Detailed type definitions:
- AssetType: enum('host', 'domain', 'vm')
- SeverityLevel: enum('low', 'medium', 'high', 'critical')
- EventType: enum for audit log event types (approval, llm_failure, adapter_invocation, etc.)

[Files]
New files to create:
- src/agent/__init__.py: Package initialization
- src/agent/cli.py: Typer CLI implementation for `agent init` command
- src/agent/db.py: Database initialization module with schema creation
- src/agent/models.py: Pydantic models for configuration and data structures
- config/default_config.yaml: Default configuration template
- docker/Dockerfile.agent: Dockerfile for agent containerization
- docker/docker-compose.yml: Tooling containers for lab environment
- docs/ARCHITECTURE.md: Architecture documentation
- docs/SECURITY.md: Security policies and safety controls
- examples/assets.yml: Sample asset configuration
- examples/workflows.md: Example usage workflows

Existing files to modify:
- README.md: Add basic setup instructions and project overview
- LICENSE: Verify compatibility with project (no changes needed if MIT)

Directory structure to create:
- src/agent/
- src/adapters/
- src/utils/
- config/
- docker/
- examples/
- docs/

[Functions]
New functions in src/agent/cli.py:
- `init_command()`: Main init command handler with Typer decorator
- `create_directory_structure()`: Creates required project directories with error handling
- `verify_prerequisites()`: Checks Docker connectivity, LLM services, file permissions
- `setup_config_file()`: Creates ~/.homepentest/config.yaml from template
- `initialize_database()`: Calls database initialization functions
- `show_legal_notice()`: Displays mandatory legal notice and requires acknowledgment

New functions in src/agent/db.py:
- `init_db()`: Creates SQLite database at ~/.homepentest/homepentest.db
- `create_assets_table()`: Creates assets table with schema from section 10
- `create_findings_table()`: Creates findings table with schema from section 10
- `create_audit_log_table()`: Creates audit_log table with JSON data column
- `run_migrations()`: Handles schema migrations for future updates

New functions in src/agent/models.py:
- `ConfigModel`: Pydantic model for configuration validation
- `AssetModel`: Model for asset data validation

[Classes]
New classes in src/agent/models.py:
- `ConfigModel`: Pydantic BaseModel for configuration with fields for LLM endpoints, scan parameters, logging settings
- `AssetModel`: BaseModel for asset validation with name, type, value fields
- `DatabaseManager`: Class to handle database operations and connections

[Dependencies]
New packages to add to pyproject.toml:
- typer>=0.9.0: CLI framework
- pydantic>=2.0.0: Data validation
- docker>=6.0.0: Docker SDK for prerequisite checking
- PyYAML>=6.0: YAML configuration handling
- sqlite3: Built-in for database operations

[Testing]
Test files to create:
- tests/test_init_command.py: Tests for init command functionality
- tests/test_db_init.py: Database initialization tests
- tests/test_config_setup.py: Configuration file generation tests
- tests/test_prerequisites.py: Prerequisite verification tests
- tests/conftest.py: Test configuration and fixtures

Test cases required:
- Verify directory structure creation with proper permissions
- Test config file generation from template with validation
- Validate database schema creation with all required tables
- Check prerequisite verification logic for Docker and LLM services
- Test legal notice display and acknowledgment requirement
- Verify error handling for missing dependencies and permission issues
- Test idempotency of init command (safe to run multiple times)

[Implementation Order]
1. Create directory structure (Task 1.1) - Create all required directories: src/agent/, src/adapters/, config/, docker/, examples/, docs/
2. Implement database initialization (Task 1.3) - Create SQLite DB with assets, findings, and audit_log tables according to section 10 schema
3. Create configuration template and models - Set up default_config.yaml and Pydantic models for validation
4. Implement core init command functionality (Task 1.2) - Create CLI command to set up directories, config files, and verify prerequisites
5. Add legal notice and acknowledgment (section 9) - Implement mandatory first-run legal notice with typed acknowledgment
6. Add prerequisite verification - Check Docker connectivity and LLM service availability
7. Create documentation stubs - ARCHITECTURE.md and SECURITY.md files
8. Write comprehensive tests - Unit tests for all components with proper test coverage
9. Update README and examples - Documentation and usage examples
10. Final validation - End-to-end testing of init command and verification
