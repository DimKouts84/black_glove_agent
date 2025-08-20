# Implementation Plan

[Overview]
Establish the core architecture components for the Black Glove pentest agent by implementing the Orchestrator, Policy Engine, and Plugin Manager modules. These components will form the foundation for workflow management, safety controls, and tool integration.

**Status: COMPLETED** - All core architecture components have been successfully implemented and tested.
**Implementation Notes:**
- All 8 steps completed successfully with comprehensive test coverage
- Integration tests passing (9/9 tests)
- Core components working together in demonstration script
- Safety controls implemented via Policy Engine
- LLM abstraction layer supports multiple providers
- Plugin system enables extensible tool adapter ecosystem

[Types]  
Define core architectural types including workflow states, policy rules, adapter interfaces, and orchestration contexts. Key types include OrchestrationContext, PolicyRule, AdapterInterface, and WorkflowStep.

Detailed type definitions:
- OrchestrationContext: Contains asset information, current workflow state, LLM client, database connection, and configuration
- PolicyRule: Defines safety constraints with validation functions and error handling
- AdapterInterface: Standardized interface for tool adapters with input/output contracts
- WorkflowStep: Represents a single step in the reconnaissance workflow with metadata
- LLMClient: Abstract interface for LLM interactions with different providers

[Files]
Create new core architecture files and establish the adapter interface structure.

New files to create:
- src/agent/orchestrator.py: Main workflow orchestration engine
- src/agent/policy_engine.py: Safety and compliance rule enforcement
- src/agent/plugin_manager.py: Tool adapter discovery and management
- src/agent/llm_client.py: LLM abstraction layer for different providers
- src/agent/reporting.py: Findings normalization and report generation
- src/adapters/__init__.py: Adapter interface definition and base classes
- src/adapters/interface.py: Standard adapter interface contract
- src/utils/docker_runner.py: Container sandboxing utility
- src/utils/rate_limiter.py: Rate limiting controls
- src/utils/evidence_store.py: Raw output storage and integrity
- tests/test_orchestrator.py: Orchestrator unit and integration tests
- tests/test_policy_engine.py: Policy validation tests
- tests/test_plugin_manager.py: Plugin system tests
- tests/test_llm_client.py: LLM integration tests

Existing files to modify:
- src/agent/__init__.py: Add imports for new modules
- pyproject.toml: Add any new dependencies if needed

[Functions]
Implement core architectural functions for workflow management, policy enforcement, and plugin handling.

New functions in src/agent/orchestrator.py:
- `Orchestrator.__init__()`: Initialize orchestrator with config, db, and llm client
- `Orchestrator.run_passive_recon()`: Execute passive reconnaissance workflow
- `Orchestrator.plan_active_scans()`: Use LLM to plan active scanning steps
- `Orchestrator.execute_scan_step()`: Run individual scan steps with approval
- `Orchestrator.process_tool_output()`: Process and normalize adapter results
- `Orchestrator.generate_report()`: Create findings report from scan results

New functions in src/agent/policy_engine.py:
- `PolicyEngine.__init__()`: Initialize with configuration and rules
- `PolicyEngine.validate_asset()`: Check asset authorization and safety
- `PolicyEngine.enforce_rate_limits()`: Apply rate limiting to scans
- `PolicyEngine.check_exploit_permissions()`: Validate lab mode for exploits
- `PolicyEngine.validate_target()`: Ensure target is in allowed ranges
- `PolicyEngine.log_violation()`: Record policy violations in audit log

New functions in src/agent/plugin_manager.py:
- `PluginManager.__init__()`: Initialize plugin discovery system
- `PluginManager.discover_adapters()`: Find and load available adapters
- `PluginManager.load_adapter()`: Load specific adapter by name
- `PluginManager.validate_adapter()`: Verify adapter implements interface
- `PluginManager.run_adapter()`: Execute adapter with parameters
- `PluginManager.get_adapter_info()`: Get adapter metadata and capabilities

New functions in src/agent/llm_client.py:
- `LLMClient.__init__()`: Initialize with provider configuration
- `LLMClient.plan_next_steps()`: Generate scan planning suggestions
- `LLMClient.analyze_findings()`: Interpret tool output and identify issues
- `LLMClient.explain_exploit()`: Provide safe exploit explanations
- `LLMClient.handle_failure()`: Manage LLM service unavailability

[Classes]
Create core architectural classes that implement the main system components.

New classes in src/agent/orchestrator.py:
- `Orchestrator`: Main workflow engine with methods for scan coordination
- `WorkflowManager`: Handles workflow state and step sequencing
- `ResultProcessor`: Normalizes and stores tool output

New classes in src/agent/policy_engine.py:
- `PolicyEngine`: Central safety rule enforcement system
- `RateLimiter`: Implements per-adapter and global rate limiting
- `TargetValidator`: Validates scan targets against asset lists

New classes in src/agent/plugin_manager.py:
- `PluginManager`: Manages adapter discovery and execution
- `AdapterManager`: Handles adapter lifecycle and configuration

New classes in src/adapters/interface.py:
- `AdapterInterface`: Abstract base class defining adapter contract
- `AdapterResult`: Standardized result structure for all adapters

[Dependencies]
Add necessary dependencies for core architecture components.

New packages to consider:
- langchain>=0.1.0: For LLM integration and prompt management (if needed)
- chromadb>=0.4.0: For local vector storage (optional for RAG features)
- docker>=6.0.0: Already included for container sandboxing
- pydantic>=2.0.0: Already included for data validation

[Testing]
Create comprehensive test suite for core architecture components.

Test files to create:
- tests/test_orchestrator.py: Tests for workflow orchestration
- tests/test_policy_engine.py: Safety rule validation tests
- tests/test_plugin_manager.py: Adapter discovery and execution tests
- tests/test_llm_client.py: LLM integration and prompt tests
- tests/test_integration.py: End-to-end workflow tests

Test cases required:
- Orchestrator workflow sequencing and error handling
- Policy engine rule enforcement and violation logging
- Plugin manager adapter discovery and validation
- LLM client prompt generation and response handling
- Integration tests for complete passive/active scan workflows
- Mock LLM and adapter testing for isolated component validation

[Implementation Order]
Follow logical sequence to build interconnected components with minimal conflicts.

1. Create adapter interface and base classes (src/adapters/)
2. Implement Policy Engine for safety controls (src/agent/policy_engine.py)
3. Build Plugin Manager for adapter handling (src/agent/plugin_manager.py)
4. Create LLM Client abstraction (src/agent/llm_client.py)
5. Implement Orchestrator core logic (src/agent/orchestrator.py)
6. Add utility modules (src/utils/)
7. Create comprehensive test suite
8. Integration testing and validation
9. Documentation updates
10. Example workflow demonstrations
