# End-to-End Test Plan for Black Glove

## Objective
Verify the functionality of the Black Glove LLM-powered CLI tool, focusing on the interactive chat session, asset management, tool execution, and reporting.

## Prerequisites
- Python 3.8+ (Verified)
- Virtual Environment activated (Verified)
- Dependencies installed (Verified via venv)
- External Tools:
    - `nmap` (To be installed/verified)
    - `gobuster` (To be installed/verified)
    - `dns_lookup` (Python-based, should be available)

## Scenarios

### 1. Continuous Chat Session
**User Story:** As a user I expect to have a continue session of chat with the Black Glove LLM, so that I will not initiate the CLI again, unless I close it.
**Test:**
- Launch `agent chat`.
- Verify the session starts and welcomes the user.
- Verify the session ID is persisted/displayed.

### 2. Add Asset via LLM
**User Story:** As a user I would like to ask the LLM to add an asset, so that it will be saved by the LLM and not me.
**Test:**
- In the chat, ask: "Add google.com as a domain asset."
- Verify the agent confirms the addition.
- Verify the asset appears in the database (or via `list assets` command in chat).

### 3. Run Tool (with Asset Request)
**User Story:** As a use I would like to ask the LLM to run a tools or module and the LLM should request back the asset if required and not provided by the user.
**Test:**
- Ask: "Run a DNS lookup." (without specifying target).
- Verify the agent asks for the target.
- Provide the target (e.g., "google.com").
- Verify the tool runs and returns results.

### 4. Multiple Tools Execution
**User Story:** As a user I would like to request multiple tools to be run either fron one chat prompt or many in sequence.
**Test:**
- Ask: "Run a DNS lookup on google.com and then check its SSL certificate." (assuming `ssl_check` adapter exists).
- Verify the agent plans and executes both tools.
- Verify results for both are shown.

### 5. Conversation History
**User Story:** As a user I expect my conversation to be saved and retrieve by the LLM so that in will remember previous messages in this session.
**Test:**
- Ask: "What was the IP address from the DNS lookup we just did?"
- Verify the agent can retrieve context from the previous tool output.

### 6. Final Report
**User Story:** As I user I expect to request for a final report so that the LLM will construct it to me in a way that a simple user might understand.
**Test:**
- Ask: "Generate a summary report for google.com."
- Verify the agent generates a markdown/text report summarizing findings.

## Execution Strategy
1.  **Tool Verification**: 
    - Verify `nmap` installation (likely in `C:\Program Files (x86)\Nmap`).
    - Skip `gobuster` if not installed (user cancelled).
    - Rely on Python-based adapters (`dns_lookup`, `whois`, `ssl_check`) for primary tool execution tests if binaries are missing from PATH.
2.  **Initialize**: Run `agent init` to ensure config/db are ready.
3.  **Run Chat**: Execute `agent chat` and perform the scenarios interactively.

## Notes
- `Insecure.Nmap` is the official ID for Nmap (from Insecure.Org).
- If `nmap` is not in PATH, we will attempt to use `dns_lookup` for the "Run Tool" scenario.
