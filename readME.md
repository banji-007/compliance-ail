# 🛡️ Agentic Integrity Ledger (AIL) - Proof of Concept

AIL is a zero-trust compliance middleware for autonomous AI agents. 

As AI agents transition from conversational chatbots to autonomous entities executing financial, infrastructure, and legal commands, enterprises face a massive liability bottleneck. AIL solves this by providing a cryptographic audit trail and pre-execution policy enforcement required for SOC2, GDPR, and the EU AI Act.

## 🚀 The Value Proposition

* **⚡ Framework Agnostic Interception:** AIL operates as an independent middleware layer. It intercepts structured `tool_calls` from any major agent framework (LangGraph, AutoGen, smolagents) *before* execution, requiring zero modifications to the underlying LLM logic.
* **⚖️ Deterministic Policy Enforcement:** Bypasses LLM hallucinations by routing all intents through Open Policy Agent (OPA). Legal and security teams can define hardcoded, deterministic Rego policies (e.g., spending limits, data residency) that actively block unauthorized agent actions. *(See [Policy Engine Documentation](/README_OPA.md) for details).*
* **🔒 Cryptographic Proof of Intent:** Every intercepted action—both approved and denied—is logged to an ImmuDB cryptographic ledger using Merkle-tree immutability. This provides enterprise auditors with an unalterable history of what the agent *intended* to do, the policy's decision, and final execution state.

## 🛠️ Architecture

1. **The Agent Layer:** A LangGraph agent equipped with execution tools.
2. **The Interceptor (Middleware):** Catches the LLM's JSON payload before the tool executes.
3. **The Policy Engine:** An Open Policy Agent (OPA) Docker container evaluating the payload against strict `Rego` rules.
4. **The Ledger:** An ImmuDB cryptographic ledger recording "Proof of Intent."

---

## 💻 Quickstart & Setup

### Prerequisites
* Python 3.10+
* Docker Desktop (for running OPA and ImmuDB)
* OpenAI API Key

### 1. Installation
Clone the repository and install required dependencies:
```bash
git clone [https://github.com/banji-007/compliance-ail.git](https://github.com/banji-007/compliance-ail.git)
cd compliance-ail
python -m venv venv

# Activate venv (Windows)
.\venv\Scripts\activate
# Activate venv (Mac/Linux)
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Environment Configuration
Copy the environment template and configure your credentials:
```bash
cp .env.example .env
# Edit .env with your actual values:
# OPENAI_API_KEY=your_openai_api_key_here
# IMMUDB_USER=immudb
# IMMUDB_PASSWORD=immudb
```

**Note:** The ImmuDB ledger includes development fallback credentials for local testing only. Production environments must inject strict environment variables.

### 3. Start the Policy Engine (OPA)
Spin up the Open Policy Agent container via Docker:
```bash
docker-compose up -d
```

### 3. Load the Compliance Policies
Upload the deterministic Rego policies to the running OPA container. 
*(Note: If you are on Windows PowerShell, use `curl.exe`. On Mac/Linux, standard `curl` works).*

```bash
curl.exe -X PUT -H "Content-Type: text/plain" --data-binary @policy/cloud_policy.rego http://localhost:8181/v1/policies/cloud_policy
```
*A successful upload will return an empty JSON object: `{}`*

---

## 🎬 Running the Demo: "The Rogue FinOps Agent"

This demo showcases a LangGraph AI agent acting as a cloud infrastructure assistant. We will test it against two scenarios.

Start the demo script:
```bash
python framework_integration/langgraph_demo.py
```

### Scenario A: The Compliant Path
Ask the agent to perform an action that is within budget and policy limits. 

**Prompt:**
> *"Deploy a small test server in us-east-1 for $1.50 an hour. Tag the environment as 'dev' and the project as 'testing'."*

**Expected Result:** The AIL intercepts the call, OPA approves it, the hash is logged, and the dummy server executes.

### Scenario B: The Disaster Path (Compliance Coach)
Force the agent to attempt a highly restricted action that violates Data Residency (PCI-DSS), FinOps tagging limits, and compute restrictions simultaneously.

**Prompt:**
> *"Deploy a p4d.24xlarge instance in us-east-1 for $32/hr. Tag it for the 'prod' environment, but don't add a cost center. Also tag the data classification as 'pci-dss'."*

**Expected Result:** 
1. The agent blindly generates the malformed payload.
2. The AIL middleware intercepts it mid-air.
3. OPA denies the request and returns the specific legal violations.
4. The ledger cryptographically seals the blocked intent.
5. The LLM reads the deterministic errors and actively coaches the user on how to fix their request.


---

## 🔍 Verifying the Cryptographic Audit Trail

To prove to auditors that the system is immutable, view the ImmuDB cryptographic ledger:
```bash
python verify_hash_chain.py
```

This will verify the ImmuDB connection and confirm Merkle-tree immutability guarantees.
