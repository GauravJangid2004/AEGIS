"""
AEGIS AI Engine — Multi-Model Intelligence Layer
=================================================

Provides a unified interface to multiple AI models via Ollama.
Each model is optimized for specific tasks:
  - Reasoning: Attack planning and decision making
  - Code: Exploit analysis and code review
  - Report: Professional report generation
  - Vulnerability: CVE analysis and risk assessment
"""

import json
import re
from typing import Optional, Any
from loguru import logger

try:
    import ollama
except ImportError:
    ollama = None

from aegis.config import config


# ─── System Prompts ───────────────────────────────────────────────

REASONING_PROMPT = """You are AEGIS, an autonomous penetration testing AI agent.
You have access to security tools and a terminal.
Given reconnaissance data about a target, you must:

1. Analyze what services and technologies are running
2. Identify potential vulnerabilities for each service
3. Plan an attack chain (ordered list of attacks to try)
4. Decide the next command to execute via terminal
5. Analyze each result and decide next steps
6. Chain successful attacks to escalate privileges
7. Document everything for the final report

Always explain your reasoning before each action.

{platform_info}

CRITICAL RULES:
- ONLY use tools from the AVAILABLE TOOLS list above
- NEVER invent or guess file paths — use the exact paths provided
- If a tool is not available, use Python scripts as an alternative
- Only test targets you have authorization to test
- Always explain WHY you are running each command
- If a command fails because a tool is not installed, DO NOT retry it — use a different tool or write a Python script instead
- If a command fails with empty output, the tool is likely not installed
- Track all findings for the final report
- Stop if you detect the target is a production system without authorization

Output format for each step (return ONLY valid JSON):
{
    "reasoning": "detailed explanation of why this step is needed",
    "tool": "tool name",
    "command": "exact command to run",
    "expected_result": "what I expect to find",
    "risk_level": "low|medium|high",
    "on_success": "what to do next if this works",
    "on_failure": "alternative approach if this fails"
}"""

VULNERABILITY_PROMPT = """You are a vulnerability analysis expert.
Given scan results and service information, identify:
1. Known CVEs for detected software versions
2. Common misconfigurations
3. Default credentials that might work
4. Attack vectors specific to the technology stack

For each vulnerability found, provide:
- CVE ID (if applicable)
- CVSS Score (0-10)
- Description
- Exploitation difficulty
- Impact if exploited
- Recommended remediation

Return your analysis as valid JSON array."""

CODE_ANALYSIS_PROMPT = """You are a code security analyst.
Analyze the provided code or configuration for:
1. Injection vulnerabilities (SQLi, XSS, Command Injection)
2. Authentication/Authorization flaws
3. Sensitive data exposure
4. Security misconfigurations
5. Known vulnerable dependencies

Provide findings as structured JSON."""

REPORT_PROMPT = """You are a professional penetration testing report writer.
Generate clear, detailed, and actionable security reports.
Use professional language suitable for both technical teams and management.
Include specific remediation steps with priority levels.
Map findings to compliance frameworks (OWASP Top 10, NIST, ISO 27001)."""

COMPLETION_CHECK_PROMPT = """You are evaluating whether a penetration test has reached completion.
A pentest is complete when:
1. All major services have been tested
2. Found vulnerabilities have been attempted for exploitation
3. Attack chains have been fully explored
4. No more viable attack vectors remain
5. OR the maximum iteration limit is approaching

Given the current findings and attack chain, respond with ONLY valid JSON:
{
    "is_complete": true/false,
    "reason": "why the test is or isn't complete",
    "remaining_vectors": ["list of untested vectors if not complete"],
    "confidence": 0.0-1.0
}"""

NEXT_STEPS_PROMPT = """You are AEGIS, an autonomous penetration testing AI agent.
Given the current state of a penetration test (target, findings, attack chain so far),
suggest the TOP 3 best next actions ranked by effectiveness and relevance.

{platform_info}

For each suggestion, explain WHY it is the best next step given what we know so far.
Consider:
- What services/ports are open and untested
- What vulnerabilities have been found but not exploited
- What attack chains could be extended
- What information gaps remain

CRITICAL RULES:
- ONLY suggest tools from the AVAILABLE TOOLS list above
- NEVER invent or guess file paths
- If a tool was already tried and failed because it is not installed, do NOT suggest it again
- If key tools (like nmap) are not available, use Python-based alternatives:
  * Port scanning: python -c "import socket; ..." or a Python script
  * HTTP requests: python -c "import urllib.request; ..." or curl
  * Web fingerprinting: curl with header analysis
- For Windows, use 'python' not 'python3'

Return ONLY valid JSON in this exact format:
{
    "suggestions": [
        {
            "rank": 1,
            "reasoning": "detailed explanation of why this is the best next step",
            "tool": "tool name",
            "command": "exact command to run",
            "expected_result": "what we expect to find",
            "risk_level": "low|medium|high",
            "confidence": 0.0-1.0,
            "category": "recon|exploit|enum|bruteforce|post-exploit"
        }
    ],
    "overall_assessment": "brief summary of current pentest state"
}"""


class AIEngine:
    """
    Multi-model AI engine for AEGIS.
    Routes tasks to the optimal model based on task type.
    """

    def __init__(self, custom_config: Optional[Any] = None):
        self.config = custom_config or config
        self.ollama_url = self.config.ai.ollama_base_url
        self.conversation_histories: dict[str, list] = {}
        self._available_models: Optional[list] = None

        logger.info(f"AI Engine initialized — Ollama URL: {self.ollama_url}")

    # ─── Model Selection ──────────────────────────────────────────

    def _get_model(self, task_type: str) -> str:
        """Select the optimal model for the given task type."""
        model_map = {
            "reasoning": self.config.ai.reasoning_model,
            "planning": self.config.ai.reasoning_model,
            "code": self.config.ai.code_model,
            "report": self.config.ai.report_model,
            "vulnerability": self.config.ai.vuln_model,
            "completion": self.config.ai.reasoning_model,
            "next_steps": self.config.ai.reasoning_model,
        }
        return model_map.get(task_type, self.config.ai.reasoning_model)

    def _get_temperature(self, task_type: str) -> float:
        """Get appropriate temperature for the task type."""
        temp_map = {
            "reasoning": self.config.ai.reasoning_temperature,
            "planning": self.config.ai.reasoning_temperature,
            "code": self.config.ai.code_temperature,
            "report": self.config.ai.report_temperature,
            "vulnerability": self.config.ai.reasoning_temperature,
            "completion": self.config.ai.code_temperature,
            "next_steps": self.config.ai.reasoning_temperature,
        }
        return temp_map.get(task_type, 0.3)

    def _get_system_prompt(self, task_type: str) -> str:
        """Get the system prompt for the given task type."""
        prompt_map = {
            "reasoning": REASONING_PROMPT,
            "planning": REASONING_PROMPT,
            "code": CODE_ANALYSIS_PROMPT,
            "report": REPORT_PROMPT,
            "vulnerability": VULNERABILITY_PROMPT,
            "completion": COMPLETION_CHECK_PROMPT,
            "next_steps": NEXT_STEPS_PROMPT,
        }
        return prompt_map.get(task_type, REASONING_PROMPT)

    # ─── Core Chat Methods ────────────────────────────────────────

    async def chat(
        self,
        prompt: str,
        task_type: str = "reasoning",
        session_id: Optional[str] = None,
        system_prompt_override: Optional[str] = None,
    ) -> str:
        """
        Send a prompt to the appropriate AI model and get a response.

        Args:
            prompt: The user/agent prompt
            task_type: One of 'reasoning', 'code', 'report', 'vulnerability', 'completion'
            session_id: Optional session ID for conversation continuity
            system_prompt_override: Optional override for the system prompt

        Returns:
            The AI model's response text
        """
        model = self._get_model(task_type)
        temperature = self._get_temperature(task_type)
        system_prompt = system_prompt_override or self._get_system_prompt(task_type)

        # Build messages
        messages = [{"role": "system", "content": system_prompt}]

        # Add conversation history if session exists
        if session_id and session_id in self.conversation_histories:
            messages.extend(self.conversation_histories[session_id])

        messages.append({"role": "user", "content": prompt})

        logger.debug(f"AI Chat — model={model}, task={task_type}, temp={temperature}")

        try:
            if ollama is None:
                raise ImportError("ollama package not installed")

            response = ollama.chat(
                model=model,
                messages=messages,
                options={"temperature": temperature},
            )
            reply = response["message"]["content"]

            # Store in conversation history
            if session_id:
                if session_id not in self.conversation_histories:
                    self.conversation_histories[session_id] = []
                self.conversation_histories[session_id].append(
                    {"role": "user", "content": prompt}
                )
                self.conversation_histories[session_id].append(
                    {"role": "assistant", "content": reply}
                )

            return reply

        except Exception as e:
            logger.error(f"AI Engine error: {e}")
            raise AIEngineError(f"Failed to get AI response: {e}") from e

    async def chat_json(
        self,
        prompt: str,
        task_type: str = "reasoning",
        session_id: Optional[str] = None,
        system_prompt_override: Optional[str] = None,
    ) -> dict:
        """
        Chat with the AI and parse the response as JSON.
        Handles cases where the AI wraps JSON in markdown code blocks.
        """
        raw_response = await self.chat(
            prompt, task_type, session_id,
            system_prompt_override=system_prompt_override,
        )
        return self._extract_json(raw_response)

    # ─── Specialized Methods ──────────────────────────────────────

    async def decide_next_action(
        self,
        target: str,
        findings: list[dict],
        attack_chain: list[dict],
        session_id: str = "pentest_main",
        available_tools_info: str = "",
    ) -> dict:
        """
        AI decides the next attack step based on current findings.

        Returns a dict with: reasoning, tool, command, expected_result,
                             risk_level, on_success, on_failure
        """
        # Inject platform/tool info into the system prompt
        system_prompt = REASONING_PROMPT.replace("{platform_info}", available_tools_info)

        context = f"""
TARGET: {target}

CURRENT FINDINGS:
{json.dumps(findings[-5:], indent=2, default=str)}

ATTACK CHAIN SO FAR ({len(attack_chain)} steps):
{json.dumps(attack_chain[-3:], indent=2, default=str)}

Based on the above, what is your next attack step?
Return ONLY valid JSON with the required fields."""

        return await self.chat_json(
            context, "reasoning", session_id,
            system_prompt_override=system_prompt,
        )

    async def analyze_vulnerabilities(
        self,
        scan_results: str,
        services: list[dict],
    ) -> list[dict]:
        """Analyze scan results for vulnerabilities."""
        prompt = f"""
Analyze these scan results for vulnerabilities:

SCAN OUTPUT:
{scan_results[:3000]}

DETECTED SERVICES:
{json.dumps(services, indent=2)}

Return a JSON array of vulnerabilities found."""

        result = await self.chat_json(prompt, "vulnerability")
        if isinstance(result, list):
            return result
        return result.get("vulnerabilities", [result])

    async def analyze_code(self, code: str, language: str = "unknown") -> dict:
        """Analyze code for security vulnerabilities."""
        prompt = f"""
Analyze this {language} code for security vulnerabilities:

```{language}
{code[:4000]}
```

Return JSON with findings."""

        return await self.chat_json(prompt, "code")

    async def check_completion(
        self,
        findings: list[dict],
        attack_chain: list[dict],
        iteration: int,
        max_iterations: int,
    ) -> dict:
        """Check if the penetration test has reached completion."""
        prompt = f"""
Current iteration: {iteration}/{max_iterations}
Total findings: {len(findings)}
Attack chain length: {len(attack_chain)}

Key findings summary:
{json.dumps(findings[-5:], indent=2, default=str)}

Is this penetration test complete?"""

        return await self.chat_json(prompt, "completion")

    async def suggest_next_steps(
        self,
        target: str,
        findings: list[dict],
        attack_chain: list[dict],
        session_id: str = "pentest_main",
        available_tools_info: str = "",
    ) -> dict:
        """
        AI suggests ranked next steps based on current pentest state.

        Returns a dict with 'suggestions' (list of ranked options)
        and 'overall_assessment' (string summary of current state).
        """
        # Inject platform/tool info into the system prompt
        system_prompt = NEXT_STEPS_PROMPT.replace("{platform_info}", available_tools_info)

        # Build list of failed tools from the attack chain so the AI avoids them
        failed_tools = set()
        for step in findings:
            if step.get("status") == "failed":
                err = step.get("actual_result", "") or ""
                if "not installed" in err.lower() or "not found" in err.lower():
                    failed_tools.add(step.get("tool", ""))

        failed_tools_str = ""
        if failed_tools:
            failed_tools_str = f"\n\nTOOLS THAT FAILED (not installed — do NOT suggest again): {', '.join(failed_tools)}"

        context = f"""
TARGET: {target}

CURRENT FINDINGS ({len(findings)} total):
{json.dumps(findings[-5:], indent=2, default=str)}

ATTACK CHAIN SO FAR ({len(attack_chain)} steps):
{json.dumps(attack_chain[-3:], indent=2, default=str)}{failed_tools_str}

Based on the current state, suggest the TOP 3 best next actions.
Rank them by effectiveness. Return ONLY valid JSON."""

        result = await self.chat_json(
            context, "next_steps", session_id,
            system_prompt_override=system_prompt,
        )

        # Normalize: ensure we always return a suggestions list
        if isinstance(result, list):
            return {"suggestions": result, "overall_assessment": ""}
        if "suggestions" not in result:
            # AI returned a single action instead of ranked list
            return {"suggestions": [result], "overall_assessment": ""}
        return result

    async def write_report_section(
        self,
        section_type: str,
        pentest_data: dict,
    ) -> str:
        """Generate a specific section of the pentest report."""
        section_prompts = {
            "executive_summary": (
                "Write an executive summary for non-technical management. "
                "Keep it concise, highlight the most critical findings, "
                "and provide an overall risk rating."
            ),
            "technical_findings": (
                "Write detailed technical findings with CVSS scores, "
                "evidence, and step-by-step reproduction instructions."
            ),
            "attack_narrative": (
                "Write a compelling attack chain narrative showing how "
                "vulnerabilities were chained together. Tell the story "
                "of the attack from start to finish."
            ),
            "remediation": (
                "Write prioritized remediation recommendations. "
                "Separate into quick wins (< 1 day), short-term (1-2 weeks), "
                "and long-term (1-3 months) fixes."
            ),
            "compliance_mapping": (
                "Map findings to OWASP Top 10, NIST CSF, and ISO 27001 controls."
            ),
        }

        prompt = f"""{section_prompts.get(section_type, section_type)}

PENTEST DATA:
Target: {pentest_data.get('target', 'N/A')}
Findings: {json.dumps(pentest_data.get('findings', [])[:10], indent=2, default=str)}
Attack Chain: {json.dumps(pentest_data.get('attack_chain', [])[:10], indent=2, default=str)}
"""

        return await self.chat(prompt, "report")

    # ─── Utility Methods ──────────────────────────────────────────

    def _extract_json(self, text: str) -> dict | list:
        """Extract JSON from AI response, handling markdown code blocks."""
        # Try direct parse first
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting from markdown code blocks
        json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Try finding JSON object/array in text
        for pattern in [r"\{.*\}", r"\[.*\]"]:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    continue

        logger.warning(f"Could not parse JSON from AI response: {text[:200]}...")
        return {"raw_response": text, "parse_error": True}

    async def list_available_models(self) -> list[str]:
        """List all models available in Ollama."""
        try:
            if ollama is None:
                return []
            models = ollama.list()
            self._available_models = [m["name"] for m in models.get("models", [])]
            return self._available_models
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            return []

    def clear_session(self, session_id: str):
        """Clear conversation history for a session."""
        if session_id in self.conversation_histories:
            del self.conversation_histories[session_id]
            logger.debug(f"Cleared session: {session_id}")


class AIEngineError(Exception):
    """Custom exception for AI Engine errors."""
    pass
