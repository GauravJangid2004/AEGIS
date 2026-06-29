"""
AEGIS Configuration Management
Loads settings from .env file and provides typed configuration objects.
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from dotenv import load_dotenv

# Load .env from project root
PROJECT_ROOT = Path(__file__).parent.parent
load_dotenv(PROJECT_ROOT / ".env")


class AIModelConfig(BaseSettings):
    """Configuration for AI model selection and parameters."""

    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for Ollama API"
    )
    reasoning_model: str = Field(
        default="llama3",
        description="Model for reasoning and attack planning"
    )
    code_model: str = Field(
        default="deepseek-coder",
        description="Model for code analysis tasks"
    )
    report_model: str = Field(
        default="mistral",
        description="Model for report generation"
    )
    vuln_model: str = Field(
        default="llama3",
        description="Model for vulnerability analysis"
    )
    reasoning_temperature: float = Field(default=0.3)
    code_temperature: float = Field(default=0.1)
    report_temperature: float = Field(default=0.5)

    model_config = SettingsConfigDict(env_prefix="DEFAULT_")


class ExecutionConfig(BaseSettings):
    """Configuration for command execution safety."""

    max_attack_iterations: int = Field(
        default=20,
        description="Maximum number of AI-driven attack iterations"
    )
    command_timeout: int = Field(
        default=120,
        description="Timeout in seconds for each command"
    )
    max_output_length: int = Field(
        default=5000,
        description="Maximum characters to capture from command output"
    )
    safe_mode: bool = Field(
        default=True,
        description="When True, requires confirmation before destructive commands"
    )


class APIKeysConfig(BaseSettings):
    """External API keys for enrichment services."""

    shodan_api_key: Optional[str] = Field(default=None)
    virustotal_api_key: Optional[str] = Field(default=None)
    censys_api_id: Optional[str] = Field(default=None)
    censys_api_secret: Optional[str] = Field(default=None)
    nvd_api_key: Optional[str] = Field(default=None)


class ReportConfig(BaseSettings):
    """Configuration for report generation."""

    output_dir: str = Field(default="./reports")
    company_name: str = Field(default="AEGIS Security")
    classification: str = Field(default="CONFIDENTIAL")

    model_config = SettingsConfigDict(env_prefix="REPORT_")


class WebUIConfig(BaseSettings):
    """Configuration for the web interface."""

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    secret_key: str = Field(default="change-this-to-a-random-secret-key")
    cors_origins: str = Field(default="http://localhost:3000,http://localhost:5173")

    model_config = SettingsConfigDict(env_prefix="API_")


class AegisConfig:
    """Master configuration class aggregating all config sections."""

    def __init__(self):
        self.ai = AIModelConfig()
        self.execution = ExecutionConfig()
        self.api_keys = APIKeysConfig()
        self.report = ReportConfig()
        self.web_ui = WebUIConfig()
        self.project_root = PROJECT_ROOT
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_file = os.getenv("LOG_FILE", "./logs/aegis.log")
        self.chromadb_dir = os.getenv("CHROMADB_PERSIST_DIR", "./data/chromadb")
        self.cve_db_path = os.getenv("CVE_DATABASE_PATH", "./data/cve_database.json")

    def __repr__(self):
        return (
            f"AegisConfig(\n"
            f"  ai_reasoning={self.ai.reasoning_model},\n"
            f"  ai_code={self.ai.code_model},\n"
            f"  ai_report={self.ai.report_model},\n"
            f"  safe_mode={self.execution.safe_mode},\n"
            f"  max_iterations={self.execution.max_attack_iterations}\n"
            f")"
        )


# Global configuration singleton
config = AegisConfig()
