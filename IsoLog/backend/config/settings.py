"""
IsoLog Configuration Module

Handles loading and validation of application configuration.
"""

from pathlib import Path
from typing import Optional, List
from functools import lru_cache

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class ServerConfig(BaseModel):
    """Server configuration settings."""
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    workers: int = 4


class DatabaseConfig(BaseModel):
    """Database configuration settings."""
    path: str = "data/isolog.db"
    echo: bool = False


class SearchConfig(BaseModel):
    """Search index configuration."""
    index_path: str = "data/search_index"


class SyslogConfig(BaseModel):
    """Syslog ingestion configuration."""
    enabled: bool = True
    udp_port: int = 514
    tcp_port: int = 514


class FileWatcherConfig(BaseModel):
    """File watcher configuration."""
    enabled: bool = True
    watch_paths: List[str] = Field(default_factory=lambda: ["data/logs"])
    patterns: List[str] = Field(default_factory=lambda: ["*.log", "*.txt", "*.json"])


class UsbImportConfig(BaseModel):
    """USB import configuration."""
    enabled: bool = True
    mount_paths: List[str] = Field(default_factory=list)


class IngestionConfig(BaseModel):
    """Ingestion module configuration."""
    syslog: SyslogConfig = Field(default_factory=SyslogConfig)
    file_watcher: FileWatcherConfig = Field(default_factory=FileWatcherConfig)
    usb_import: UsbImportConfig = Field(default_factory=UsbImportConfig)


class ParserConfig(BaseModel):
    """Parser configuration."""
    default_timezone: str = "UTC"
    max_line_length: int = 65536


class SigmaConfig(BaseModel):
    """Sigma detection configuration."""
    enabled: bool = True
    rules_path: str = "rules/sigma_rules"


class MitreConfig(BaseModel):
    """MITRE ATT&CK configuration."""
    enabled: bool = True
    attack_json_path: str = "rules/mitre_mapping/attack.json"


class AnomalyConfig(BaseModel):
    """ML anomaly detection configuration."""
    enabled: bool = True
    models_path: str = "models"
    threshold: float = 0.85


class ScoringConfig(BaseModel):
    """Threat scoring weights."""
    sigma_weight: float = 0.4
    mitre_weight: float = 0.2
    ml_weight: float = 0.3
    heuristic_weight: float = 0.1


class DetectionConfig(BaseModel):
    """Detection engine configuration."""
    sigma: SigmaConfig = Field(default_factory=SigmaConfig)
    mitre: MitreConfig = Field(default_factory=MitreConfig)
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)


class MLConfig(BaseModel):
    """Machine learning configuration."""
    initial_training_days: int = 7
    retrain_interval_hours: int = 24
    min_events_for_training: int = 1000


class BlockchainConfig(BaseModel):
    """Blockchain/ledger configuration."""
    enabled: bool = True
    batch_size: int = 1000
    batch_interval_seconds: int = 300
    ledger_path: str = "data/blockchain.db"


class ReportingConfig(BaseModel):
    """Reporting configuration."""
    output_path: str = "data/reports"
    templates_path: str = "backend/reporting/templates"


class AuthConfig(BaseModel):
    """Authentication configuration."""
    enabled: bool = False
    jwt_secret: str = "change-this-in-production"
    token_expiry_hours: int = 24


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = "INFO"
    file_path: str = "logs/isolog.log"
    max_size_mb: int = 100
    backup_count: int = 5


class UpdatesConfig(BaseModel):
    """Offline update configuration."""
    public_key: str = ""
    auto_apply: bool = False


class Settings(BaseSettings):
    """
    Main application settings.
    
    Loads configuration from config.yml file, with environment variable overrides.
    """
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    search: SearchConfig = Field(default_factory=SearchConfig)
    ingestion: IngestionConfig = Field(default_factory=IngestionConfig)
    parsers: ParserConfig = Field(default_factory=ParserConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    blockchain: BlockchainConfig = Field(default_factory=BlockchainConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    updates: UpdatesConfig = Field(default_factory=UpdatesConfig)
    
    # Base path for relative paths
    base_path: Path = Field(default_factory=lambda: Path.cwd())
    
    class Config:
        env_prefix = "ISOLOG_"
        env_nested_delimiter = "__"

    def resolve_path(self, path: str) -> Path:
        """Resolve a relative path against the base path."""
        p = Path(path)
        if p.is_absolute():
            return p
        return self.base_path / p


def load_config(config_path: Optional[str] = None) -> Settings:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to config file. Defaults to 'config.yml' in current directory.
        
    Returns:
        Settings object with loaded configuration.
    """
    if config_path is None:
        config_path = "config.yml"
    
    config_file = Path(config_path)
    
    if config_file.exists():
        with open(config_file, "r") as f:
            config_data = yaml.safe_load(f) or {}
    else:
        config_data = {}
    
    # Set base path to config file's parent directory
    config_data["base_path"] = config_file.parent.resolve()
    
    return Settings(**config_data)


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    This is the primary way to access settings throughout the application.
    """
    return load_config()


# Convenience function for dependency injection
def get_config() -> Settings:
    """Alias for get_settings for use with FastAPI Depends."""
    return get_settings()
