from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    db_path: str = "./scan.db"
    max_depth: int = 20
    skip_dirs: list[str] = ["vendor", "node_modules", ".git", ".svn", "bower_components", "dist", "build"]
    semgrep_timeout: int = 600
    semgrep_jobs: int = 4
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "neo4j"

    class Config:
        env_prefix = "BOOYAH_"


settings = Settings()
