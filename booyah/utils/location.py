from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SourceLocation:
    file_path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def __str__(self) -> str:
        return f"{self.file_path}:{self.start_line}:{self.start_col}"
