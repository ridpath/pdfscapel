"""Solve module - CTF challenge solving tools with ethical enforcement"""

from .ctf_mode import (
    CTFModeContext,
    CTFModeError,
    ctf_mode,
    validate_ctf_mode,
    generate_provenance_file,
    verify_provenance_file,
)

from .flag_hunter import (
    FlagHunter,
    FlagCandidate,
    FlagLocation,
    FlagEncoding,
)

from .stego_solver import (
    StegoSolver,
    StegoFinding,
    StegoTechnique,
    DetectionDifficulty,
    solve_steganography,
)

from .auto_solver import (
    AutoSolver,
    AutoSolverReport,
    SolverStage,
    SolverStageResult,
    solve_auto,
)

from .repair import (
    PDFRepairAnalyzer,
    RepairResult,
    DamageAssessment,
    DamageReport,
    DamageType,
    RepairSeverity,
)

__all__ = [
    'CTFModeContext',
    'CTFModeError',
    'ctf_mode',
    'validate_ctf_mode',
    'generate_provenance_file',
    'verify_provenance_file',
    'FlagHunter',
    'FlagCandidate',
    'FlagLocation',
    'FlagEncoding',
    'StegoSolver',
    'StegoFinding',
    'StegoTechnique',
    'DetectionDifficulty',
    'solve_steganography',
    'AutoSolver',
    'AutoSolverReport',
    'SolverStage',
    'SolverStageResult',
    'solve_auto',
    'PDFRepairAnalyzer',
    'RepairResult',
    'DamageAssessment',
    'DamageReport',
    'DamageType',
    'RepairSeverity',
]
