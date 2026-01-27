from pdfscalpel.generate.challenges import (
    generate_challenge,
    ChallengeGenerator,
    ChallengeType,
    Difficulty,
    SolutionMetadata,
    HintConfig,
)
from pdfscalpel.generate.corrupted import (
    generate_corrupted_pdf,
    BrokenPDFGenerator,
    CorruptionType,
    CorruptionDifficulty,
    CorruptionMetadata,
    RecoveryHint,
)
from pdfscalpel.generate.polyglot import (
    generate_pdf_zip_polyglot,
    generate_pdf_html_polyglot,
    PolyglotGenerator,
    PolyglotValidation,
)
from pdfscalpel.generate.steganography import (
    embed_whitespace_stego,
    embed_metadata_stego,
    embed_invisible_text,
    embed_lsb_image_stego,
    SteganographyGenerator,
    StegoEmbedResult,
)
from pdfscalpel.generate.watermark import (
    create_watermarked_pdf,
    create_watermark_samples,
    WatermarkGenerator,
    WatermarkConfig,
    WatermarkStyle,
)

__all__ = [
    'generate_challenge',
    'ChallengeGenerator',
    'ChallengeType',
    'Difficulty',
    'SolutionMetadata',
    'HintConfig',
    'generate_corrupted_pdf',
    'BrokenPDFGenerator',
    'CorruptionType',
    'CorruptionDifficulty',
    'CorruptionMetadata',
    'RecoveryHint',
    'generate_pdf_zip_polyglot',
    'generate_pdf_html_polyglot',
    'PolyglotGenerator',
    'PolyglotValidation',
    'embed_whitespace_stego',
    'embed_metadata_stego',
    'embed_invisible_text',
    'embed_lsb_image_stego',
    'SteganographyGenerator',
    'StegoEmbedResult',
    'create_watermarked_pdf',
    'create_watermark_samples',
    'WatermarkGenerator',
    'WatermarkConfig',
    'WatermarkStyle',
]
