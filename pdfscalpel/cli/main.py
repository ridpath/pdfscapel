"""Main CLI entry point using Click"""

import sys
import json
from pathlib import Path
from typing import Optional, Dict, Any

import click

from pdfscalpel import __version__
from pdfscalpel.core.logging import setup_logger, get_logger
from pdfscalpel.core.config import load_config, get_config
from pdfscalpel.core.dependencies import check_all_dependencies, print_missing_dependencies
from pdfscalpel.core.exceptions import PDFScalpelError
from pdfscalpel.cli.ui import (
    print_error,
    print_success,
    print_info,
    print_header,
    print_warning,
    print_analysis_result,
    print_verbose,
    print_debug,
    print_suggestion,
    ProgressTracker,
)
from pdfscalpel.cli.decorators import handle_errors, with_timing, log_command
from pdfscalpel.analyze.structure import analyze_structure, check_compliance
from pdfscalpel.analyze.metadata import analyze_metadata
from pdfscalpel.analyze.encryption import analyze_encryption
from pdfscalpel.analyze.watermark import analyze_watermark
from pdfscalpel.analyze.intelligence import analyze_intelligence, analyze_rendering_differences
from pdfscalpel.analyze.graph import analyze_object_graph, analyze_entropy, PDFObjectGraphGenerator, PDFEntropyAnalyzer
from pdfscalpel.analyze.malware import PDFMalwareAnalyzer
from pdfscalpel.analyze.signatures import PDFSignatureAnalyzer
from pdfscalpel.analyze.form_security import PDFFormSecurityAnalyzer
from pdfscalpel.analyze.anti_forensics import PDFAntiForensicsDetector
from pdfscalpel.analyze.advanced_stego import PDFAdvancedStegoDetector
from pdfscalpel.solve.repair import PDFRepairAnalyzer
from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.extract import (
    extract_text,
    extract_images,
    list_objects,
    dump_object,
    dump_objects_by_type,
    extract_streams,
    extract_javascript,
    extract_attachments,
    extract_hidden_data,
    extract_forms,
    extract_revisions,
    RevisionExtractor,
)
from pdfscalpel.generate import (
    generate_challenge,
    ChallengeType,
    Difficulty,
    generate_corrupted_pdf,
    CorruptionType,
    CorruptionDifficulty,
    generate_pdf_zip_polyglot,
    generate_pdf_html_polyglot,
    embed_whitespace_stego,
    embed_metadata_stego,
    embed_invisible_text,
    embed_lsb_image_stego,
    create_watermarked_pdf,
    create_watermark_samples,
    WatermarkStyle,
)


@click.group()
@click.version_option(version=__version__, prog_name="pdfscalpel")
@click.option('--config', type=click.Path(exists=True, path_type=Path), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--debug', '-d', is_flag=True, help='Debug output')
@click.pass_context
def cli(ctx, config: Optional[Path], verbose: bool, debug: bool):
    """
    PDFScalpel - Forensic-grade PDF analysis and CTF toolkit
    
    A professional tool for PDF analysis, forensics, and CTF challenges.
    """
    ctx.ensure_object(dict)
    
    setup_logger(verbose=verbose, debug=debug)
    
    if config:
        load_config(config)
    else:
        load_config()
    
    cfg = get_config()
    cfg.verbose = verbose or cfg.verbose
    cfg.debug = debug or cfg.debug
    
    ctx.obj['config'] = cfg
    ctx.obj['logger'] = get_logger()


@cli.command()
@click.option('--verbose', '-v', is_flag=True, help='Show detailed information')
def check_deps(verbose: bool):
    """Check all dependencies and show installation instructions"""
    results = check_all_dependencies(verbose=verbose)
    
    all_ok = print_missing_dependencies(results)
    
    if all_ok:
        click.echo("\nAll required dependencies are installed!")
        sys.exit(0)
    else:
        sys.exit(1)


@cli.group()
def analyze():
    """
    Analyze PDF files (non-destructive)
    
    Examine PDF structure, metadata, encryption, watermarks, and more without
    modifying the original file. Use intelligence layer for actionable insights.
    
    Examples:
        pdfscalpel analyze structure input.pdf
        pdfscalpel analyze encryption input.pdf --check-exploits
        pdfscalpel analyze watermark input.pdf --verbose
        pdfscalpel analyze intelligence input.pdf --report report.json
    """
    pass


@cli.group()
def extract():
    """
    Extract data from PDF files
    
    Recover text, images, JavaScript, attachments, hidden data, forms, and more.
    Non-destructive operations that export content from PDFs.
    
    Examples:
        pdfscalpel extract text input.pdf --output text.txt
        pdfscalpel extract images input.pdf --output-dir images/
        pdfscalpel extract javascript input.pdf --beautify
        pdfscalpel extract revisions input.pdf --output-dir revisions/
    """
    pass


@cli.group()
def mutate():
    """
    Modify PDF files
    
    Add/remove watermarks, encrypt/decrypt, merge/split, redact, optimize, and more.
    Always creates new output file - never modifies original.
    
    Examples:
        pdfscalpel mutate watermark input.pdf output.pdf --remove crop
        pdfscalpel mutate encrypt input.pdf output.pdf --password secret
        pdfscalpel mutate merge file1.pdf file2.pdf output.pdf
        pdfscalpel mutate redact input.pdf output.pdf --pattern "\\d{3}-\\d{2}-\\d{4}"
    """
    pass


@cli.group()
def generate():
    """
    Generate new PDFs and challenges
    
    Create CTF challenges, corrupted PDFs, polyglots, steganography samples,
    and watermarked documents for testing and education.
    
    Examples:
        pdfscalpel generate challenge output.pdf --flag "CTF{test}" --type password
        pdfscalpel generate corrupted output.pdf --type xref_corrupt --difficulty medium
        pdfscalpel generate polyglot output.pdf --formats pdf,zip
        pdfscalpel generate watermark output.pdf --text "SAMPLE" --style diagonal
    """
    pass


@generate.command('challenge')
@click.argument('output', type=click.Path(path_type=Path))
@click.option('--flag', '-f', required=True, help='Flag to hide in the challenge')
@click.option('--type', '-t', 'challenge_type',
              type=click.Choice([t.value for t in ChallengeType]),
              default='password',
              help='Challenge type')
@click.option('--difficulty', '-d',
              type=click.Choice([d.value for d in Difficulty]),
              default='easy',
              help='Difficulty level')
@click.option('--no-solution', is_flag=True, help='Do not save solution metadata')
@click.option('--watermark-text', help='Custom watermark text (for watermark challenges)')
@click.option('--stego-type', help='Steganography type (for stego challenges)')
def generate_challenge_cmd(
    output: Path,
    flag: str,
    challenge_type: str,
    difficulty: str,
    no_solution: bool,
    watermark_text: Optional[str],
    stego_type: Optional[str]
):
    """
    Generate a CTF challenge PDF
    
    Creates various types of PDF-based CTF challenges with configurable difficulty.
    Automatically generates solution metadata for validation.
    
    Examples:
        pdfscalpel generate challenge challenge.pdf --flag "CTF{test123}" --type password --difficulty easy
        pdfscalpel generate challenge stego.pdf --flag "FLAG{hidden}" --type steganography --difficulty medium
        pdfscalpel generate challenge watermark.pdf --flag "CTF{clean}" --type watermark --watermark-text "CONFIDENTIAL"
    """
    try:
        print_header("Challenge Generator", str(output))
        
        kwargs = {}
        if watermark_text:
            kwargs['watermark_text'] = watermark_text
        if stego_type:
            kwargs['stego_type'] = stego_type
        
        solution = generate_challenge(
            output_path=output,
            flag=flag,
            challenge_type=challenge_type,
            difficulty=difficulty,
            save_solution=not no_solution,
            **kwargs
        )
        
        print_success(f"Challenge created: {output}")
        
        if not no_solution:
            solution_path = output.with_suffix('.solution.json')
            print_info(f"Solution metadata: {solution_path}")
        
        print("\nChallenge Details:")
        print(f"  Type: {solution.challenge_type}")
        print(f"  Difficulty: {solution.difficulty}")
        print(f"  Estimated Time: {solution.estimated_time_minutes} minutes")
        
        if solution.password:
            print(f"  Password: {solution.password}")
        
        if solution.hints:
            print(f"\n  Hints ({len(solution.hints)}):")
            for i, hint in enumerate(solution.hints, 1):
                print(f"    {i}. {hint}")
        
        print(f"\n  Techniques Required:")
        for tech in solution.techniques_required:
            print(f"    - {tech}")
        
        print(f"\n  Suggested Tools:")
        for tool in solution.tools_suggested:
            print(f"    - {tool}")
        
    except PDFScalpelError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@generate.command('corrupted')
@click.argument('output', type=click.Path(path_type=Path))
@click.option('--type', '-t', 'corruption_type',
              type=click.Choice([t.value for t in CorruptionType]),
              default='xref_offset',
              help='Type of corruption to apply')
@click.option('--difficulty', '-d',
              type=click.Choice([d.value for d in CorruptionDifficulty]),
              default='medium',
              help='Recovery difficulty level')
@click.option('--content', '-c', help='Custom content for the PDF')
@click.option('--no-hints', is_flag=True, help='Do not include recovery hints')
@click.option('--save-metadata', type=click.Path(path_type=Path), help='Save corruption metadata to file')
def generate_corrupted_cmd(
    output: Path,
    corruption_type: str,
    difficulty: str,
    content: Optional[str],
    no_hints: bool,
    save_metadata: Optional[Path]
):
    """
    Generate intentionally corrupted PDF for recovery challenges
    
    Creates PDFs with various types of corruption for testing PDF recovery
    tools, creating repair challenges, or teaching PDF structure.
    
    Examples:
        pdfscalpel generate corrupted broken.pdf --type xref_offset --difficulty easy
        pdfscalpel generate corrupted challenge.pdf --type mixed --difficulty expert
        pdfscalpel generate corrupted test.pdf --type truncated_stream --difficulty medium --save-metadata metadata.json
    """
    try:
        print_header("Corrupted PDF Generator", str(output))
        
        metadata = generate_corrupted_pdf(
            output_path=output,
            corruption_type=corruption_type,
            difficulty=difficulty,
            content=content,
            include_hints=not no_hints
        )
        
        print_success(f"Corrupted PDF created: {output}")
        
        print("\nCorruption Details:")
        print(f"  Type: {metadata['corruption_type']}")
        print(f"  Difficulty: {metadata['difficulty']}")
        
        if metadata.get('corruption_offset'):
            print(f"  Offset: {metadata['corruption_offset']}")
        
        if metadata.get('original_value'):
            print(f"  Original Value: {metadata['original_value']}")
        
        if metadata.get('corrupted_value'):
            print(f"  Corrupted Value: {metadata['corrupted_value']}")
        
        if metadata.get('hints') and not no_hints:
            print(f"\nRecovery Hints ({len(metadata['hints'])}):")
            for i, hint in enumerate(metadata['hints'], 1):
                print(f"\n  Hint {i} (Difficulty: {hint['difficulty']}):")
                print(f"    {hint['hint']}")
                if hint.get('tool'):
                    print(f"    Tool: {hint['tool']}")
                if hint.get('approach'):
                    print(f"    Approach: {hint['approach']}")
        
        if save_metadata:
            import json
            with open(save_metadata, 'w') as f:
                json.dump(metadata, f, indent=2)
            print_info(f"\nMetadata saved to: {save_metadata}")
        
    except PDFScalpelError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@generate.command('polyglot')
@click.argument('output', type=click.Path(path_type=Path))
@click.option('--type', '-t', 'polyglot_type',
              type=click.Choice(['pdf-zip', 'pdf-html']),
              default='pdf-zip',
              help='Polyglot type')
@click.option('--pdf-content', help='Custom PDF content text')
@click.option('--html-content', help='Custom HTML content (for pdf-html)')
@click.option('--method', '-m',
              type=click.Choice(['append', 'prepend']),
              default='append',
              help='Method for pdf-zip polyglots')
def generate_polyglot_cmd(
    output: Path,
    polyglot_type: str,
    pdf_content: Optional[str],
    html_content: Optional[str],
    method: str
):
    """
    Generate polyglot files (valid in multiple formats)
    
    Creates files that are valid PDFs and another format simultaneously.
    Useful for CTF challenges, format confusion testing, and parser analysis.
    
    Examples:
        pdfscalpel generate polyglot output.pdf --type pdf-zip
        pdfscalpel generate polyglot hybrid.pdf --type pdf-html --pdf-content "Secret PDF" --html-content "<h1>Secret HTML</h1>"
        pdfscalpel generate polyglot test.pdf --type pdf-zip --method prepend
    """
    try:
        print_header("Polyglot Generator", str(output))
        
        if polyglot_type == 'pdf-zip':
            validation = generate_pdf_zip_polyglot(
                output_path=output,
                pdf_content=pdf_content,
                method=method
            )
            print_success(f"PDF+ZIP polyglot created: {output}")
            print(f"\n  PDF Valid: {validation.is_valid_pdf}")
            print(f"  ZIP Valid: {validation.is_valid_secondary}")
            
        elif polyglot_type == 'pdf-html':
            validation = generate_pdf_html_polyglot(
                output_path=output,
                pdf_content=pdf_content,
                html_content=html_content
            )
            print_success(f"PDF+HTML polyglot created: {output}")
            print(f"\n  PDF Valid: {validation.is_valid_pdf}")
            print(f"  HTML Present: {validation.is_valid_secondary}")
        
        if validation.notes:
            print("\n  Notes:")
            for note in validation.notes:
                print(f"    - {note}")
        
        if validation.warnings:
            print("\n  Warnings:")
            for warning in validation.warnings:
                print_warning(f"    {warning}")
        
    except PDFScalpelError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@generate.command('stego')
@click.argument('output', type=click.Path(path_type=Path))
@click.option('--data', '-d', required=True, help='Data to hide')
@click.option('--technique', '-t',
              type=click.Choice(['whitespace', 'metadata', 'invisible', 'lsb-image']),
              default='whitespace',
              help='Steganography technique')
@click.option('--cover-text', help='Visible cover text')
@click.option('--method', help='Method variant (for invisible text: white_on_white, tiny_font, off_page)')
def generate_stego_cmd(
    output: Path,
    data: str,
    technique: str,
    cover_text: Optional[str],
    method: Optional[str]
):
    """
    Embed hidden data in PDF using steganography
    
    Creates PDFs with hidden data embedded using various steganographic techniques.
    Data is invisible in normal viewing but can be extracted with proper tools.
    
    Examples:
        pdfscalpel generate stego output.pdf --data "CTF{hidden_flag}" --technique whitespace
        pdfscalpel generate stego secret.pdf --data "Secret message" --technique metadata
        pdfscalpel generate stego invisible.pdf --data "Hidden text" --technique invisible --method white_on_white
        pdfscalpel generate stego image.pdf --data "Image LSB data" --technique lsb-image
    """
    try:
        print_header("Steganography Generator", str(output))
        
        if technique == 'whitespace':
            result = embed_whitespace_stego(output, data, cover_text)
        elif technique == 'metadata':
            result = embed_metadata_stego(output, data, cover_text)
        elif technique == 'invisible':
            method = method or 'white_on_white'
            result = embed_invisible_text(output, data, cover_text, method)
        elif technique == 'lsb-image':
            result = embed_lsb_image_stego(output, data, cover_text)
        
        print_success(f"Steganographic PDF created: {output}")
        print(f"\n  Technique: {result.technique}")
        print(f"  Data Size: {result.data_size} bytes")
        print(f"  Capacity Used: {result.capacity_used:.2%}")
        print(f"\n  Extraction Hint: {result.extraction_hint}")
        
        if result.metadata:
            print("\n  Metadata:")
            for key, value in result.metadata.items():
                print(f"    {key}: {value}")
        
    except PDFScalpelError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@generate.command('watermark')
@click.argument('output', type=click.Path(path_type=Path))
@click.option('--text', '-t', required=True, help='Watermark text')
@click.option('--style', '-s',
              type=click.Choice([s.value for s in WatermarkStyle]),
              default='text_diagonal',
              help='Watermark style')
@click.option('--opacity', '-o', type=float, default=0.3, help='Watermark opacity (0.0-1.0)')
@click.option('--content', help='Main PDF content text')
def generate_watermark_cmd(
    output: Path,
    text: str,
    style: str,
    opacity: float,
    content: Optional[str]
):
    """
    Generate watermarked PDF with various styles
    
    Creates PDFs with different watermark styles for testing watermark
    detection and removal capabilities.
    
    Examples:
        pdfscalpel generate watermark output.pdf --text "CONFIDENTIAL" --style text_diagonal
        pdfscalpel generate watermark draft.pdf --text "DRAFT" --style text_header --opacity 0.5
        pdfscalpel generate watermark sample.pdf --text "SAMPLE" --style grid --opacity 0.2
    """
    try:
        print_header("Watermark Generator", str(output))
        
        result = create_watermarked_pdf(output, text, style, content, opacity)
        
        print_success(f"Watermarked PDF created: {result}")
        print(f"\n  Watermark: {text}")
        print(f"  Style: {style}")
        print(f"  Opacity: {opacity}")
        
    except PDFScalpelError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@generate.command('watermark-samples')
@click.argument('output_dir', type=click.Path(path_type=Path))
@click.option('--text', '-t', default='SAMPLE', help='Watermark text')
def generate_watermark_samples_cmd(
    output_dir: Path,
    text: str
):
    """
    Generate sample PDFs with all watermark styles
    
    Creates a collection of watermarked PDFs demonstrating all available
    watermark styles. Useful for testing and comparison.
    
    Examples:
        pdfscalpel generate watermark-samples ./samples
        pdfscalpel generate watermark-samples ./test_watermarks --text "TEST"
    """
    try:
        print_header("Watermark Sample Generator", str(output_dir))
        
        created_files = create_watermark_samples(output_dir, text)
        
        print_success(f"Created {len(created_files)} watermark samples in: {output_dir}")
        print("\nCreated files:")
        for path in created_files:
            print(f"  - {path.name}")
        
    except PDFScalpelError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.group()
def solve():
    """
    CTF solving tools (ethical use only)
    
    Automated tools for solving PDF-based CTF challenges. Use CTF mode for
    audit trails and ethical compliance. For authorized competitions only.
    
    Examples:
        pdfscalpel solve password input.pdf --ctf-mode --challenge-id ctf2024_1
        pdfscalpel solve flag-hunt input.pdf --patterns ctf,md5
        pdfscalpel solve stego input.pdf --output-dir findings/
        pdfscalpel solve auto input.pdf --ctf-mode --challenge-id test --report report.json
    """
    pass


@analyze.command('structure')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'markdown']), default='text', help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Show verbose output')
@handle_errors("PDF Structure Analysis")
@log_command
def analyze_structure_cmd(input_pdf: Path, output: Optional[Path], format: str, verbose: bool):
    """
    Analyze PDF structure and detect anomalies
    
    Examines PDF internal structure including xref tables, object hierarchy,
    streams, and compliance with PDF standards. Detects corruption, malformation,
    and suspicious patterns.
    
    Examples:
        pdfscalpel analyze structure file.pdf
        pdfscalpel analyze structure file.pdf --output report.json --format json
        pdfscalpel analyze structure suspicious.pdf --verbose
    """
    print_header("PDF Structure Analysis", str(input_pdf))
    
    result = analyze_structure(input_pdf)
    
    if output:
        if format == 'json':
            with open(output, 'w') as f:
                json.dump(result, f, indent=2)
        else:
            with open(output, 'w') as f:
                f.write(str(result))
        print_success(f"Report saved to: {output}")
    else:
        print_analysis_result(result, format)
    
    anomalies = result.get('anomalies', [])
    if anomalies:
        print_info(f"Found {len(anomalies)} anomalies")
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'unknown')
            desc = anomaly.get('description', 'Unknown anomaly')
            print_warning(f"[{severity.upper()}] {desc}")
            
            if verbose and 'details' in anomaly:
                print_verbose(f"  Details: {anomaly['details']}", verbose)
        
        if not verbose and len(anomalies) > 5:
            print_suggestion("Use --verbose to see all anomaly details")
    else:
        print_success("No structural anomalies detected")


@analyze.command('metadata')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'markdown']), default='text', help='Output format')
def analyze_metadata_cmd(input_pdf: Path, output: Optional[Path], format: str):
    """Extract and analyze PDF metadata"""
    try:
        print_header("PDF Metadata Analysis", str(input_pdf))
        
        result = analyze_metadata(input_pdf)
        
        if output:
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2)
            else:
                with open(output, 'w') as f:
                    f.write(str(result))
            print_success(f"Report saved to: {output}")
        else:
            print_analysis_result(result, format)
        
        tool_fp = result.get('tool_fingerprint', {})
        if tool_fp.get('identified_tool'):
            print_success(f"Identified tool: {tool_fp['identified_tool']} (confidence: {tool_fp['confidence']:.0%})")
        
        hidden = result.get('hidden_fields', [])
        if hidden:
            print_info(f"Found {len(hidden)} hidden/non-standard metadata fields")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@analyze.command('compliance')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--standard', '-s', type=click.Choice(['all', 'pdfa', 'pdfx', 'pdfe', 'pdfua']), default='all', help='Standard to check')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'markdown']), default='text', help='Output format')
def analyze_compliance_cmd(input_pdf: Path, standard: str, output: Optional[Path], format: str):
    """Check PDF compliance with standards (PDF/A, PDF/X, PDF/E, PDF/UA)"""
    try:
        print_header("PDF Compliance Check", str(input_pdf))
        print_info(f"Checking: {standard.upper()}")
        
        result = check_compliance(input_pdf, standard)
        
        if output:
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2)
            else:
                with open(output, 'w') as f:
                    f.write(str(result))
            print_success(f"Report saved to: {output}")
        else:
            print_analysis_result(result, format)
        
        compliance_checks = {k: v for k, v in result.items() if k.startswith('pdf_') and isinstance(v, dict)}
        for std_name, std_result in compliance_checks.items():
            compliant = std_result.get('compliant')
            if compliant is True:
                print_success(f"{std_name.upper()}: COMPLIANT")
            elif compliant is False:
                violations = std_result.get('violations', [])
                print_error(f"{std_name.upper()}: NOT COMPLIANT ({len(violations)} violations)")
            else:
                print_info(f"{std_name.upper()}: UNKNOWN")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@analyze.command('encryption')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--check-exploits', is_flag=True, help='Check for exploitation opportunities')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'markdown']), default='text', help='Output format')
def analyze_encryption_cmd(input_pdf: Path, check_exploits: bool, output: Optional[Path], format: str):
    """Analyze PDF encryption and assess crackability"""
    try:
        print_header("PDF Encryption Analysis", str(input_pdf))
        
        result = analyze_encryption(input_pdf, check_exploits=check_exploits)
        
        if output:
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2)
            else:
                with open(output, 'w') as f:
                    f.write(str(result))
            print_success(f"Report saved to: {output}")
        else:
            print_analysis_result(result, format)
        
        if not result['is_encrypted']:
            print_success("PDF is not encrypted")
        else:
            print_info(f"Algorithm: {result['algorithm']}")
            print_info(f"Key Length: {result['key_length']} bits")
            print_info(f"Revision: R{result['revision']}")
            
            if check_exploits and result.get('crackability'):
                crack = result['crackability']
                weaknesses = crack.get('weaknesses', [])
                
                if weaknesses:
                    print_error(f"Found {len(weaknesses)} security weaknesses:")
                    for weakness in weaknesses:
                        print_error(f"  - {weakness}")
                
                print_info(f"Dictionary attack probability: {crack['dictionary_attack_probability']:.0%}")
                print_info(f"Recommended approach: {crack['recommended_approach']}")
                
                if crack.get('exploitable_owner_password'):
                    print_error("Owner password may be exploitable")
                
                if crack.get('permission_bypass_possible'):
                    print_error("Permission bypass may be possible")
            
            if result.get('owner_password_weakness'):
                print_error(f"Owner password weakness: {result['owner_password_weakness']}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@analyze.command('watermark')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--verbose', '-v', is_flag=True, help='Show detailed properties and CTF angles')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'markdown']), default='text', help='Output format')
def analyze_watermark_cmd(input_pdf: Path, verbose: bool, output: Optional[Path], format: str):
    """Detect and classify watermarks"""
    try:
        print_header("PDF Watermark Analysis", str(input_pdf))
        
        result = analyze_watermark(input_pdf, verbose=verbose)
        
        if output:
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2)
            else:
                with open(output, 'w') as f:
                    f.write(str(result))
            print_success(f"Report saved to: {output}")
        else:
            print_analysis_result(result, format)
        
        wm_count = result['total_watermarks']
        if wm_count == 0:
            print_success("No watermarks detected")
        else:
            print_info(f"Detected {wm_count} watermark(s)")
            print_info(f"Analysis confidence: {result['analysis_confidence']:.0%}")
            
            if verbose:
                from rich.table import Table
                from rich.console import Console
                
                console = Console()
                table = Table(title="Watermark Details")
                table.add_column("Type", style="cyan")
                table.add_column("Confidence", style="green")
                table.add_column("Pages", style="yellow")
                table.add_column("Difficulty", style="magenta")
                
                for wm in result['watermarks']:
                    table.add_row(
                        wm['type'],
                        f"{wm['confidence']:.0%}",
                        f"{wm['pages_count']}/{result['total_pages']}",
                        wm['removal_difficulty']
                    )
                
                console.print(table)
            
            if result.get('recommendations'):
                print_info("\nRecommendations:")
                for rec in result['recommendations']:
                    click.echo(f"  - {rec}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@analyze.command('intelligence')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--report', '-r', type=click.Path(path_type=Path), help='Output file for intelligence report')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'markdown']), default='text', help='Output format')
@click.option('--quick', is_flag=True, help='Quick analysis (skip deep sub-analyzers)')
def analyze_intelligence_cmd(input_pdf: Path, report: Optional[Path], format: str, quick: bool):
    """Generate intelligence report with recommendations"""
    try:
        print_header("PDF Intelligence Analysis", str(input_pdf))
        
        intel_report = analyze_intelligence(input_pdf, deep=not quick)
        
        if report:
            if format == 'json':
                with open(report, 'w') as f:
                    json.dump(intel_report.to_dict(), f, indent=2, default=str)
            else:
                with open(report, 'w') as f:
                    f.write(_format_intelligence_report(intel_report, format))
            print_success(f"Intelligence report saved to: {report}")
        else:
            click.echo(_format_intelligence_report(intel_report, format))
        
        findings_count = len(intel_report.findings)
        critical = sum(1 for f in intel_report.findings if f.severity == "critical")
        high = sum(1 for f in intel_report.findings if f.severity == "high")
        
        print_info(f"Total findings: {findings_count}")
        if critical > 0:
            print_error(f"Critical findings: {critical}")
        if high > 0:
            print_error(f"High-severity findings: {high}")
        
        if intel_report.recommendations:
            print_info(f"\nTop {min(3, len(intel_report.recommendations))} Recommendations:")
            for i, rec in enumerate(intel_report.recommendations[:3], 1):
                priority_color = {
                    "critical": "red",
                    "high": "yellow",
                    "medium": "cyan",
                    "low": "white"
                }.get(rec.priority, "white")
                
                click.echo(click.style(f"{i}. [{rec.priority.upper()}] {rec.action}", fg=priority_color))
                if rec.command:
                    click.echo(f"   Command: {rec.command}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@analyze.command('render-diff')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--readers', '-r', help='Comma-separated list of readers (adobe,foxit,chrome,firefox)', default='adobe,chrome,firefox')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'markdown']), default='text', help='Output format')
def analyze_render_diff_cmd(input_pdf: Path, readers: str, output: Optional[Path], format: str):
    """Analyze rendering differences between PDF readers"""
    try:
        print_header("PDF Rendering Difference Analysis", str(input_pdf))
        
        reader_list = [r.strip() for r in readers.split(',')]
        
        result = analyze_rendering_differences(input_pdf, reader_list)
        
        if output:
            if format == 'json':
                result_dict = {reader: [d.to_dict() for d in diffs] for reader, diffs in result.items()}
                with open(output, 'w') as f:
                    json.dump(result_dict, f, indent=2)
            else:
                with open(output, 'w') as f:
                    f.write(_format_rendering_diff_report(result, format))
            print_success(f"Rendering analysis saved to: {output}")
        else:
            click.echo(_format_rendering_diff_report(result, format))
        
        total_diffs = sum(len(diffs) for diffs in result.values())
        if total_diffs == 0:
            print_success("No significant rendering differences detected")
        else:
            print_info(f"Total rendering differences: {total_diffs}")
            
            for reader, diffs in result.items():
                if diffs:
                    print_info(f"{reader}: {len(diffs)} difference(s)")
                    for diff in diffs:
                        if diff.risk_level in ["critical", "high"]:
                            print_error(f"  - [{diff.risk_level.upper()}] {diff.feature}: {diff.behavior}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@analyze.command('graph')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), required=True, help='Output file path')
@click.option('--format', '-f', type=click.Choice(['dot', 'html', 'json']), default='dot', help='Output format')
@click.option('--depth', '-d', type=int, default=-1, help='Maximum traversal depth (-1 for unlimited)')
@click.option('--filter-types', help='Comma-separated list of object types to include')
@click.option('--no-entropy', is_flag=True, help='Disable entropy analysis')
@click.option('--title', '-t', help='Graph title')
def analyze_graph_cmd(input_pdf: Path, output: Path, format: str, depth: int, filter_types: Optional[str], no_entropy: bool, title: Optional[str]):
    """Generate PDF object graph visualization"""
    try:
        print_header("PDF Object Graph Generation", str(input_pdf))
        
        filter_list = None
        if filter_types:
            filter_list = [t.strip() for t in filter_types.split(',')]
            print_info(f"Filtering types: {', '.join(filter_list)}")
        
        if depth >= 0:
            print_info(f"Max depth: {depth}")
        
        print_info("Analyzing PDF structure...")
        graph_data = analyze_object_graph(
            input_pdf,
            max_depth=depth,
            include_entropy=not no_entropy,
            filter_types=filter_list,
        )
        
        stats = graph_data['statistics']
        print_success(f"Graph generated: {stats['total_nodes']} nodes, {stats['total_edges']} edges")
        print_info(f"Object types: {len(stats['nodes_by_type'])}")
        print_info(f"Suspicious nodes: {stats['suspicious_nodes']}")
        print_info(f"Average entropy: {stats['avg_entropy']:.4f}")
        
        graph_title = title or f"PDF Object Graph: {input_pdf.name}"
        
        if format == 'json':
            with open(output, 'w') as f:
                json.dump(graph_data, f, indent=2)
            print_success(f"JSON graph data saved to: {output}")
        
        elif format == 'dot':
            with PDFDocument.open(input_pdf) as pdf_doc:
                generator = PDFObjectGraphGenerator(pdf_doc)
                dot_content = generator.to_dot(graph_data, title=graph_title)
            
            with open(output, 'w') as f:
                f.write(dot_content)
            print_success(f"DOT file saved to: {output}")
            print_info("Convert to image with: dot -Tpng graph.dot -o graph.png")
        
        elif format == 'html':
            with PDFDocument.open(input_pdf) as pdf_doc:
                generator = PDFObjectGraphGenerator(pdf_doc)
                html_content = generator.to_html(graph_data, title=graph_title)
            
            with open(output, 'w') as f:
                f.write(html_content)
            print_success(f"Interactive HTML saved to: {output}")
            print_info(f"Open in browser: file://{output.absolute()}")
        
        if stats['suspicious_nodes'] > 0:
            print_error(f"Warning: {stats['suspicious_nodes']} suspicious objects detected (high entropy or malicious patterns)")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@analyze.command('entropy')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--heatmap', type=click.Path(path_type=Path), help='Generate entropy heatmap image')
@click.option('--histogram', is_flag=True, help='Include histogram data in output')
def analyze_entropy_cmd(input_pdf: Path, output: Optional[Path], format: str, heatmap: Optional[Path], histogram: bool):
    """Analyze PDF entropy for malware/stego detection"""
    try:
        print_header("PDF Entropy Analysis", str(input_pdf))
        
        result = analyze_entropy(input_pdf)
        
        stats = result['entropy_statistics']
        print_info(f"Total objects: {result['total_objects']}")
        print_info(f"Entropy range: {stats['min']:.4f} - {stats['max']:.4f}")
        print_info(f"Mean entropy: {stats['mean']:.4f}")
        print_info(f"Median entropy: {stats['median']:.4f}")
        
        print_info("\nEntropy Distribution:")
        for classification, count in result['entropy_distribution'].items():
            if count > 0:
                click.echo(f"  {classification}: {count}")
        
        suspicious_count = len(result['suspicious_objects'])
        if suspicious_count > 0:
            print_error(f"\nSuspicious objects: {suspicious_count}")
            print_info("Top 5 suspicious objects:")
            for i, obj in enumerate(result['suspicious_objects'][:5], 1):
                click.echo(f"  {i}. Object {obj['object_id']}: entropy={obj['entropy']:.4f}, type={obj['type']}")
        else:
            print_success("No suspicious high-entropy objects detected")
        
        if histogram:
            with PDFDocument.open(input_pdf) as pdf_doc:
                analyzer = PDFEntropyAnalyzer(pdf_doc)
                hist_data = analyzer.generate_entropy_histogram()
                result['histogram'] = hist_data
                print_info("Histogram data included in output")
        
        if heatmap:
            print_info(f"Generating entropy heatmap...")
            with PDFDocument.open(input_pdf) as pdf_doc:
                analyzer = PDFEntropyAnalyzer(pdf_doc)
                analyzer.generate_entropy_heatmap(heatmap)
            print_success(f"Heatmap saved to: {heatmap}")
        
        if output:
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2)
            else:
                with open(output, 'w') as f:
                    f.write(_format_entropy_report(result))
            print_success(f"Report saved to: {output}")
        elif format == 'json':
            click.echo(json.dumps(result, indent=2))
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


def _format_entropy_report(result: Dict[str, Any]) -> str:
    """Format entropy report for text output"""
    lines = []
    lines.append("=" * 80)
    lines.append("PDF ENTROPY ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"File: {result['file_path']}")
    lines.append(f"Total Objects: {result['total_objects']}")
    lines.append("")
    
    lines.append("ENTROPY STATISTICS")
    lines.append("-" * 80)
    stats = result['entropy_statistics']
    lines.append(f"Minimum: {stats['min']:.4f}")
    lines.append(f"Maximum: {stats['max']:.4f}")
    lines.append(f"Mean: {stats['mean']:.4f}")
    lines.append(f"Median: {stats['median']:.4f}")
    lines.append("")
    
    lines.append("ENTROPY DISTRIBUTION")
    lines.append("-" * 80)
    for classification, count in result['entropy_distribution'].items():
        lines.append(f"{classification}: {count}")
    lines.append("")
    
    if result['suspicious_objects']:
        lines.append(f"SUSPICIOUS OBJECTS ({len(result['suspicious_objects'])})")
        lines.append("-" * 80)
        for obj in result['suspicious_objects'][:20]:
            lines.append(f"Object {obj['object_id']}: entropy={obj['entropy']:.4f}, "
                        f"size={obj['size']}, type={obj['type']}, class={obj['classification']}")
        lines.append("")
    
    return '\n'.join(lines)


@analyze.command('malware')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--yara-rules', type=click.Path(exists=True, path_type=Path), help='YARA rules directory')
@handle_errors("PDF Malware Analysis")
@log_command
def analyze_malware_cmd(input_pdf: Path, output: Optional[Path], format: str, yara_rules: Optional[Path]):
    """
    Detect malware, exploits, and malicious JavaScript in PDFs
    
    Comprehensive malware detection including CVE fingerprinting, JavaScript
    exploit detection, obfuscation analysis, shellcode patterns, heap spray
    detection, and YARA rule scanning.
    
    Examples:
        pdfscalpel analyze malware suspicious.pdf
        pdfscalpel analyze malware file.pdf --yara-rules ./rules --output report.json
        pdfscalpel analyze malware malicious.pdf --format json
    """
    print_header("PDF Malware Analysis", str(input_pdf))
    
    try:
        analyzer = PDFMalwareAnalyzer(yara_rules_dir=yara_rules)
        result = analyzer.analyze(input_pdf)
        
        if result.is_malicious:
            print_error(f"THREAT DETECTED: {result.threat_level.value.upper()}")
        else:
            print_success("No malware detected")
        
        print_info(f"Confidence: {result.confidence:.1%}")
        print_info(f"Findings: {len(result.findings)}")
        print_info(f"JavaScript detected: {result.javascript_detected}")
        print_info(f"Obfuscation score: {result.obfuscation_score:.2f}")
        
        if result.cve_matches:
            print_warning(f"\nCVE Matches: {', '.join(result.cve_matches)}")
        
        if result.malicious_actions:
            print_warning(f"\nMalicious Actions:")
            for action in result.malicious_actions:
                click.echo(f"  - {action}")
        
        if result.findings:
            click.echo("\nDetailed Findings:")
            for i, finding in enumerate(result.findings[:10], 1):
                severity_color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'yellow',
                    'info': 'blue'
                }.get(finding.severity.value, 'white')
                
                click.secho(f"\n{i}. [{finding.severity.value.upper()}] {finding.type.value}", 
                           fg=severity_color, bold=True)
                click.echo(f"   {finding.description}")
                click.echo(f"   Confidence: {finding.confidence:.1%}")
                if finding.location:
                    click.echo(f"   Location: {finding.location}")
                if finding.cve_id:
                    click.echo(f"   CVE: {finding.cve_id}")
        
        if len(result.findings) > 10:
            print_info(f"\n... and {len(result.findings) - 10} more findings")
        
        if output:
            result_dict = result.to_dict()
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(result_dict, f, indent=2, default=str)
            else:
                with open(output, 'w') as f:
                    f.write(_format_malware_report(result))
            print_success(f"\nReport saved to: {output}")
        elif format == 'json':
            click.echo(json.dumps(result.to_dict(), indent=2, default=str))
        
    except Exception as e:
        print_error(f"Analysis failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@analyze.command('signatures')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@handle_errors("PDF Signature Validation")
@log_command
def analyze_signatures_cmd(input_pdf: Path, output: Optional[Path], format: str):
    """
    Validate digital signatures and detect signature attacks
    
    Comprehensive signature validation including PKCS#7/CMS verification,
    certificate chain analysis, attack detection (USF, SWA, ISA), weak
    cryptography detection, and PAdES compliance checking.
    
    Examples:
        pdfscalpel analyze signatures signed.pdf
        pdfscalpel analyze signatures file.pdf --output report.json --format json
        pdfscalpel analyze signatures document.pdf
    """
    print_header("PDF Signature Validation", str(input_pdf))
    
    try:
        analyzer = PDFSignatureAnalyzer()
        result = analyzer.analyze(input_pdf)
        
        print_info(f"Total Signatures: {result.total_signatures}")
        
        if result.total_signatures == 0:
            print_info("No signatures found in PDF")
        else:
            status_color = {
                'valid': 'green',
                'invalid': 'red',
                'unknown': 'yellow'
            }.get(result.overall_status.value, 'white')
            
            click.secho(f"Overall Status: {result.overall_status.value.upper()}", 
                       fg=status_color, bold=True)
            click.echo(f"Overall Trust: {result.overall_trust.value}")
            
            if result.attack_indicators:
                print_error(f"\nATTACK INDICATORS DETECTED:")
                for indicator in result.attack_indicators:
                    click.echo(f"  - {indicator}")
            
            if result.cryptography_warnings:
                print_warning(f"\nCryptography Warnings:")
                for warning in result.cryptography_warnings:
                    click.echo(f"  - {warning}")
            
            click.echo("\nSignature Details:")
            for sig in result.signatures:
                click.echo(f"\n  Signature #{sig.signature_number}:")
                click.echo(f"    Signer: {sig.signer_name}")
                click.echo(f"    Status: {sig.status.value}")
                click.echo(f"    Trust: {sig.trust_level.value}")
                click.echo(f"    Algorithm: {sig.digest_algorithm}")
                click.echo(f"    ByteRange Valid: {sig.byte_range_valid}")
                
                if sig.unsigned_bytes > 0:
                    print_warning(f"    Unsigned Bytes: {sig.unsigned_bytes}")
                
                if sig.findings:
                    click.echo(f"    Findings:")
                    for finding in sig.findings:
                        click.echo(f"      - [{finding.severity.value}] {finding.description}")
        
        if output:
            result_dict = result.to_dict()
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(result_dict, f, indent=2, default=str)
            else:
                with open(output, 'w') as f:
                    f.write(_format_signature_report(result))
            print_success(f"\nReport saved to: {output}")
        elif format == 'json':
            click.echo(json.dumps(result.to_dict(), indent=2, default=str))
        
    except Exception as e:
        print_error(f"Analysis failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@analyze.command('form-security')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@handle_errors("PDF Form Security Analysis")
@log_command
def analyze_form_security_cmd(input_pdf: Path, output: Optional[Path], format: str):
    """
    Analyze PDF forms for security vulnerabilities
    
    Comprehensive form security analysis including XXE detection in XFA forms,
    JavaScript injection, SSRF in submit URLs, hidden fields, malicious URL
    schemes, and hybrid AcroForm/XFA risks.
    
    Examples:
        pdfscalpel analyze form-security form.pdf
        pdfscalpel analyze form-security file.pdf --output report.json
        pdfscalpel analyze form-security suspicious.pdf --format json
    """
    print_header("PDF Form Security Analysis", str(input_pdf))
    
    try:
        analyzer = PDFFormSecurityAnalyzer()
        result = analyzer.analyze(input_pdf)
        
        print_info(f"Has AcroForm: {result.has_acroform}")
        print_info(f"Has XFA: {result.has_xfa}")
        print_info(f"Is Hybrid: {result.is_hybrid}")
        print_info(f"Total Fields: {result.total_fields}")
        
        if result.has_acroform:
            print_info(f"Hidden Fields: {result.hidden_fields}")
            print_info(f"JavaScript Fields: {result.javascript_fields}")
            
            if result.submit_urls:
                click.echo(f"\nSubmit URLs:")
                for url in result.submit_urls:
                    click.echo(f"  - {url}")
        
        vuln_count = len(result.vulnerabilities)
        if vuln_count > 0:
            print_error(f"\nVulnerabilities Found: {vuln_count}")
            
            for i, vuln in enumerate(result.vulnerabilities, 1):
                severity_color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'yellow',
                    'info': 'blue'
                }.get(vuln.severity.value, 'white')
                
                click.secho(f"\n{i}. [{vuln.severity.value.upper()}] {vuln.type.value}", 
                           fg=severity_color, bold=True)
                click.echo(f"   {vuln.description}")
                click.echo(f"   Location: {vuln.location}")
                
                if vuln.evidence:
                    click.echo(f"   Evidence:")
                    for evidence in vuln.evidence[:3]:
                        click.echo(f"     - {evidence}")
                
                if vuln.cve_id:
                    click.echo(f"   CVE: {vuln.cve_id}")
                
                if vuln.recommendation:
                    click.echo(f"   Recommendation: {vuln.recommendation}")
        else:
            print_success("No form security vulnerabilities detected")
        
        if output:
            result_dict = result.to_dict()
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(result_dict, f, indent=2, default=str)
            else:
                with open(output, 'w') as f:
                    f.write(_format_form_security_report(result))
            print_success(f"\nReport saved to: {output}")
        elif format == 'json':
            click.echo(json.dumps(result.to_dict(), indent=2, default=str))
        
    except Exception as e:
        print_error(f"Analysis failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@analyze.command('anti-forensics')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@handle_errors("PDF Anti-Forensics Detection")
@log_command
def analyze_anti_forensics_cmd(input_pdf: Path, output: Optional[Path], format: str):
    """
    Detect PDF sanitization and anti-forensic manipulation
    
    Detects sanitization tool fingerprints (ExifTool, MAT2, QPDF, Ghostscript),
    metadata removal patterns, incremental update removal, timestamp anomalies,
    and object manipulation indicators.
    
    Examples:
        pdfscalpel analyze anti-forensics document.pdf
        pdfscalpel analyze anti-forensics file.pdf --output report.json
        pdfscalpel analyze anti-forensics sanitized.pdf --format json
    """
    print_header("PDF Anti-Forensics Detection", str(input_pdf))
    
    try:
        detector = PDFAntiForensicsDetector()
        result = detector.analyze(input_pdf)
        
        if result.is_sanitized:
            print_warning(f"SANITIZATION DETECTED (confidence: {result.sanitization_confidence:.1%})")
        else:
            print_success("No sanitization detected")
        
        if result.detected_tools:
            click.echo(f"\nDetected Tools:")
            for tool_fp in result.detected_tools:
                click.echo(f"  - {tool_fp.tool.value} (confidence: {tool_fp.confidence:.1%})")
                if tool_fp.evidence:
                    click.echo(f"    Evidence:")
                    for evidence in tool_fp.evidence[:3]:
                        click.echo(f"      * {evidence}")
        
        print_info(f"\nMetadata removed: {result.metadata_removed}")
        print_info(f"Incremental updates removed: {result.incremental_updates_removed}")
        print_info(f"JavaScript removed: {result.javascript_removed}")
        print_info(f"Embedded files removed: {result.embedded_files_removed}")
        
        if result.findings:
            click.echo(f"\nFindings ({len(result.findings)}):")
            for i, finding in enumerate(result.findings, 1):
                severity_color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'yellow',
                    'info': 'blue'
                }.get(finding.severity.value, 'white')
                
                click.secho(f"\n{i}. [{finding.severity.value.upper()}] {finding.type}", 
                           fg=severity_color, bold=True)
                click.echo(f"   {finding.description}")
                
                if finding.evidence:
                    click.echo(f"   Evidence:")
                    for evidence in finding.evidence[:3]:
                        click.echo(f"     - {evidence}")
        
        if result.recommendations:
            click.echo(f"\nRecommendations:")
            for rec in result.recommendations:
                click.echo(f"  - {rec}")
        
        if output:
            result_dict = result.to_dict()
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(result_dict, f, indent=2, default=str)
            else:
                with open(output, 'w') as f:
                    f.write(_format_anti_forensics_report(result))
            print_success(f"\nReport saved to: {output}")
        elif format == 'json':
            click.echo(json.dumps(result.to_dict(), indent=2, default=str))
        
    except Exception as e:
        print_error(f"Analysis failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@analyze.command('advanced-stego')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--deep', is_flag=True, help='Enable deep content stream analysis (slower)')
@handle_errors("PDF Advanced Steganography Detection")
@log_command
def analyze_advanced_stego_cmd(input_pdf: Path, output: Optional[Path], format: str, deep: bool):
    """
    Detect advanced steganography techniques in PDFs
    
    Detects sophisticated steganography beyond LSB including stream operator
    manipulation, object ID ordering covert channels, zero-width Unicode
    characters, xref manipulation, incremental updates, and trailing data.
    
    Examples:
        pdfscalpel analyze advanced-stego file.pdf
        pdfscalpel analyze advanced-stego suspicious.pdf --deep
        pdfscalpel analyze advanced-stego file.pdf --output report.json
    """
    print_header("PDF Advanced Steganography Detection", str(input_pdf))
    
    try:
        detector = PDFAdvancedStegoDetector()
        result = detector.analyze(input_pdf, deep_analysis=deep)
        
        if result.stego_detected:
            print_warning(f"STEGANOGRAPHY DETECTED (confidence: {result.overall_confidence:.1%})")
        else:
            print_success("No steganography detected")
        
        print_info(f"\nTrailing data: {result.trailing_data_size} bytes")
        print_info(f"Incremental updates: {result.incremental_updates_count}")
        print_info(f"Suspicious objects: {result.suspicious_objects_count}")
        
        if result.findings:
            click.echo(f"\nFindings ({len(result.findings)}):")
            for i, finding in enumerate(result.findings, 1):
                severity_color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'yellow',
                    'info': 'blue'
                }.get(finding.severity.value, 'white')
                
                click.secho(f"\n{i}. [{finding.severity.value.upper()}] {finding.technique.value}", 
                           fg=severity_color, bold=True)
                click.echo(f"   {finding.description}")
                click.echo(f"   Confidence: {finding.confidence:.1%}")
                click.echo(f"   Location: {finding.location}")
                
                if finding.estimated_capacity:
                    click.echo(f"   Estimated Capacity: {finding.estimated_capacity}")
                
                if finding.evidence:
                    click.echo(f"   Evidence:")
                    for evidence in finding.evidence[:3]:
                        click.echo(f"     - {evidence}")
        
        if result.entropy_anomalies:
            click.echo(f"\nEntropy Anomalies:")
            for anomaly in result.entropy_anomalies[:5]:
                click.echo(f"  - {anomaly}")
        
        if result.recommendations:
            click.echo(f"\nRecommendations:")
            for rec in result.recommendations:
                click.echo(f"  - {rec}")
        
        if output:
            result_dict = result.to_dict()
            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(result_dict, f, indent=2, default=str)
            else:
                with open(output, 'w') as f:
                    f.write(_format_advanced_stego_report(result))
            print_success(f"\nReport saved to: {output}")
        elif format == 'json':
            click.echo(json.dumps(result.to_dict(), indent=2, default=str))
        
    except Exception as e:
        print_error(f"Analysis failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _format_malware_report(result) -> str:
    """Format malware analysis report for text output"""
    lines = []
    lines.append("=" * 80)
    lines.append("PDF MALWARE ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"File: {result.file_path}")
    lines.append(f"Threat Level: {result.threat_level.value.upper()}")
    lines.append(f"Is Malicious: {result.is_malicious}")
    lines.append(f"Confidence: {result.confidence:.1%}")
    lines.append("")
    
    lines.append("SUMMARY")
    lines.append("-" * 80)
    lines.append(f"Findings: {len(result.findings)}")
    lines.append(f"JavaScript Detected: {result.javascript_detected}")
    lines.append(f"Obfuscation Score: {result.obfuscation_score:.2f}")
    lines.append("")
    
    if result.cve_matches:
        lines.append("CVE MATCHES")
        lines.append("-" * 80)
        for cve in result.cve_matches:
            lines.append(f"  - {cve}")
        lines.append("")
    
    if result.malicious_actions:
        lines.append("MALICIOUS ACTIONS")
        lines.append("-" * 80)
        for action in result.malicious_actions:
            lines.append(f"  - {action}")
        lines.append("")
    
    if result.findings:
        lines.append(f"DETAILED FINDINGS ({len(result.findings)})")
        lines.append("-" * 80)
        for i, finding in enumerate(result.findings, 1):
            lines.append(f"{i}. [{finding.severity.value.upper()}] {finding.type.value}")
            lines.append(f"   {finding.description}")
            lines.append(f"   Confidence: {finding.confidence:.1%}")
            if finding.location:
                lines.append(f"   Location: {finding.location}")
            if finding.cve_id:
                lines.append(f"   CVE: {finding.cve_id}")
            lines.append("")
    
    return '\n'.join(lines)


def _format_signature_report(result) -> str:
    """Format signature analysis report for text output"""
    lines = []
    lines.append("=" * 80)
    lines.append("PDF SIGNATURE VALIDATION REPORT")
    lines.append("=" * 80)
    lines.append(f"File: {result.file_path}")
    lines.append(f"Total Signatures: {result.total_signatures}")
    lines.append(f"Overall Status: {result.overall_status.value.upper()}")
    lines.append(f"Overall Trust: {result.overall_trust.value}")
    lines.append("")
    
    if result.attack_indicators:
        lines.append("ATTACK INDICATORS")
        lines.append("-" * 80)
        for indicator in result.attack_indicators:
            lines.append(f"  - {indicator}")
        lines.append("")
    
    if result.cryptography_warnings:
        lines.append("CRYPTOGRAPHY WARNINGS")
        lines.append("-" * 80)
        for warning in result.cryptography_warnings:
            lines.append(f"  - {warning}")
        lines.append("")
    
    for sig in result.signatures:
        lines.append(f"SIGNATURE #{sig.signature_number}")
        lines.append("-" * 80)
        lines.append(f"Signer: {sig.signer_name}")
        lines.append(f"Status: {sig.status.value}")
        lines.append(f"Trust Level: {sig.trust_level.value}")
        lines.append(f"Digest Algorithm: {sig.digest_algorithm}")
        lines.append(f"ByteRange Valid: {sig.byte_range_valid}")
        lines.append(f"Unsigned Bytes: {sig.unsigned_bytes}")
        
        if sig.findings:
            lines.append("Findings:")
            for finding in sig.findings:
                lines.append(f"  - [{finding.severity.value}] {finding.description}")
        lines.append("")
    
    return '\n'.join(lines)


def _format_form_security_report(result) -> str:
    """Format form security report for text output"""
    lines = []
    lines.append("=" * 80)
    lines.append("PDF FORM SECURITY ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"File: {result.file_path}")
    lines.append(f"Has AcroForm: {result.has_acroform}")
    lines.append(f"Has XFA: {result.has_xfa}")
    lines.append(f"Is Hybrid: {result.is_hybrid}")
    lines.append(f"Total Fields: {result.total_fields}")
    lines.append("")
    
    if result.has_acroform:
        lines.append("ACROFORM DETAILS")
        lines.append("-" * 80)
        lines.append(f"Hidden Fields: {result.hidden_fields}")
        lines.append(f"JavaScript Fields: {result.javascript_fields}")
        lines.append("")
    
    if result.submit_urls:
        lines.append("SUBMIT URLS")
        lines.append("-" * 80)
        for url in result.submit_urls:
            lines.append(f"  - {url}")
        lines.append("")
    
    if result.vulnerabilities:
        lines.append(f"VULNERABILITIES ({len(result.vulnerabilities)})")
        lines.append("-" * 80)
        for i, vuln in enumerate(result.vulnerabilities, 1):
            lines.append(f"{i}. [{vuln.severity.value.upper()}] {vuln.type.value}")
            lines.append(f"   {vuln.description}")
            lines.append(f"   Location: {vuln.location}")
            if vuln.cve_id:
                lines.append(f"   CVE: {vuln.cve_id}")
            lines.append("")
    
    return '\n'.join(lines)


def _format_anti_forensics_report(result) -> str:
    """Format anti-forensics report for text output"""
    lines = []
    lines.append("=" * 80)
    lines.append("PDF ANTI-FORENSICS DETECTION REPORT")
    lines.append("=" * 80)
    lines.append(f"File: {result.file_path}")
    lines.append(f"Is Sanitized: {result.is_sanitized}")
    lines.append(f"Sanitization Confidence: {result.sanitization_confidence:.1%}")
    lines.append("")
    
    if result.detected_tools:
        lines.append("DETECTED TOOLS")
        lines.append("-" * 80)
        for tool_fp in result.detected_tools:
            lines.append(f"  - {tool_fp.tool.value} (confidence: {tool_fp.confidence:.1%})")
        lines.append("")
    
    lines.append("MANIPULATION INDICATORS")
    lines.append("-" * 80)
    lines.append(f"Metadata Removed: {result.metadata_removed}")
    lines.append(f"Incremental Updates Removed: {result.incremental_updates_removed}")
    lines.append(f"JavaScript Removed: {result.javascript_removed}")
    lines.append(f"Embedded Files Removed: {result.embedded_files_removed}")
    lines.append("")
    
    if result.findings:
        lines.append(f"FINDINGS ({len(result.findings)})")
        lines.append("-" * 80)
        for i, finding in enumerate(result.findings, 1):
            lines.append(f"{i}. [{finding.severity.value.upper()}] {finding.type}")
            lines.append(f"   {finding.description}")
            lines.append("")
    
    return '\n'.join(lines)


def _format_advanced_stego_report(result) -> str:
    """Format advanced steganography report for text output"""
    lines = []
    lines.append("=" * 80)
    lines.append("PDF ADVANCED STEGANOGRAPHY DETECTION REPORT")
    lines.append("=" * 80)
    lines.append(f"File: {result.file_path}")
    lines.append(f"Steganography Detected: {result.stego_detected}")
    lines.append(f"Overall Confidence: {result.overall_confidence:.1%}")
    lines.append("")
    
    lines.append("SUMMARY")
    lines.append("-" * 80)
    lines.append(f"Trailing Data: {result.trailing_data_size} bytes")
    lines.append(f"Incremental Updates: {result.incremental_updates_count}")
    lines.append(f"Suspicious Objects: {result.suspicious_objects_count}")
    lines.append("")
    
    if result.findings:
        lines.append(f"FINDINGS ({len(result.findings)})")
        lines.append("-" * 80)
        for i, finding in enumerate(result.findings, 1):
            lines.append(f"{i}. [{finding.severity.value.upper()}] {finding.technique.value}")
            lines.append(f"   {finding.description}")
            lines.append(f"   Confidence: {finding.confidence:.1%}")
            lines.append(f"   Location: {finding.location}")
            if finding.estimated_capacity:
                lines.append(f"   Estimated Capacity: {finding.estimated_capacity}")
            lines.append("")
    
    return '\n'.join(lines)


def _format_intelligence_report(report, format_type: str) -> str:
    """Format intelligence report for display"""
    if format_type == 'json':
        return json.dumps(report.to_dict(), indent=2, default=str)
    
    lines = []
    lines.append("=" * 80)
    lines.append("PDF INTELLIGENCE REPORT")
    lines.append("=" * 80)
    lines.append(f"File: {report.file_path}")
    lines.append(f"Timestamp: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 80)
    lines.append(report.executive_summary)
    lines.append("")
    
    if report.creator_analysis:
        lines.append("CREATOR ANALYSIS")
        lines.append("-" * 80)
        tool = report.creator_analysis.get('tool', 'Unknown')
        confidence = report.creator_analysis.get('confidence', 0.0)
        lines.append(f"Tool: {tool} (confidence: {confidence:.0%})")
        
        implications = report.creator_analysis.get('implications', [])
        if implications:
            lines.append("Implications:")
            for impl in implications:
                lines.append(f"  - {impl}")
        lines.append("")
    
    if report.encryption_analysis and report.encryption_analysis.get('is_encrypted'):
        lines.append("ENCRYPTION ANALYSIS")
        lines.append("-" * 80)
        enc = report.encryption_analysis
        lines.append(f"Algorithm: {enc.get('algorithm', 'Unknown')}")
        lines.append(f"Key Length: {enc.get('key_length', 'Unknown')} bits")
        
        if enc.get('crackability'):
            crack = enc['crackability']
            lines.append(f"Crackability: {crack['recommended_approach']}")
            lines.append(f"Dictionary attack probability: {crack['dictionary_attack_probability']:.0%}")
        lines.append("")
    
    if report.findings:
        lines.append(f"FINDINGS ({len(report.findings)} total)")
        lines.append("-" * 80)
        
        by_severity = {}
        for finding in report.findings:
            by_severity.setdefault(finding.severity, []).append(finding)
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            findings = by_severity.get(severity, [])
            if findings:
                lines.append(f"\n{severity.upper()} ({len(findings)}):")
                for f in findings:
                    lines.append(f"  - {f.description} (confidence: {f.confidence:.0%})")
        lines.append("")
    
    if report.rendering_risks:
        lines.append(f"RENDERING RISKS ({len(report.rendering_risks)} features)")
        lines.append("-" * 80)
        for risk in report.rendering_risks:
            lines.append(f"Feature: {risk['feature']}")
            lines.append(f"  Risk Level: {risk['risk_level'].upper()}")
            if risk.get('exploitation_potential'):
                lines.append(f"  Exploitation: {risk['exploitation_potential']}")
        lines.append("")
    
    if report.recommendations:
        lines.append(f"RECOMMENDATIONS ({len(report.recommendations)} total)")
        lines.append("-" * 80)
        
        by_priority = {}
        for rec in report.recommendations:
            by_priority.setdefault(rec.priority, []).append(rec)
        
        for priority in ["critical", "high", "medium", "low"]:
            recs = by_priority.get(priority, [])
            if recs:
                lines.append(f"\n{priority.upper()} PRIORITY:")
                for r in recs:
                    lines.append(f"  - {r.action}")
                    lines.append(f"    Reasoning: {r.reasoning}")
                    if r.command:
                        lines.append(f"    Command: {r.command}")
        lines.append("")
    
    if report.suggested_workflow:
        lines.append("SUGGESTED WORKFLOW")
        lines.append("-" * 80)
        for step in report.suggested_workflow:
            lines.append(step)
        lines.append("")
    
    lines.append("=" * 80)
    
    return "\n".join(lines)


def _format_rendering_diff_report(result: dict, format_type: str) -> str:
    """Format rendering difference report"""
    if format_type == 'json':
        result_dict = {reader: [d.to_dict() for d in diffs] for reader, diffs in result.items()}
        return json.dumps(result_dict, indent=2)
    
    lines = []
    lines.append("=" * 80)
    lines.append("PDF RENDERING DIFFERENCE ANALYSIS")
    lines.append("=" * 80)
    lines.append("")
    
    for reader, diffs in result.items():
        lines.append(f"{reader.upper()}")
        lines.append("-" * 80)
        
        if not diffs:
            lines.append("  No significant differences detected")
        else:
            for diff in diffs:
                lines.append(f"  Feature: {diff.feature}")
                lines.append(f"    Behavior: {diff.behavior}")
                lines.append(f"    Risk Level: {diff.risk_level.upper()}")
                if diff.exploitation_potential:
                    lines.append(f"    Exploitation: {diff.exploitation_potential}")
                lines.append("")
        lines.append("")
    
    lines.append("=" * 80)
    
    return "\n".join(lines)


@extract.command('text')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for extracted text')
@click.option('--page', '-p', type=int, help='Extract from specific page (0-indexed)')
@click.option('--no-layout', is_flag=True, help='Disable layout preservation')
@click.option('--password', type=str, help='Password for encrypted PDFs')
def extract_text_cmd(input_pdf: Path, output: Optional[Path], page: Optional[int], no_layout: bool, password: Optional[str]):
    """Extract text from PDF"""
    try:
        print_header("Text Extraction", str(input_pdf))
        
        if page is not None:
            print_info(f"Extracting page {page}")
        
        text = extract_text(
            input_pdf,
            output_file=output,
            page_num=page,
            preserve_layout=not no_layout,
            password=password,
        )
        
        if output:
            print_success(f"Text saved to: {output}")
        else:
            click.echo(text)
        
        char_count = len(text)
        word_count = len(text.split())
        line_count = text.count('\n') + 1
        
        print_info(f"Extracted {char_count} characters, {word_count} words, {line_count} lines")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@extract.command('images')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output-dir', '-o', type=click.Path(path_type=Path), required=True, help='Output directory for images')
@click.option('--page', '-p', type=int, help='Extract from specific page (0-indexed)')
@click.option('--prefix', type=str, default='image', help='Prefix for output filenames')
@click.option('--password', type=str, help='Password for encrypted PDFs')
def extract_images_cmd(input_pdf: Path, output_dir: Path, page: Optional[int], prefix: str, password: Optional[str]):
    """Extract images from PDF"""
    try:
        print_header("Image Extraction", str(input_pdf))
        
        if page is not None:
            print_info(f"Extracting images from page {page}")
        
        images = extract_images(
            input_pdf,
            output_dir,
            page_num=page,
            prefix=prefix,
            password=password,
        )
        
        if images:
            print_success(f"Extracted {len(images)} images to {output_dir}")
            
            from rich.table import Table
            from rich.console import Console
            
            console = Console()
            table = Table(title="Extracted Images")
            table.add_column("Index", style="cyan")
            table.add_column("Filename", style="green")
            table.add_column("Page", style="yellow")
            table.add_column("Format", style="magenta")
            table.add_column("Size", style="blue")
            
            for img in images[:20]:
                table.add_row(
                    str(img.get('global_index', img.get('object_name', ''))),
                    img['filename'],
                    str(img['page']),
                    img['format'],
                    f"{img['width']}x{img['height']}"
                )
            
            console.print(table)
            
            if len(images) > 20:
                print_info(f"Showing first 20 of {len(images)} images")
        else:
            print_info("No images found in PDF")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@extract.command('objects')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--list', '-l', 'list_mode', is_flag=True, help='List all objects')
@click.option('--dump', '-d', type=int, help='Dump specific object by ID')
@click.option('--dump-type', '-t', type=str, help='Dump all objects of type (e.g., Stream, Dictionary)')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file or directory')
@click.option('--filter-types', help='Comma-separated list of types to include (for listing)')
@click.option('--password', type=str, help='Password for encrypted PDFs')
def extract_objects_cmd(
    input_pdf: Path,
    list_mode: bool,
    dump: Optional[int],
    dump_type: Optional[str],
    output: Optional[Path],
    filter_types: Optional[str],
    password: Optional[str]
):
    """List or dump PDF objects"""
    try:
        if list_mode:
            print_header("Object Listing", str(input_pdf))
            
            filter_list = None
            if filter_types:
                filter_list = [t.strip() for t in filter_types.split(',')]
                print_info(f"Filtering types: {', '.join(filter_list)}")
            
            objects = list_objects(input_pdf, filter_types=filter_list, output_file=output, password=password)
            
            if output:
                print_success(f"Object list saved to: {output}")
            
            from rich.table import Table
            from rich.console import Console
            
            console = Console()
            table = Table(title="PDF Objects")
            table.add_column("ID", style="cyan")
            table.add_column("Type", style="green")
            table.add_column("Subtype", style="yellow")
            table.add_column("Size", style="magenta")
            table.add_column("Stream", style="blue")
            
            for obj in objects[:50]:
                table.add_row(
                    str(obj['object_id']),
                    obj['type'],
                    obj.get('subtype', ''),
                    str(obj['size']),
                    'Yes' if obj['is_stream'] else 'No'
                )
            
            console.print(table)
            
            if len(objects) > 50:
                print_info(f"Showing first 50 of {len(objects)} objects")
            
            print_info(f"Total objects: {len(objects)}")
        
        elif dump is not None:
            print_header("Object Dump", str(input_pdf))
            print_info(f"Dumping object {dump}")
            
            if output is None:
                output = Path(f"object_{dump}.bin")
            
            obj_info = dump_object(input_pdf, dump, output_file=output, password=password)
            print_success(f"Object dumped to: {output}")
            
            print_info(f"Type: {obj_info['type']}")
            if obj_info.get('subtype'):
                print_info(f"Subtype: {obj_info['subtype']}")
            
            if obj_info.get('is_stream'):
                print_info(f"Stream: Yes")
                print_info(f"Filter: {obj_info.get('filter', 'None')}")
                if 'decompressed_size' in obj_info:
                    print_info(f"Decompressed size: {obj_info['decompressed_size']} bytes")
        
        elif dump_type:
            print_header("Objects By Type", str(input_pdf))
            print_info(f"Dumping all objects of type: {dump_type}")
            
            if output is None:
                output = Path(f"objects_{dump_type}")
            
            objects = dump_objects_by_type(input_pdf, dump_type, output_dir=output, password=password)
            print_success(f"Dumped {len(objects)} objects to {output}")
        
        else:
            print_error("Must specify --list, --dump, or --dump-type")
            sys.exit(1)
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@extract.command('streams')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output-dir', '-o', type=click.Path(path_type=Path), required=True, help='Output directory for streams')
@click.option('--object-id', type=int, help='Extract specific stream by object ID')
@click.option('--no-decompress', is_flag=True, help='Do not decompress streams')
@click.option('--no-detect', is_flag=True, help='Do not detect file types')
@click.option('--password', type=str, help='Password for encrypted PDFs')
def extract_streams_cmd(
    input_pdf: Path,
    output_dir: Path,
    object_id: Optional[int],
    no_decompress: bool,
    no_detect: bool,
    password: Optional[str]
):
    """Extract and decompress streams from PDF"""
    try:
        print_header("Stream Extraction", str(input_pdf))
        
        if object_id is not None:
            print_info(f"Extracting stream from object {object_id}")
        
        streams = extract_streams(
            input_pdf,
            output_dir,
            obj_id=object_id,
            decompress=not no_decompress,
            detect_type=not no_detect,
            password=password,
        )
        
        if streams:
            print_success(f"Extracted {len(streams)} stream(s) to {output_dir}")
            
            from rich.table import Table
            from rich.console import Console
            
            console = Console()
            table = Table(title="Extracted Streams")
            table.add_column("Object ID", style="cyan")
            table.add_column("Filename", style="green")
            table.add_column("Filter", style="yellow")
            table.add_column("Size", style="magenta")
            table.add_column("Type", style="blue")
            
            for stream in streams[:30]:
                size_str = f"{stream['decompressed_size']}" if stream['decompressed'] else f"{stream['raw_size']}"
                detected = stream.get('detected_type', 'unknown')
                
                table.add_row(
                    str(stream['object_id']),
                    stream['filename'],
                    str(stream['filter'])[:20],
                    size_str,
                    detected if detected else 'unknown'
                )
            
            console.print(table)
            
            if len(streams) > 30:
                print_info(f"Showing first 30 of {len(streams)} streams")
            
            decompressed_count = sum(1 for s in streams if s['decompressed'])
            print_info(f"Decompressed: {decompressed_count}/{len(streams)}")
        else:
            print_info("No streams found in PDF")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@extract.command('javascript')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output-dir', '-o', type=click.Path(path_type=Path), help='Output directory for JavaScript files')
@click.option('--no-deobfuscate', is_flag=True, help='Disable JavaScript deobfuscation')
@click.option('--password', type=str, help='Password for encrypted PDFs')
def extract_javascript_cmd(input_pdf: Path, output_dir: Optional[Path], no_deobfuscate: bool, password: Optional[str]):
    """Extract JavaScript from PDF"""
    try:
        print_header("JavaScript Extraction", str(input_pdf))
        
        scripts = extract_javascript(
            input_pdf,
            output_dir=output_dir,
            deobfuscate=not no_deobfuscate,
            password=password,
        )
        
        if scripts:
            print_success(f"Extracted {len(scripts)} JavaScript block(s)")
            
            if output_dir:
                print_info(f"JavaScript saved to: {output_dir}")
            
            from rich.table import Table
            from rich.console import Console
            
            console = Console()
            table = Table(title="Extracted JavaScript")
            table.add_column("Index", style="cyan")
            table.add_column("Source", style="green")
            table.add_column("Name", style="yellow")
            table.add_column("Size", style="magenta")
            table.add_column("Obfuscated", style="red")
            
            for i, script in enumerate(scripts):
                table.add_row(
                    str(i),
                    script['source'][:40] + ('...' if len(script['source']) > 40 else ''),
                    script.get('name', '(none)') or '(none)',
                    f"{len(script['code'])} chars",
                    'Yes' if script.get('obfuscation_detected') else 'No'
                )
            
            console.print(table)
            
            obfuscated_count = sum(1 for s in scripts if s.get('obfuscation_detected'))
            if obfuscated_count > 0:
                print_error(f"Warning: {obfuscated_count} obfuscated JavaScript block(s) detected")
        else:
            print_info("No JavaScript found in PDF")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@extract.command('attachments')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output-dir', '-o', type=click.Path(path_type=Path), required=True, help='Output directory for attachments')
@click.option('--no-metadata', is_flag=True, help='Do not save metadata files')
@click.option('--password', type=str, help='Password for encrypted PDFs')
def extract_attachments_cmd(input_pdf: Path, output_dir: Path, no_metadata: bool, password: Optional[str]):
    """Extract embedded files from PDF"""
    try:
        print_header("Attachment Extraction", str(input_pdf))
        
        attachments = extract_attachments(
            input_pdf,
            output_dir,
            preserve_metadata=not no_metadata,
            password=password,
        )
        
        if attachments:
            print_success(f"Extracted {len(attachments)} embedded file(s) to {output_dir}")
            
            from rich.table import Table
            from rich.console import Console
            
            console = Console()
            table = Table(title="Extracted Attachments")
            table.add_column("Index", style="cyan")
            table.add_column("Filename", style="green")
            table.add_column("Source", style="yellow")
            table.add_column("Type", style="magenta")
            table.add_column("Size", style="blue")
            
            for i, att in enumerate(attachments):
                size_kb = att['size'] / 1024
                size_str = f"{size_kb:.1f} KB" if size_kb > 1 else f"{att['size']} B"
                
                table.add_row(
                    str(i),
                    att['filename'][:40] + ('...' if len(att['filename']) > 40 else ''),
                    att['source'][:30] + ('...' if len(att['source']) > 30 else ''),
                    att['detected_type'],
                    size_str
                )
            
            console.print(table)
            
            total_size = sum(att['size'] for att in attachments)
            print_info(f"Total size: {total_size / 1024:.1f} KB")
        else:
            print_info("No embedded files found in PDF")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@extract.command('hidden')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for hidden data report')
@click.option('--password', type=str, help='Password for encrypted PDFs')
def extract_hidden_cmd(input_pdf: Path, output: Optional[Path], password: Optional[str]):
    """Find and extract hidden data from PDF"""
    try:
        print_header("Hidden Data Extraction", str(input_pdf))
        
        findings = extract_hidden_data(
            input_pdf,
            output_file=output,
            password=password,
        )
        
        if findings:
            print_success(f"Found {len(findings)} hidden data occurrence(s)")
            
            if output:
                print_info(f"Report saved to: {output}")
            
            from rich.table import Table
            from rich.console import Console
            
            console = Console()
            table = Table(title="Hidden Data Findings")
            table.add_column("Type", style="cyan")
            table.add_column("Location", style="green")
            table.add_column("Method", style="yellow")
            table.add_column("Preview", style="magenta")
            
            by_type = {}
            for finding in findings:
                by_type.setdefault(finding['type'], []).append(finding)
            
            for type_name, type_findings in by_type.items():
                for finding in type_findings[:10]:
                    preview = str(finding['data'])[:50]
                    if len(str(finding['data'])) > 50:
                        preview += '...'
                    
                    table.add_row(
                        finding['type'].replace('_', ' ').title(),
                        finding['location'],
                        finding['method'][:40],
                        preview
                    )
            
            console.print(table)
            
            print_info("\nFindings by type:")
            for type_name, type_findings in by_type.items():
                click.echo(f"  {type_name.replace('_', ' ').title()}: {len(type_findings)}")
        else:
            print_info("No hidden data found in PDF")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@extract.command('forms')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output-dir', '-o', type=click.Path(path_type=Path), help='Output directory for form data')
@click.option('--export-fdf', is_flag=True, help='Export form data in FDF format')
@click.option('--password', type=str, help='Password for encrypted PDFs')
def extract_forms_cmd(input_pdf: Path, output_dir: Optional[Path], export_fdf: bool, password: Optional[str]):
    """Extract form fields and data from PDF"""
    try:
        print_header("Form Extraction", str(input_pdf))
        
        result = extract_forms(
            input_pdf,
            output_dir=output_dir,
            export_fdf=export_fdf,
            password=password,
        )
        
        if not result['has_forms']:
            print_info("No forms found in PDF")
            return
        
        print_success(f"Extracted {result['total_fields']} form field(s)")
        
        if output_dir:
            print_info(f"Form data saved to: {output_dir}")
        
        if result['acroform_fields']:
            from rich.table import Table
            from rich.console import Console
            
            console = Console()
            table = Table(title="Form Fields")
            table.add_column("Name", style="cyan")
            table.add_column("Type", style="green")
            table.add_column("Value", style="yellow")
            table.add_column("Flags", style="magenta")
            
            for field in result['acroform_fields'][:20]:
                flags = []
                if field.get('flags'):
                    flags = [k for k, v in field['flags'].items() if v]
                
                value = field.get('value', '(none)')
                if value and len(str(value)) > 30:
                    value = str(value)[:30] + '...'
                
                table.add_row(
                    field['name'][:30],
                    field['type'],
                    str(value) or '(none)',
                    ', '.join(flags[:3]) if flags else ''
                )
            
            console.print(table)
            
            if len(result['acroform_fields']) > 20:
                print_info(f"Showing first 20 of {result['total_fields']} fields")
            
            hidden_count = sum(1 for f in result['acroform_fields'] if f.get('hidden'))
            if hidden_count > 0:
                print_error(f"Warning: {hidden_count} hidden field(s) detected")
        
        if result['total_scripts'] > 0:
            print_error(f"Warning: {result['total_scripts']} JavaScript block(s) found in form fields")
        
        if result['xfa_data'] and result['xfa_data']['has_xfa']:
            print_info("XFA (XML Forms Architecture) data detected")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@extract.command('revisions')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output-dir', '-o', type=click.Path(path_type=Path), help='Output directory to export revisions')
@click.option('--export-all', is_flag=True, help='Export all revisions as separate PDFs')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--password', type=str, help='Password for encrypted PDFs')
def extract_revisions_cmd(
    input_pdf: Path, 
    output_dir: Optional[Path], 
    export_all: bool, 
    output_format: str,
    password: Optional[str]
):
    """Extract and analyze PDF revision timeline"""
    try:
        print_header("Revision Timeline Extraction", str(input_pdf))
        
        with PDFDocument.open(input_pdf, password=password) as pdf_doc:
            extractor = RevisionExtractor(pdf_doc)
            revisions = extractor.extract_all_revisions()
            
            if output_format == 'json':
                result = {
                    'file': str(input_pdf),
                    'total_revisions': len(revisions),
                    'revisions': [r.to_dict() for r in revisions]
                }
                print(json.dumps(result, indent=2))
            else:
                timeline = extractor.generate_timeline(revisions)
                print(timeline)
            
            if export_all:
                if not output_dir:
                    output_dir = Path(f"{input_pdf.stem}_revisions")
                
                print_info(f"\nExporting all revisions to {output_dir}")
                
                with ProgressTracker(len(revisions), "Exporting revisions") as progress:
                    for revision in revisions:
                        output_path = output_dir / f"revision_{revision.revision_number}.pdf"
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        extractor.export_revision(revision.revision_number, output_path)
                        progress.update(1)
                
                print_success(f"Exported {len(revisions)} revision(s) to {output_dir}")
            
            if len(revisions) > 1:
                suspicious_count = sum(
                    len(r.suspicious_activities) 
                    for r in revisions
                )
                
                if suspicious_count > 0:
                    print_error(f"\n⚠ Warning: {suspicious_count} suspicious activity/activities detected")
            else:
                print_info("\nNo incremental updates found - PDF has only initial revision")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@extract.command('web')
@click.option('--config', '-c', type=click.Path(exists=True, path_type=Path), help='Configuration file (TOML)')
@click.option('--url', type=str, help='Base URL to extract from')
@click.option('--pages', type=str, default='1-100', help='Page range (e.g., "1-10", "1,3,5-7")')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output PDF file')
@click.option('--title', type=str, default='Web Extraction', help='PDF title')
@click.option('--auto-discover', is_flag=True, help='Auto-discover available pages')
@click.option('--browser-cookies', type=click.Choice(['firefox', 'chrome', 'edge', 'chromium']), help='Load cookies from browser')
@click.option('--cookie-domain', type=str, help='Domain filter for browser cookies')
@click.option('--max-retries', type=int, default=5, help='Maximum retries per page')
@click.option('--rate-limit', type=int, default=2000, help='Rate limit in milliseconds')
@click.option('--min-size', type=int, default=1500, help='Minimum image size in bytes')
def extract_web_cmd(
    config: Optional[Path],
    url: Optional[str],
    pages: str,
    output: Optional[Path],
    title: str,
    auto_discover: bool,
    browser_cookies: Optional[str],
    cookie_domain: Optional[str],
    max_retries: int,
    rate_limit: int,
    min_size: int
):
    """
    Extract paginated web content to PDF
    
    Download paginated images or content from web APIs and compile them into
    a PDF document. Useful for documentation downloads, writeup archives,
    and API-based content extraction.
    
    \b
    Configuration File (TOML):
        [web_extraction]
        base_url = "https://api.example.com/writeups"
        page_param = "page"
        pages = "1-50"
        url_template = "https://api.example.com/writeup/{page}.png"
        title = "Documentation Archive"
        
        [retry]
        max_retries = 5
        retry_delay_ms = 3000
        exponential_backoff = true
        timeout_seconds = 30
        
        [rate_limit]
        base_delay_ms = 2000
        jitter_ms = 1000
        
        [cookies]
        session_id = "your_session_cookie"
        auth_token = "your_auth_token"
    
    \b
    Examples:
        # Using config file
        pdfscalpel extract web --config scrape-config.toml
        
        # Direct URL with page range
        pdfscalpel extract web --url "https://api.example.com/page" --pages "1-20" -o output.pdf
        
        # Auto-discover pages with browser cookies
        pdfscalpel extract web --url "https://api.example.com/page" --auto-discover --browser-cookies firefox -o output.pdf
        
        # With custom rate limiting
        pdfscalpel extract web --url "https://api.example.com/page" --pages "1-10" --rate-limit 5000 -o output.pdf
    """
    try:
        from pdfscalpel.extract.web import WebExtractionConfig, WebPageExtractor, parse_page_range
        from pdfscalpel.core.http_client import RetryConfig, RateLimitConfig
        
        print_header("Web Content Extraction", "")
        
        if config:
            if sys.version_info >= (3, 11):
                import tomllib
            else:
                try:
                    import tomli as tomllib
                except ImportError:
                    print_error("tomli is required for Python < 3.11. Install with: pip install tomli")
                    sys.exit(1)
            
            print_info(f"Loading configuration from: {config}")
            with open(config, 'rb') as f:
                config_data = tomllib.load(f)
            
            web_config_data = config_data.get('web_extraction', {})
            retry_data = config_data.get('retry', {})
            rate_limit_data = config_data.get('rate_limit', {})
            cookies_data = config_data.get('cookies', {})
            
            retry_config = RetryConfig(**retry_data) if retry_data else RetryConfig()
            rate_limit_config = RateLimitConfig(**rate_limit_data) if rate_limit_data else RateLimitConfig()
            
            web_config = WebExtractionConfig(
                base_url=web_config_data.get('base_url', url or ''),
                page_param=web_config_data.get('page_param', 'page'),
                pages=web_config_data.get('pages', pages),
                url_template=web_config_data.get('url_template'),
                retry_config=retry_config,
                rate_limit_config=rate_limit_config,
                cookies=cookies_data if cookies_data else None,
                headers=web_config_data.get('headers'),
                output_file=Path(web_config_data.get('output_file', output or 'web_extraction.pdf')),
                title=web_config_data.get('title', title),
                min_image_size=web_config_data.get('min_image_size', min_size),
                auto_discover=web_config_data.get('auto_discover', auto_discover),
                cookies_from_browser=web_config_data.get('cookies_from_browser', browser_cookies),
                browser_domain=web_config_data.get('browser_domain', cookie_domain)
            )
        else:
            if not url:
                print_error("Error: --url is required when not using --config")
                print_info("Use --config for full configuration or --url for simple extraction")
                sys.exit(1)
            
            retry_config = RetryConfig(max_retries=max_retries)
            rate_limit_config = RateLimitConfig(base_delay_ms=rate_limit)
            
            web_config = WebExtractionConfig(
                base_url=url,
                pages=pages,
                retry_config=retry_config,
                rate_limit_config=rate_limit_config,
                output_file=output or Path('web_extraction.pdf'),
                title=title,
                min_image_size=min_size,
                auto_discover=auto_discover,
                cookies_from_browser=browser_cookies,
                browser_domain=cookie_domain
            )
        
        print_info(f"Target URL: {web_config.base_url}")
        print_info(f"Pages: {web_config.pages}")
        print_info(f"Output: {web_config.output_file}")
        
        if web_config.cookies_from_browser:
            print_info(f"Browser cookies: {web_config.cookies_from_browser}")
        
        if web_config.auto_discover:
            print_info("Auto-discovery mode enabled")
        
        extractor = WebPageExtractor(web_config)
        output_file = extractor.extract()
        
        stats = extractor.stats
        http_stats = extractor.client.get_stats()
        
        print_success(f"\nExtraction complete!")
        print_info(f"Output file: {output_file}")
        print_info(f"Pages downloaded: {stats['downloaded']}/{stats['total_pages']}")
        
        if stats['failed'] > 0:
            print_warning(f"Failed pages: {stats['failed']}")
        if stats['retried'] > 0:
            print_info(f"Retried pages: {stats['retried']}")
        
        print_info(f"\nHTTP Statistics:")
        print_info(f"  Total requests: {http_stats['total_requests']}")
        print_info(f"  Successful: {http_stats['successful']}")
        print_info(f"  Failed: {http_stats['failed']}")
        if http_stats['timeouts'] > 0:
            print_warning(f"  Timeouts: {http_stats['timeouts']}")
        if http_stats['gateway_errors'] > 0:
            print_warning(f"  Gateway errors: {http_stats['gateway_errors']}")
    
    except ImportError as e:
        print_error(f"Missing dependency: {e}")
        print_info("Install required packages: pip install httpx browser-cookie3 reportlab Pillow")
        sys.exit(1)
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@mutate.command('watermark')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.option('--add', type=str, help='Add watermark with specified text')
@click.option('--remove', type=click.Choice([
    'auto', 'crop', 'ocg', 'xobject', 'annotation', 'content_stream_text',
    'content_stream_graphics', 'background', 'zorder', 'invisible_text',
    'transparency', 'inpaint', 'pattern_match', 'ghostscript', 'forensic_metadata', 'all'
]), help='Remove watermark using specified method')
@click.option('--remove-all', is_flag=True, help='Try all removal methods until one succeeds')
@click.option('--pattern', type=str, help='Text pattern for pattern-based removal')
@click.option('--crop-top', type=float, default=0.5, help='Crop top (inches)')
@click.option('--crop-bottom', type=float, default=0.5, help='Crop bottom (inches)')
@click.option('--crop-left', type=float, default=0.5, help='Crop left (inches)')
@click.option('--crop-right', type=float, default=0.5, help='Crop right (inches)')
@click.option('--position', type=click.Choice(['center', 'top', 'bottom']), default='center', help='Watermark position')
@click.option('--font-size', type=int, default=48, help='Font size for text watermark')
@click.option('--opacity', type=float, default=0.3, help='Watermark opacity (0-1)')
@click.option('--rotation', type=int, default=45, help='Watermark rotation angle')
@click.option('--color', type=str, default='0.5,0.5,0.5', help='RGB color (comma-separated, 0-1 each)')
def watermark_cmd(
    input_pdf: Path,
    output_pdf: Path,
    add: Optional[str],
    remove: Optional[str],
    remove_all: bool,
    pattern: Optional[str],
    crop_top: float,
    crop_bottom: float,
    crop_left: float,
    crop_right: float,
    position: str,
    font_size: int,
    opacity: float,
    rotation: int,
    color: str
):
    """Add or remove watermarks from PDF"""
    from pdfscalpel.mutate.watermark import WatermarkRemover, WatermarkAdder, RemovalMethod
    
    try:
        if add:
            print_header("Adding Watermark", str(input_pdf))
            
            color_tuple = tuple(float(c) for c in color.split(','))
            if len(color_tuple) != 3:
                raise ValueError("Color must be 3 comma-separated values (R,G,B)")
            
            adder = WatermarkAdder(input_pdf)
            success = adder.add_text(
                output_pdf,
                text=add,
                position=position,
                font_size=font_size,
                opacity=opacity,
                rotation=rotation,
                color=color_tuple
            )
            
            if success:
                print_success(f"Watermark added: {output_pdf}")
            else:
                print_error("Failed to add watermark")
                sys.exit(1)
        
        elif remove or remove_all:
            print_header("Removing Watermark", str(input_pdf))
            
            crop_params = {
                'top': crop_top,
                'bottom': crop_bottom,
                'left': crop_left,
                'right': crop_right
            }
            
            remover = WatermarkRemover(input_pdf)
            
            if remove:
                method = RemovalMethod(remove)
            else:
                method = RemovalMethod.ALL
            
            result = remover.remove(
                output_pdf,
                method=method,
                watermark_pattern=pattern,
                crop_params=crop_params,
                try_all=remove_all
            )
            
            if result.success:
                print_success(f"Method: {result.method_used}")
                print_success(f"Pages processed: {result.pages_processed}")
                print_success(f"Watermarks removed: {result.watermarks_removed}")
                print_success(f"Output: {output_pdf}")
                if result.message:
                    print_info(f"Details: {result.message}")
            else:
                print_error(f"Removal failed: {result.message}")
                sys.exit(1)
        
        else:
            print_error("Must specify --add or --remove")
            sys.exit(1)
    
    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)


@mutate.command('encrypt')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.option('--password', type=str, required=True, help='User password to open the PDF')
@click.option('--owner-password', type=str, help='Owner password for full permissions (defaults to user password)')
@click.option('--level', type=click.Choice(['rc4_40', 'rc4_128', 'aes_128', 'aes_256']), default='aes_256', help='Encryption level')
@click.option('--allow-print/--no-print', default=True, help='Allow printing')
@click.option('--allow-modify/--no-modify', default=False, help='Allow content modification')
@click.option('--allow-extract/--no-extract', default=True, help='Allow text/image extraction')
@click.option('--allow-annotate/--no-annotate', default=True, help='Allow annotations')
@click.option('--allow-form/--no-form', default=True, help='Allow form filling')
@click.option('--allow-accessibility/--no-accessibility', default=True, help='Allow accessibility features')
@click.option('--allow-assemble/--no-assemble', default=False, help='Allow document assembly')
@click.option('--allow-print-highres/--no-print-highres', default=True, help='Allow high-resolution printing')
def encrypt_cmd(
    input_pdf: Path,
    output_pdf: Path,
    password: str,
    owner_password: Optional[str],
    level: str,
    allow_print: bool,
    allow_modify: bool,
    allow_extract: bool,
    allow_annotate: bool,
    allow_form: bool,
    allow_accessibility: bool,
    allow_assemble: bool,
    allow_print_highres: bool
):
    """Add password protection and encryption to PDF"""
    from pdfscalpel.mutate.encryption import encrypt_pdf
    
    try:
        print_header("Encrypting PDF", str(input_pdf))
        print_info(f"Encryption level: {level.upper()}")
        
        result = encrypt_pdf(
            input_path=input_pdf,
            output_path=output_pdf,
            password=password,
            owner_password=owner_password,
            level=level,
            allow_print=allow_print,
            allow_modify=allow_modify,
            allow_extract=allow_extract,
            allow_annotate=allow_annotate,
            allow_form=allow_form,
            allow_accessibility=allow_accessibility,
            allow_assemble=allow_assemble,
            allow_print_highres=allow_print_highres,
        )
        
        if result['success']:
            print_success(f"PDF encrypted successfully: {output_pdf}")
            print_info(f"Algorithm: {result['encryption_level'].upper()}")
            print_info(f"Revision: R{result['revision']}")
            
            if get_config().verbose:
                from rich.table import Table
                from rich.console import Console
                
                console = Console()
                table = Table(title="Permissions")
                table.add_column("Permission", style="cyan")
                table.add_column("Allowed", style="green")
                
                for perm, allowed in result['permissions'].items():
                    table.add_row(perm.replace('_', ' ').title(), str(allowed))
                
                console.print(table)
        else:
            print_error("Failed to encrypt PDF")
            sys.exit(1)
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@mutate.command('decrypt')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.option('--password', type=str, help='Password to open the encrypted PDF')
def decrypt_cmd(
    input_pdf: Path,
    output_pdf: Path,
    password: Optional[str]
):
    """Remove encryption and password protection from PDF"""
    from pdfscalpel.mutate.encryption import decrypt_pdf
    
    try:
        print_header("Decrypting PDF", str(input_pdf))
        
        result = decrypt_pdf(
            input_path=input_pdf,
            output_path=output_pdf,
            password=password,
        )
        
        if result['success']:
            if result['was_encrypted']:
                print_success(f"PDF decrypted successfully: {output_pdf}")
                if result['password_required']:
                    print_info("Password was required and accepted")
                else:
                    print_info("No password was required")
            else:
                print_info(f"PDF was not encrypted, saved copy to: {output_pdf}")
        else:
            print_error("Failed to decrypt PDF")
            sys.exit(1)
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@mutate.command('merge')
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.argument('input_pdfs', nargs=-1, type=click.Path(exists=True, path_type=Path), required=True)
@click.option('--no-bookmarks', is_flag=True, help='Do not preserve bookmarks from source PDFs')
def merge_cmd(
    output_pdf: Path,
    input_pdfs: tuple,
    no_bookmarks: bool,
):
    """Merge multiple PDFs into one"""
    from pdfscalpel.mutate.pages import merge_pdfs
    
    try:
        print_header("Merging PDFs", f"{len(input_pdfs)} files")
        
        for i, pdf_path in enumerate(input_pdfs, 1):
            print_info(f"  {i}. {pdf_path}")
        
        result = merge_pdfs(
            pdf_paths=list(input_pdfs),
            output_path=output_pdf,
            preserve_bookmarks=not no_bookmarks,
        )
        
        print_success(f"Merged {len(input_pdfs)} PDFs to: {output_pdf}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@mutate.command('extract-pages')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.argument('pages', type=str)
def extract_pages_cmd(
    input_pdf: Path,
    output_pdf: Path,
    pages: str,
):
    """Extract specific pages from PDF (e.g., '1-5,7,9-12')"""
    from pdfscalpel.mutate.pages import extract_pages
    
    try:
        print_header("Extracting Pages", str(input_pdf))
        print_info(f"Pages: {pages}")
        
        result = extract_pages(
            input_path=input_pdf,
            output_path=output_pdf,
            page_ranges=pages,
        )
        
        print_success(f"Extracted pages to: {output_pdf}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@mutate.command('delete-pages')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.argument('pages', type=str)
def delete_pages_cmd(
    input_pdf: Path,
    output_pdf: Path,
    pages: str,
):
    """Delete specific pages from PDF (e.g., '1-5,7,9-12')"""
    from pdfscalpel.mutate.pages import delete_pages
    
    try:
        print_header("Deleting Pages", str(input_pdf))
        print_info(f"Pages to delete: {pages}")
        
        result = delete_pages(
            input_path=input_pdf,
            output_path=output_pdf,
            pages_to_delete=pages,
        )
        
        print_success(f"Deleted pages, saved to: {output_pdf}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@mutate.command('rotate-pages')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.argument('rotation', type=int)
@click.option('--pages', type=str, help='Pages to rotate (e.g., "1-5,7"). Default: all pages')
def rotate_pages_cmd(
    input_pdf: Path,
    output_pdf: Path,
    rotation: int,
    pages: Optional[str],
):
    """Rotate pages in PDF (rotation: 90, 180, or 270 degrees)"""
    from pdfscalpel.mutate.pages import rotate_pages
    
    try:
        print_header("Rotating Pages", str(input_pdf))
        print_info(f"Rotation: {rotation} degrees")
        if pages:
            print_info(f"Pages: {pages}")
        else:
            print_info("Pages: all")
        
        result = rotate_pages(
            input_path=input_pdf,
            output_path=output_pdf,
            rotation=rotation,
            page_ranges=pages,
        )
        
        print_success(f"Rotated pages, saved to: {output_pdf}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@mutate.command('add-bookmarks')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.option('--auto', is_flag=True, help='Auto-detect headings from document')
@click.option('--pattern-only', is_flag=True, help='Use pattern matching only (faster, less accurate)')
@click.option('--patterns', type=str, help='Comma-separated regex patterns')
def add_bookmarks_cmd(
    input_pdf: Path,
    output_pdf: Path,
    auto: bool,
    pattern_only: bool,
    patterns: Optional[str],
):
    """Add bookmarks/table of contents to PDF"""
    from pdfscalpel.mutate.bookmarks import add_bookmarks
    
    try:
        print_header("Adding Bookmarks", str(input_pdf))
        
        if not auto:
            print_error("Manual bookmark specification not yet implemented via CLI")
            print_info("Use --auto to auto-detect headings")
            sys.exit(1)
        
        pattern_list = None
        if patterns:
            pattern_list = [p.strip() for p in patterns.split(',')]
        
        result = add_bookmarks(
            input_path=input_pdf,
            output_path=output_pdf,
            auto_detect=True,
            patterns=pattern_list,
            use_font_analysis=not pattern_only,
        )
        
        print_success(f"Added bookmarks to: {output_pdf}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@mutate.command('remove-bookmarks')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
def remove_bookmarks_cmd(
    input_pdf: Path,
    output_pdf: Path,
):
    """Remove all bookmarks from PDF"""
    from pdfscalpel.mutate.bookmarks import remove_bookmarks
    
    try:
        print_header("Removing Bookmarks", str(input_pdf))
        
        result = remove_bookmarks(
            input_path=input_pdf,
            output_path=output_pdf,
        )
        
        print_success(f"Removed bookmarks, saved to: {output_pdf}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@mutate.command('redact')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.option('--pattern', type=str, help='Regex pattern or preset (ssn, phone, email, credit_card)')
@click.option('--replacement', type=str, default='[REDACTED]', help='Replacement text')
@click.option('--list-patterns', is_flag=True, help='List available preset patterns')
def redact_cmd(
    input_pdf: Path,
    output_pdf: Path,
    pattern: Optional[str],
    replacement: str,
    list_patterns: bool,
):
    """Redact text matching a pattern (WARNING: basic text replacement only)"""
    from pdfscalpel.mutate.redaction import redact_text_pattern, list_redaction_patterns
    
    try:
        if list_patterns:
            print_header("Available Redaction Patterns", "")
            patterns = list_redaction_patterns()
            for name, regex in patterns.items():
                print_info(f"{name:15s} : {regex}")
            return
        
        if not pattern:
            print_error("Error: --pattern is required")
            print_info("Use --list-patterns to see available presets")
            sys.exit(1)
        
        print_header("Redacting Text", str(input_pdf))
        print_info(f"Pattern: {pattern}")
        print_warning("WARNING: Basic text redaction - not secure for images or advanced PDFs")
        
        result_path, count = redact_text_pattern(
            input_path=input_pdf,
            output_path=output_pdf,
            pattern=pattern,
            replacement=replacement,
        )
        
        print_success(f"Redacted {count} occurrences, saved to: {output_pdf}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@mutate.command('optimize')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.option('--level', type=click.Choice(['fast', 'balanced', 'maximum']), default='balanced', help='Compression level')
@click.option('--no-remove-unused', is_flag=True, help='Skip removing unused objects')
@click.option('--linearize', is_flag=True, help='Linearize for fast web viewing')
def optimize_cmd(
    input_pdf: Path,
    output_pdf: Path,
    level: str,
    no_remove_unused: bool,
    linearize: bool,
):
    """Optimize and compress PDF"""
    from pdfscalpel.mutate.optimize import optimize_pdf
    
    try:
        print_header("Optimizing PDF", str(input_pdf))
        print_info(f"Compression level: {level}")
        if not no_remove_unused:
            print_info("Removing unused objects: enabled")
        if linearize:
            print_info("Linearization: enabled")
        
        result = optimize_pdf(
            input_path=input_pdf,
            output_path=output_pdf,
            level=level,
            remove_unused=not no_remove_unused,
            linearize=linearize,
        )
        
        print_success(f"Optimized PDF saved to: {output_pdf}")
        print_info(f"Original size: {result.original_size:,} bytes")
        print_info(f"Optimized size: {result.optimized_size:,} bytes")
        print_info(f"Size reduction: {result.size_reduction_percent:.1f}%")
        print_info(f"Operations: {', '.join(result.operations_performed)}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@mutate.command('ocr')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.argument('output_pdf', type=click.Path(path_type=Path))
@click.option('--lang', type=str, default='eng', help='OCR language code (eng, spa, fra, deu, etc.)')
@click.option('--jobs', type=int, help='Number of CPU cores to use (default: auto-detect)')
@click.option('--no-deskew', is_flag=True, help='Skip deskewing')
@click.option('--force-ocr', is_flag=True, help='Force OCR even if text already exists')
@click.option('--no-skip-text', is_flag=True, help='OCR all pages, even those with existing text')
@click.option('--no-optimize', is_flag=True, help='Skip optimization/compression')
@click.option('--output-type', type=click.Choice(['pdf', 'pdfa', 'pdfa-1', 'pdfa-2', 'pdfa-3']), default='pdfa', help='Output PDF type')
@click.option('--no-progress', is_flag=True, help='Hide progress bar')
@click.option('--list-langs', is_flag=True, help='List available Tesseract languages and exit')
def ocr_cmd(
    input_pdf: Path,
    output_pdf: Path,
    lang: str,
    jobs: Optional[int],
    no_deskew: bool,
    force_ocr: bool,
    no_skip_text: bool,
    no_optimize: bool,
    output_type: str,
    no_progress: bool,
    list_langs: bool,
):
    """
    Run OCR on PDF to make it searchable
    
    Converts scanned PDF images to searchable text using Tesseract OCR.
    Automatically detects existing text and skips already-processed pages.
    
    Examples:
        pdfscalpel mutate ocr scanned.pdf output.pdf
        pdfscalpel mutate ocr document.pdf searchable.pdf --lang fra --jobs 8
        pdfscalpel mutate ocr scan.pdf out.pdf --force-ocr --no-optimize
        pdfscalpel mutate ocr --list-langs
    """
    from pdfscalpel.mutate.ocr import run_ocr, check_ocr_dependencies, get_available_languages, OCRError
    from pdfscalpel.core.constants import DEFAULT_OCR_JOBS
    
    try:
        if list_langs:
            print_header("Available Tesseract Languages", "")
            
            if not check_ocr_dependencies(verbose=False):
                print_error("Tesseract OCR is not installed")
                print_info("\nInstallation instructions:")
                print_info("  Windows: https://github.com/UB-Mannheim/tesseract/wiki")
                print_info("  Linux/WSL: sudo apt install tesseract-ocr")
                sys.exit(1)
            
            languages = get_available_languages()
            
            if languages:
                print_success(f"Found {len(languages)} language(s):")
                for i, lang_code in enumerate(languages, 1):
                    print(f"  {i:2}. {lang_code}")
            else:
                print_warning("Could not retrieve language list")
            
            return
        
        print_header("PDF OCR", str(input_pdf))
        
        if not check_ocr_dependencies(verbose=False):
            print_error("Missing OCR dependencies")
            print_info("\nRequired:")
            print_info("  - ocrmypdf: pip install ocrmypdf>=15.0.0")
            print_info("  - Tesseract OCR:")
            print_info("      Windows: https://github.com/UB-Mannheim/tesseract/wiki")
            print_info("      Linux/WSL: sudo apt install tesseract-ocr")
            sys.exit(1)
        
        if jobs is None:
            jobs = DEFAULT_OCR_JOBS
        
        skip_text = not no_skip_text
        if force_ocr and skip_text:
            skip_text = False
        
        print_info(f"Language: {lang}")
        print_info(f"CPU cores: {jobs}")
        print_info(f"Deskew: {not no_deskew}")
        print_info(f"Force OCR: {force_ocr}")
        print_info(f"Skip text pages: {skip_text}")
        print_info(f"Optimize: {not no_optimize}")
        print_info(f"Output type: {output_type}")
        
        run_ocr(
            input_path=input_pdf,
            output_path=output_pdf,
            language=lang,
            jobs=jobs,
            deskew=not no_deskew,
            force_ocr=force_ocr,
            skip_text=skip_text,
            optimize=not no_optimize,
            output_type=output_type,
            progress_bar=not no_progress,
        )
        
        print_success(f"OCR complete: {output_pdf}")
        
        original_size = input_pdf.stat().st_size
        output_size = output_pdf.stat().st_size
        
        print_info(f"Original size: {original_size:,} bytes")
        print_info(f"Output size: {output_size:,} bytes")
        
        if output_size < original_size:
            reduction = ((original_size - output_size) / original_size) * 100
            print_info(f"Size reduction: {reduction:.1f}%")
        elif output_size > original_size:
            increase = ((output_size - original_size) / original_size) * 100
            print_warning(f"Size increase: {increase:.1f}% (searchable text added)")
    
    except OCRError as e:
        print_error(f"OCR Error: {e}")
        sys.exit(1)
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@solve.command('password')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--ctf-mode', is_flag=True, required=True, help='CTF mode (required for password cracking)')
@click.option('--challenge-id', type=str, help='Challenge ID for audit trail')
@click.option('--wordlist', '-w', type=click.Path(exists=True, path_type=Path), help='Dictionary wordlist file')
@click.option('--brute-charset', type=str, help='Brute force charset (alphanum, numeric, hex, lower, upper, ascii, or custom)')
@click.option('--brute-min', type=int, default=1, help='Minimum password length for brute force')
@click.option('--brute-max', type=int, default=8, help='Maximum password length for brute force')
@click.option('--mask', type=str, help='Mask pattern (? = letter, # = digit, @ = symbol, * = alphanum)')
@click.option('--use-hashcat', is_flag=True, help='Use Hashcat GPU acceleration if available')
@click.option('--use-john', is_flag=True, help='Use John the Ripper if available')
@click.option('--max-time', type=int, help='Maximum time in seconds for external tools')
@click.option('--intelligent-only', is_flag=True, help='Only try intelligent CTF patterns (fast)')
@click.option('--workers', type=int, help='Number of worker processes (default: CPU count)')
@click.option('--benchmark', is_flag=True, help='Run benchmark mode to measure cracking speed')
@click.option('--assess-only', is_flag=True, help='Only assess crackability, do not attempt cracking')
def solve_password_cmd(
    input_pdf: Path,
    ctf_mode: bool,
    challenge_id: Optional[str],
    wordlist: Optional[Path],
    brute_charset: Optional[str],
    brute_min: int,
    brute_max: int,
    mask: Optional[str],
    use_hashcat: bool,
    use_john: bool,
    max_time: Optional[int],
    intelligent_only: bool,
    workers: Optional[int],
    benchmark: bool,
    assess_only: bool,
):
    """Crack PDF password (CTF and authorized security research only)
    
    Examples:
        pdfscalpel solve password encrypted.pdf --ctf-mode --challenge-id ctf2024
        pdfscalpel solve password file.pdf --ctf-mode --wordlist rockyou.txt
        pdfscalpel solve password file.pdf --ctf-mode --mask "password###"
        pdfscalpel solve password file.pdf --ctf-mode --brute-charset numeric --brute-max 6
        pdfscalpel solve password file.pdf --ctf-mode --benchmark
        pdfscalpel solve password file.pdf --ctf-mode --assess-only
    """
    from pdfscalpel.solve.password import PasswordCracker, assess_crackability
    from pdfscalpel.solve import ctf_mode as ctf_mode_context
    
    try:
        if assess_only:
            print_header("Password Crackability Assessment", str(input_pdf))
            
            assessment = assess_crackability(str(input_pdf))
            
            if not assessment.get('encrypted'):
                print_success("PDF is not encrypted")
                return
            
            from rich.table import Table
            from rich.console import Console
            
            console_rich = Console()
            table = Table(title="Crackability Assessment")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Encryption Algorithm", assessment['algorithm'])
            table.add_row("R Value", str(assessment['r_value']))
            table.add_row("Key Length", f"{assessment['key_length']} bytes")
            table.add_row("Difficulty", assessment['difficulty'])
            table.add_row("Estimated Time", assessment['estimated_time'])
            
            console_rich.print(table)
            
            print_info("\nRecommendation:")
            click.echo(f"  {assessment['recommendation']}")
            
            return
        
        print_header("PDF Password Cracking", str(input_pdf))
        
        if challenge_id:
            print_info(f"Challenge ID: {challenge_id}")
        else:
            print_warning("No challenge ID provided (best practice: use --challenge-id)")
        
        with ctf_mode_context(
            challenge_id=challenge_id,
            operation_name="password_cracking",
            require_challenge_id=False
        ) as ctx:
            cracker = PasswordCracker(
                pdf_path=str(input_pdf),
                ctf_mode=ctf_mode,
                challenge_id=challenge_id,
                num_workers=workers,
                ctf_context=ctx
            )
            
            print_info(f"Encryption: {cracker.params.algorithm} (R={cracker.params.R})")
            print_info(f"Workers: {cracker.num_workers}")
            
            if benchmark:
                print_info("Running benchmark mode...")
                results = cracker.benchmark()
                return
            
            password = cracker.crack(
                wordlist=str(wordlist) if wordlist else None,
                brute_charset=brute_charset,
                brute_min=brute_min,
                brute_max=brute_max,
                mask=mask,
                use_hashcat=use_hashcat,
                use_john=use_john,
                max_time=max_time,
                intelligent_only=intelligent_only
            )
            
            if password is not None:
                print_success(f"Password cracked successfully!")
                print_info(f"Password: {password}")
            else:
                print_error("Password not found with given parameters")
                print_info("\nTry:")
                print_info("  - Adding a wordlist (--wordlist)")
                print_info("  - Using a mask if you know the pattern (--mask)")
                print_info("  - Enabling GPU acceleration (--use-hashcat)")
                print_info("  - Using John the Ripper (--use-john)")
                print_info("  - Running assessment mode (--assess-only)")
                sys.exit(1)
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print_warning("\nPassword cracking interrupted by user")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@solve.command('flag-hunt')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--patterns', type=str, multiple=True, help='Built-in pattern types: ctf, md5, sha1, sha256, sha512, all')
@click.option('--custom-pattern', type=str, multiple=True, help='Custom regex patterns (can be specified multiple times)')
@click.option('--report', '-r', type=click.Path(path_type=Path), help='Output report file')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--min-confidence', type=float, default=0.0, help='Minimum confidence threshold (0.0-1.0)')
def solve_flag_hunt_cmd(
    input_pdf: Path,
    patterns: tuple,
    custom_pattern: tuple,
    report: Optional[Path],
    format: str,
    min_confidence: float
):
    """Hunt for flags across all PDF layers"""
    from pdfscalpel.solve.flag_hunter import FlagHunter
    from rich.table import Table
    from rich.console import Console
    
    console = Console()
    
    try:
        print_header("Flag Hunter", str(input_pdf))
        
        with PDFDocument.open(input_pdf) as pdf_doc:
            builtin_patterns = list(patterns) if patterns else None
            custom_patterns = list(custom_pattern) if custom_pattern else None
            
            hunter = FlagHunter(
                pdf_doc,
                custom_patterns=custom_patterns,
                builtin_patterns=builtin_patterns
            )
            
            print_info("Hunting for flags...")
            candidates = hunter.hunt()
            
            filtered_candidates = [
                c for c in candidates
                if c.confidence >= min_confidence
            ]
            
            if not filtered_candidates:
                print_info("No flag candidates found")
                return
            
            print_success(f"Found {len(filtered_candidates)} flag candidate(s)")
            
            if format == 'json':
                result = {
                    'input_pdf': str(input_pdf),
                    'total_candidates': len(filtered_candidates),
                    'candidates': [c.to_dict() for c in filtered_candidates]
                }
                
                if report:
                    with open(report, 'w') as f:
                        json.dump(result, f, indent=2)
                    print_success(f"Report saved to: {report}")
                else:
                    print(json.dumps(result, indent=2))
            
            else:
                table = Table(title="Flag Candidates")
                table.add_column("Confidence", style="cyan")
                table.add_column("Value", style="green")
                table.add_column("Location", style="yellow")
                table.add_column("Encoding", style="magenta")
                table.add_column("Pattern", style="blue")
                
                for candidate in filtered_candidates[:20]:
                    confidence_color = "green" if candidate.confidence >= 0.7 else "yellow" if candidate.confidence >= 0.4 else "red"
                    table.add_row(
                        f"[{confidence_color}]{candidate.confidence:.2f}[/]",
                        candidate.value[:60] + ("..." if len(candidate.value) > 60 else ""),
                        candidate.location.value,
                        candidate.encoding.value,
                        candidate.pattern_matched
                    )
                
                console.print(table)
                
                if len(filtered_candidates) > 20:
                    print_info(f"Showing top 20 of {len(filtered_candidates)} candidates")
                
                if report:
                    hunter.export_report(report)
                    print_success(f"Full report saved to: {report}")
                
                high_confidence = [c for c in filtered_candidates if c.confidence >= 0.7]
                if high_confidence:
                    print_success(f"\nHigh confidence candidates: {len(high_confidence)}")
                    for candidate in high_confidence[:5]:
                        console.print(f"  [green]•[/] {candidate.value}")
                        if candidate.context:
                            console.print(f"    Context: [dim]{candidate.context[:100]}[/]")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@solve.command('stego')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output-dir', '-o', type=click.Path(path_type=Path), help='Output directory for extracted data')
@click.option('--techniques', '-t', multiple=True, help='Specific techniques to check (default: all)')
@click.option('--report', '-r', type=click.Path(path_type=Path), help='Output report file')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--min-confidence', type=float, default=0.0, help='Minimum confidence threshold (0.0-1.0)')
def solve_stego_cmd(
    input_pdf: Path,
    output_dir: Optional[Path],
    techniques: tuple,
    report: Optional[Path],
    format: str,
    min_confidence: float
):
    """Detect and extract steganography"""
    from pdfscalpel.solve.stego_solver import solve_steganography, StegoSolver
    from pdfscalpel.core.pdf_base import PDFDocument
    from rich.table import Table
    from rich.console import Console
    
    try:
        print_header("PDF Steganography Detection & Extraction", str(input_pdf))
        
        result = solve_steganography(input_pdf, output_dir, techniques if techniques else None)
        
        total_findings = result['total_findings']
        
        if total_findings == 0:
            print_success("No steganography detected")
            return
        
        print_info(f"Detected {total_findings} steganography finding(s)")
        
        filtered_findings = [
            f for f in result['findings']
            if f['confidence'] >= min_confidence
        ]
        
        if not filtered_findings:
            print_warning(f"No findings above confidence threshold {min_confidence:.0%}")
            return
        
        if format == 'json':
            output_result = {
                'input_pdf': str(input_pdf),
                'total_findings': len(filtered_findings),
                'techniques_detected': result['techniques_detected'],
                'findings': filtered_findings,
            }
            
            if report:
                with open(report, 'w') as f:
                    json.dump(output_result, f, indent=2)
                print_success(f"Report saved to: {report}")
            else:
                print(json.dumps(output_result, indent=2))
        
        else:
            console = Console()
            table = Table(title="Steganography Findings")
            table.add_column("Technique", style="cyan")
            table.add_column("Confidence", style="green")
            table.add_column("Location", style="yellow")
            table.add_column("Difficulty", style="magenta")
            table.add_column("Data", style="blue")
            
            for finding in filtered_findings[:30]:
                confidence_color = "green" if finding['confidence'] >= 0.7 else "yellow" if finding['confidence'] >= 0.5 else "red"
                
                technique_display = finding['technique'].replace('_', ' ').title()[:30]
                data_display = "Yes" if finding['has_extracted_data'] else "No"
                if finding['extracted_size'] > 0:
                    data_display += f" ({finding['extracted_size']} bytes)"
                
                table.add_row(
                    technique_display,
                    f"[{confidence_color}]{finding['confidence']:.0%}[/]",
                    finding['location'][:40],
                    finding['difficulty'],
                    data_display
                )
            
            console.print(table)
            
            if len(filtered_findings) > 30:
                print_info(f"Showing top 30 of {len(filtered_findings)} findings")
            
            high_confidence = [f for f in filtered_findings if f['confidence'] >= 0.8]
            if high_confidence:
                print_success(f"\nHigh confidence findings: {len(high_confidence)}")
                for finding in high_confidence[:5]:
                    console.print(f"  [green]•[/] {finding['technique']}")
                    if finding['details']:
                        console.print(f"    Details: [dim]{finding['details']}[/]")
            
            if result['extracted_data_available']:
                extracted_count = sum(1 for f in filtered_findings if f['has_extracted_data'])
                print_success(f"\nExtracted data from {extracted_count} finding(s)")
                if output_dir:
                    print_info(f"Output directory: {output_dir}")
            
            if report:
                summary_text = f"Steganography Detection Report\n"
                summary_text += f"PDF: {input_pdf}\n"
                summary_text += f"Total Findings: {len(filtered_findings)}\n\n"
                
                for i, finding in enumerate(filtered_findings, 1):
                    summary_text += f"Finding #{i}\n"
                    summary_text += f"  Technique: {finding['technique']}\n"
                    summary_text += f"  Confidence: {finding['confidence']:.0%}\n"
                    summary_text += f"  Location: {finding['location']}\n"
                    summary_text += f"  Difficulty: {finding['difficulty']}\n"
                    if finding['has_extracted_data']:
                        summary_text += f"  Extracted: {finding['extracted_size']} bytes\n"
                    summary_text += f"  Details: {finding['details']}\n\n"
                
                with open(report, 'w') as f:
                    f.write(summary_text)
                print_success(f"Report saved to: {report}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@solve.command('auto')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--ctf-mode', is_flag=True, required=True, help='CTF mode (required for auto solver)')
@click.option('--challenge-id', type=str, help='Challenge ID for audit trail')
@click.option('--quick-mode', is_flag=True, help='Skip time-intensive operations')
@click.option('--report', '-r', type=click.Path(path_type=Path), help='Output report file')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
def solve_auto_cmd(
    input_pdf: Path,
    ctf_mode: bool,
    challenge_id: Optional[str],
    quick_mode: bool,
    report: Optional[Path],
    format: str
):
    """Automatically solve PDF CTF challenge"""
    from pdfscalpel.solve.auto_solver import solve_auto
    from rich.table import Table
    from rich.console import Console
    
    console = Console()
    
    try:
        print_header("Auto Solver", str(input_pdf))
        
        if ctf_mode and not challenge_id:
            print_warning("CTF mode enabled without challenge ID - consider providing --challenge-id")
        
        print_info("Starting automated solving workflow...")
        
        result = solve_auto(
            pdf_path=input_pdf,
            ctf_mode=ctf_mode,
            challenge_id=challenge_id,
            quick_mode=quick_mode,
            output_report=report if format == 'json' else None
        )
        
        if format == 'json':
            output_data = result.to_dict()
            
            if report:
                print_success(f"JSON report saved to: {report}")
            else:
                print(json.dumps(output_data, indent=2))
        
        else:
            print_info(f"Executed {len(result.stages_executed)} stages in {result.total_duration_seconds:.2f}s")
            
            table = Table(title="Solver Stages")
            table.add_column("Stage", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Duration", style="yellow")
            table.add_column("Details", style="white")
            
            for stage_result in result.stage_results:
                status_icon = "✓" if stage_result.success else "✗"
                status_color = "green" if stage_result.success else "red"
                
                stage_name = stage_result.stage.value.replace('_', ' ').title()
                
                details = ""
                if stage_result.stage.value == 'password_cracking' and stage_result.success:
                    password = stage_result.data.get('password', 'N/A')
                    details = f"Password: {password}"
                elif stage_result.stage.value == 'flag_hunting':
                    high_conf = stage_result.data.get('high_confidence', 0)
                    details = f"{high_conf} high-confidence flags"
                elif stage_result.stage.value == 'steganography_detection':
                    findings = stage_result.data.get('medium_confidence', 0)
                    details = f"{findings} findings"
                elif stage_result.stage.value == 'revision_analysis':
                    revisions = stage_result.data.get('total_revisions', 0)
                    details = f"{revisions} revisions"
                
                table.add_row(
                    stage_name,
                    f"[{status_color}]{status_icon}[/]",
                    f"{stage_result.duration_seconds:.2f}s",
                    details
                )
            
            console.print(table)
            
            if result.flags_found:
                print_success(f"\nFound {len(result.flags_found)} potential flags:")
                flags_table = Table()
                flags_table.add_column("Confidence", style="cyan")
                flags_table.add_column("Value", style="green")
                flags_table.add_column("Location", style="yellow")
                
                for flag in result.flags_found[:10]:
                    confidence_color = "green" if flag['confidence'] >= 0.8 else "yellow"
                    flags_table.add_row(
                        f"[{confidence_color}]{flag['confidence']:.0%}[/]",
                        flag['value'][:60] + ("..." if len(flag['value']) > 60 else ""),
                        flag['location']
                    )
                
                console.print(flags_table)
                
                if len(result.flags_found) > 10:
                    print_info(f"Showing top 10 of {len(result.flags_found)} flags")
            
            if result.stego_findings:
                print_success(f"\nDetected {len(result.stego_findings)} steganography patterns:")
                for finding in result.stego_findings[:5]:
                    technique = finding['technique'].replace('_', ' ').title()
                    console.print(f"  [green]•[/] {technique} (confidence: {finding['confidence']:.0%})")
                
                if len(result.stego_findings) > 5:
                    print_info(f"Showing top 5 of {len(result.stego_findings)} findings")
            
            if result.recommendations:
                print_header("Recommendations", "Next Steps")
                for i, rec in enumerate(result.recommendations, 1):
                    console.print(f"  {i}. {rec}")
            
            if result.solved:
                print_success("\n✓ Challenge appears solvable - review findings above")
            else:
                print_warning("\n⚠ No obvious solution found - manual analysis recommended")
            
            if report and format == 'text':
                report_text = f"PDFScalpel Auto Solver Report\n"
                report_text += f"=" * 80 + "\n\n"
                report_text += f"PDF: {input_pdf}\n"
                report_text += f"Timestamp: {result.timestamp.isoformat()}\n"
                report_text += f"Challenge ID: {result.challenge_id or 'N/A'}\n"
                report_text += f"Duration: {result.total_duration_seconds:.2f}s\n"
                report_text += f"Solved: {'Yes' if result.solved else 'No'}\n\n"
                
                report_text += "STAGES EXECUTED\n"
                report_text += "-" * 80 + "\n"
                for stage_result in result.stage_results:
                    stage_name = stage_result.stage.value.replace('_', ' ').title()
                    status = "SUCCESS" if stage_result.success else "FAILED"
                    report_text += f"{stage_name}: {status} ({stage_result.duration_seconds:.2f}s)\n"
                    if stage_result.error:
                        report_text += f"  Error: {stage_result.error}\n"
                report_text += "\n"
                
                if result.flags_found:
                    report_text += "FLAGS FOUND\n"
                    report_text += "-" * 80 + "\n"
                    for i, flag in enumerate(result.flags_found, 1):
                        report_text += f"{i}. {flag['value']}\n"
                        report_text += f"   Confidence: {flag['confidence']:.0%}\n"
                        report_text += f"   Location: {flag['location']}\n"
                        report_text += f"   Encoding: {flag['encoding']}\n\n"
                
                if result.stego_findings:
                    report_text += "STEGANOGRAPHY FINDINGS\n"
                    report_text += "-" * 80 + "\n"
                    for i, finding in enumerate(result.stego_findings, 1):
                        report_text += f"{i}. {finding['technique']}\n"
                        report_text += f"   Confidence: {finding['confidence']:.0%}\n"
                        report_text += f"   Location: {finding['location']}\n\n"
                
                report_text += "RECOMMENDATIONS\n"
                report_text += "-" * 80 + "\n"
                for i, rec in enumerate(result.recommendations, 1):
                    report_text += f"{i}. {rec}\n"
                
                with open(report, 'w') as f:
                    f.write(report_text)
                print_success(f"\nReport saved to: {report}")
    
    except PDFScalpelError as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@solve.command('repair')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Repaired output file')
@click.option('--assess-only', is_flag=True, help='Only assess damage without repairing')
@click.option('--report', '-r', type=click.Path(path_type=Path), help='Damage assessment report')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@handle_errors("PDF Repair & Recovery")
@log_command
def solve_repair_cmd(
    input_pdf: Path,
    output: Optional[Path],
    assess_only: bool,
    report: Optional[Path],
    format: str
):
    """
    Assess PDF damage and attempt repair/recovery
    
    Comprehensive PDF repair including header reconstruction, xref table
    rebuilding, stream recovery, EOF marker repair, and incremental update
    extraction. Assesses damage severity and recoverability.
    
    Examples:
        pdfscalpel solve repair corrupted.pdf --assess-only
        pdfscalpel solve repair broken.pdf --output fixed.pdf
        pdfscalpel solve repair damaged.pdf --output fixed.pdf --report report.json
    """
    print_header("PDF Repair & Recovery", str(input_pdf))
    
    try:
        analyzer = PDFRepairAnalyzer()
        
        print_info("Assessing PDF damage...")
        assessment = analyzer.assess_damage(input_pdf)
        
        print_info(f"Damage detected: {assessment.is_damaged}")
        print_info(f"Total damage reports: {assessment.damage_count}")
        print_info(f"Critical damage: {assessment.critical_damage_count}")
        print_info(f"Estimated recoverability: {assessment.estimated_recoverability:.1%}")
        
        if assessment.damage_reports:
            click.echo("\nDamage Reports:")
            for i, damage in enumerate(assessment.damage_reports, 1):
                severity_color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'yellow',
                    'info': 'blue'
                }.get(damage.severity.value, 'white')
                
                click.secho(f"\n{i}. [{damage.severity.value.upper()}] {damage.damage_type.value}", 
                           fg=severity_color, bold=True)
                click.echo(f"   {damage.description}")
                click.echo(f"   Location: {damage.location}")
                click.echo(f"   Repairable: {damage.repairable}")
                
                if damage.repair_method:
                    click.echo(f"   Repair Method: {damage.repair_method}")
                
                if damage.evidence:
                    click.echo(f"   Evidence:")
                    for evidence in damage.evidence[:3]:
                        click.echo(f"     - {evidence}")
        
        if assessment.recommended_tools:
            click.echo(f"\nRecommended Tools:")
            for tool in assessment.recommended_tools:
                click.echo(f"  - {tool}")
        
        if not assess_only and output:
            if assessment.estimated_recoverability < 0.3:
                print_warning("\nLow recoverability - repair may fail or produce incomplete results")
                if not click.confirm("Continue with repair attempt?"):
                    print_info("Repair cancelled")
                    sys.exit(0)
            
            print_info(f"\nAttempting repair...")
            repair_result = analyzer.repair(input_pdf, output)
            
            if repair_result.success:
                print_success(f"Repair successful! Repaired file: {repair_result.repaired_file}")
                print_info(f"Recovery percentage: {repair_result.recovery_percentage:.1%}")
                
                if repair_result.repair_methods_used:
                    click.echo("\nRepair Methods Used:")
                    for method in repair_result.repair_methods_used:
                        click.echo(f"  - {method}")
                
                if repair_result.warnings:
                    print_warning("\nWarnings:")
                    for warning in repair_result.warnings:
                        click.echo(f"  - {warning}")
            else:
                print_error("Repair failed")
                if repair_result.warnings:
                    click.echo("\nReasons:")
                    for warning in repair_result.warnings:
                        click.echo(f"  - {warning}")
        elif not assess_only and not output:
            print_warning("No output file specified. Use --output to repair the PDF.")
        
        if report:
            assessment_dict = assessment.to_dict()
            if format == 'json':
                with open(report, 'w') as f:
                    json.dump(assessment_dict, f, indent=2, default=str)
            else:
                with open(report, 'w') as f:
                    f.write(_format_repair_report(assessment))
            print_success(f"\nReport saved to: {report}")
        elif format == 'json' and not output:
            click.echo(json.dumps(assessment.to_dict(), indent=2, default=str))
        
    except Exception as e:
        print_error(f"Repair analysis failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _format_repair_report(assessment) -> str:
    """Format repair assessment report for text output"""
    lines = []
    lines.append("=" * 80)
    lines.append("PDF REPAIR & DAMAGE ASSESSMENT REPORT")
    lines.append("=" * 80)
    lines.append(f"File: {assessment.file_path}")
    lines.append(f"Is Damaged: {assessment.is_damaged}")
    lines.append(f"Total Damage Reports: {assessment.damage_count}")
    lines.append(f"Critical Damage: {assessment.critical_damage_count}")
    lines.append(f"Estimated Recoverability: {assessment.estimated_recoverability:.1%}")
    lines.append("")
    
    if assessment.damage_reports:
        lines.append(f"DAMAGE REPORTS ({len(assessment.damage_reports)})")
        lines.append("-" * 80)
        for i, damage in enumerate(assessment.damage_reports, 1):
            lines.append(f"{i}. [{damage.severity.value.upper()}] {damage.damage_type.value}")
            lines.append(f"   {damage.description}")
            lines.append(f"   Location: {damage.location}")
            lines.append(f"   Repairable: {damage.repairable}")
            if damage.repair_method:
                lines.append(f"   Repair Method: {damage.repair_method}")
            lines.append("")
    
    if assessment.recommended_tools:
        lines.append("RECOMMENDED TOOLS")
        lines.append("-" * 80)
        for tool in assessment.recommended_tools:
            lines.append(f"  - {tool}")
        lines.append("")
    
    return '\n'.join(lines)


@cli.group()
def plugin():
    """Plugin management commands"""
    pass


@plugin.command('list')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed plugin information')
def plugin_list(verbose: bool):
    """List all loaded plugins"""
    from pdfscalpel.plugins import get_registry, discover_plugins
    
    registry = get_registry()
    
    if len(registry) == 0:
        loaded = discover_plugins()
        if loaded == 0:
            print_warning("No plugins loaded. Use 'plugin load' to load plugins.")
            return
    
    plugins = registry.list_all()
    
    if not plugins:
        print_warning("No plugins loaded")
        return
    
    print_header("Loaded Plugins", f"{len(plugins)} total")
    
    by_type = {}
    for plugin in plugins:
        plugin_type = plugin.plugin_type.value
        if plugin_type not in by_type:
            by_type[plugin_type] = []
        by_type[plugin_type].append(plugin)
    
    for plugin_type, type_plugins in sorted(by_type.items()):
        print_info(f"\n{plugin_type.upper()} Plugins:")
        for plugin in type_plugins:
            if verbose:
                print(f"  - {plugin.name} v{plugin.version}")
                print(f"    Author: {plugin.author}")
                print(f"    Description: {plugin.description}")
                if plugin.dependencies:
                    print(f"    Dependencies: {', '.join(plugin.dependencies)}")
                print()
            else:
                print(f"  - {plugin.name} v{plugin.version} - {plugin.description}")
    
    failed = registry.list_failed()
    if failed:
        print_warning(f"\nFailed to load {len(failed)} plugins:")
        for name, error in failed.items():
            print_error(f"  - {name}: {error}")


@plugin.command('load')
@click.argument('plugin_path', type=click.Path(exists=True, path_type=Path))
@click.option('--recursive', '-r', is_flag=True, help='Load plugins from subdirectories')
def plugin_load(plugin_path: Path, recursive: bool):
    """Load plugins from a directory or file"""
    from pdfscalpel.plugins import get_loader
    
    loader = get_loader()
    
    try:
        if plugin_path.is_dir():
            loaded = loader.load_from_directory(plugin_path, recursive=recursive)
            print_success(f"Loaded {loaded} plugins from {plugin_path}")
        else:
            loaded = loader.load_from_file(plugin_path)
            print_success(f"Loaded {loaded} plugins from {plugin_path}")
    except Exception as e:
        print_error(f"Failed to load plugins: {e}")
        sys.exit(1)


@plugin.command('discover')
@click.option('--recursive', '-r', is_flag=True, help='Scan subdirectories')
def plugin_discover(recursive: bool):
    """Discover and load plugins from standard locations"""
    from pdfscalpel.plugins import discover_plugins
    
    print_info("Discovering plugins...")
    loaded = discover_plugins(recursive=recursive)
    
    if loaded > 0:
        print_success(f"Discovered and loaded {loaded} plugins")
    else:
        print_warning("No plugins found in standard locations")


@plugin.command('run')
@click.argument('plugin_name')
@click.argument('input_pdf', type=click.Path(exists=True, path_type=Path), required=False)
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file or directory')
@click.option('--option', '-O', multiple=True, help='Plugin option as key=value')
def plugin_run(plugin_name: str, input_pdf: Optional[Path], output: Optional[Path], option: tuple):
    """Run a plugin by name"""
    from pdfscalpel.plugins import get_registry, discover_plugins
    
    registry = get_registry()
    
    if len(registry) == 0:
        print_info("Loading plugins...")
        discover_plugins()
    
    plugin = registry.get(plugin_name)
    if not plugin:
        print_error(f"Plugin not found: {plugin_name}")
        print_info("Use 'pdfscalpel plugin list' to see available plugins")
        sys.exit(1)
    
    options = {}
    for opt in option:
        if '=' in opt:
            key, value = opt.split('=', 1)
            options[key] = value
        else:
            print_error(f"Invalid option format: {opt}. Use key=value")
            sys.exit(1)
    
    print_header(f"Running Plugin: {plugin_name}", plugin.metadata.description)
    
    try:
        from pdfscalpel.plugins.base import AnalyzerPlugin, ExtractorPlugin, MutatorPlugin, SolverPlugin, UtilityPlugin
        
        if isinstance(plugin, AnalyzerPlugin):
            if not input_pdf:
                print_error("Analyzer plugins require an input PDF")
                sys.exit(1)
            with PDFDocument.open(input_pdf) as pdf:
                result = plugin.execute(pdf, **options)
        
        elif isinstance(plugin, ExtractorPlugin):
            if not input_pdf:
                print_error("Extractor plugins require an input PDF")
                sys.exit(1)
            output_dir = output or Path.cwd() / "output"
            with PDFDocument.open(input_pdf) as pdf:
                result = plugin.execute(pdf, output_dir, **options)
        
        elif isinstance(plugin, MutatorPlugin):
            if not input_pdf or not output:
                print_error("Mutator plugins require both input PDF and output path")
                sys.exit(1)
            with PDFDocument.open(input_pdf) as pdf:
                result = plugin.execute(pdf, output, **options)
        
        elif isinstance(plugin, SolverPlugin):
            if not input_pdf:
                print_error("Solver plugins require an input PDF")
                sys.exit(1)
            with PDFDocument.open(input_pdf) as pdf:
                result = plugin.execute(pdf, **options)
        
        elif isinstance(plugin, UtilityPlugin):
            if input_pdf:
                options['pdf_path'] = input_pdf
            if output:
                options['output_file'] = output
            result = plugin.execute(**options)
        
        else:
            print_error(f"Unknown plugin type: {type(plugin)}")
            sys.exit(1)
        
        if result.success:
            print_success("Plugin execution completed successfully")
            if result.data:
                print_info("\nResults:")
                print(json.dumps(result.data, indent=2, default=str))
        else:
            print_error(f"Plugin execution failed: {result.error}")
            sys.exit(1)
    
    except Exception as e:
        print_error(f"Plugin execution failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.group()
def perf():
    """Performance profiling and benchmarking"""
    pass


@perf.command()
@click.argument('input_file', type=click.Path(exists=True, path_type=Path))
@click.option('--operation', type=click.Choice(['parse', 'metadata', 'objects', 'all']), 
              default='all', help='Operation to benchmark')
@click.option('--runs', type=int, default=5, help='Number of runs for averaging')
def benchmark(input_file: Path, operation: str, runs: int):
    """Benchmark PDF operations on a file"""
    from pdfscalpel.core.benchmark import quick_benchmark
    from rich.table import Table
    from rich.console import Console
    
    try:
        print_header(f"Benchmarking: {input_file.name}")
        
        results_list = []
        for i in range(runs):
            print_info(f"Run {i+1}/{runs}...")
            results = quick_benchmark(input_file)
            results_list.append(results)
        
        # Average results
        avg_results = {}
        for key in results_list[0]:
            if isinstance(results_list[0][key], (int, float)) and key != 'num_pages' and key != 'num_objects':
                avg_results[key] = sum(r.get(key, 0) for r in results_list) / len(results_list)
            else:
                avg_results[key] = results_list[0][key]
        
        # Display results
        table = Table(title="Benchmark Results")
        table.add_column("Operation")
        table.add_column("Avg Time (s)")
        table.add_column("Info")
        
        if 'open' in avg_results:
            table.add_row("Open PDF", f"{avg_results['open']:.4f}", 
                         f"{avg_results.get('num_pages', 0)} pages")
        if 'metadata' in avg_results:
            table.add_row("Extract Metadata", f"{avg_results['metadata']:.4f}", "")
        if 'objects' in avg_results:
            table.add_row("Traverse Objects", f"{avg_results['objects']:.4f}",
                         f"{avg_results.get('num_objects', 0)} objects")
        
        Console().print(table)
        
        print_success(f"Benchmark completed ({runs} runs)")
        
    except Exception as e:
        print_error(f"Benchmark failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@perf.command()
@click.argument('input_file', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output profile file')
@click.option('--operation', type=click.Choice(['parse', 'analyze', 'extract']),
              default='parse', help='Operation to profile')
def profile(input_file: Path, output: Optional[Path], operation: str):
    """Profile CPU usage of PDF operations"""
    from pdfscalpel.core.profiling import profile_context
    from pdfscalpel.core.pdf_base import PDFDocument
    
    try:
        print_header(f"Profiling: {input_file.name}")
        
        with profile_context(f"PDF {operation}", save_path=output):
            if operation == 'parse':
                with PDFDocument.open(input_file) as doc:
                    _ = doc.num_pages
                    _ = doc.metadata
            elif operation == 'analyze':
                from pdfscalpel.analyze.structure import analyze_structure
                analyze_structure(input_file)
            elif operation == 'extract':
                from pdfscalpel.extract import extract_text
                extract_text(input_file, None)
        
        print_success("Profiling completed")
        if output:
            print_info(f"Profile saved to {output}")
            print_info(f"Visualize with: snakeviz {output}")
        
    except Exception as e:
        print_error(f"Profiling failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@perf.command()
@click.argument('input_file', type=click.Path(exists=True, path_type=Path))
@click.option('--iterations', type=int, default=100, help='Number of iterations')
def leak_check(input_file: Path, iterations: int):
    """Check for memory leaks"""
    from pdfscalpel.core.profiling import detect_memory_leaks
    from pdfscalpel.core.pdf_base import PDFDocument
    
    try:
        print_header(f"Memory Leak Detection: {input_file.name}")
        print_info(f"Running {iterations} iterations...")
        
        def test_func():
            with PDFDocument.open(input_file) as doc:
                _ = doc.num_pages
                _ = doc.metadata
        
        results = detect_memory_leaks(test_func, iterations=iterations)
        
        if 'error' in results:
            print_error(f"Leak detection failed: {results['error']}")
            sys.exit(1)
        
        from rich.table import Table
        from rich.console import Console
        
        table = Table(title="Memory Leak Analysis")
        table.add_column("Metric")
        table.add_column("Value")
        
        table.add_row("Iterations", str(results['iterations']))
        table.add_row("Start Memory", f"{results['start_memory_mb']:.2f} MB")
        table.add_row("End Memory", f"{results['end_memory_mb']:.2f} MB")
        table.add_row("Growth", f"{results['growth_mb']:.2f} MB ({results['growth_percent']:.1f}%)")
        table.add_row("Potential Leak", "YES" if results['potential_leak'] else "NO")
        
        Console().print(table)
        
        if results['potential_leak']:
            print_warning("Potential memory leak detected!")
        else:
            print_success("No significant memory growth detected")
        
    except Exception as e:
        print_error(f"Leak check failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@perf.command()
def cache_stats():
    """Show performance cache statistics"""
    from pdfscalpel.core.performance import get_cache_stats, get_memory_usage
    from rich.table import Table
    from rich.console import Console
    
    try:
        print_header("Performance Cache Statistics")
        
        stats = get_cache_stats()
        
        table = Table(title="Cache Stats")
        table.add_column("Cache")
        table.add_column("Hits")
        table.add_column("Misses")
        table.add_column("Size")
        table.add_column("Hit Rate")
        
        for cache_name, cache_stat in stats.items():
            table.add_row(
                cache_name,
                str(cache_stat['hits']),
                str(cache_stat['misses']),
                f"{cache_stat['size']}/{cache_stat['maxsize']}",
                f"{cache_stat['hit_rate']:.1f}%"
            )
        
        Console().print(table)
        
        # Memory usage
        memory = get_memory_usage()
        if 'error' not in memory:
            print_info(f"\nCurrent Memory Usage: {memory['rss_mb']:.2f} MB ({memory['percent']:.1f}%)")
            print_info(f"Available Memory: {memory['available_mb']:.2f} MB")
        
        print_success("Cache statistics retrieved")
        
    except Exception as e:
        print_error(f"Failed to get cache stats: {e}")
        sys.exit(1)


@perf.command()
def clear_cache():
    """Clear all performance caches"""
    from pdfscalpel.core.performance import clear_all_caches
    
    try:
        clear_all_caches()
        print_success("All caches cleared")
    except Exception as e:
        print_error(f"Failed to clear caches: {e}")
        sys.exit(1)


@perf.command()
@click.argument('input_files', nargs=-1, type=click.Path(exists=True, path_type=Path), required=True)
@click.option('--tools', multiple=True, default=['pdfscalpel'], 
              help='Tools to compare (pdfscalpel, qpdf, pdfinfo, pdftk)')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output report file')
def compare(input_files: tuple, tools: tuple, output: Optional[Path]):
    """Compare performance against other tools"""
    from pdfscalpel.core.benchmark import BenchmarkSuite
    
    try:
        print_header("Performance Comparison")
        
        file_paths = [Path(f) for f in input_files]
        
        suite = BenchmarkSuite(file_paths)
        results = suite.run_comparison(list(tools), 'parse')
        
        report = suite.generate_report(output)
        
        print(report)
        
        if output:
            suite.save_json(output.with_suffix('.json'))
            print_success(f"Results saved to {output} and {output.with_suffix('.json')}")
        
    except Exception as e:
        print_error(f"Comparison failed: {e}")
        if get_config().debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command('completion')
@click.argument('shell', type=click.Choice(['bash', 'zsh', 'fish'], case_sensitive=False))
def completion_cmd(shell: str):
    """
    Generate shell completion script
    
    Install tab completion for your shell to enable command/option autocomplete.
    
    Bash:
        pdfscalpel completion bash > ~/.pdfscalpel-complete.bash
        echo "source ~/.pdfscalpel-complete.bash" >> ~/.bashrc
        source ~/.bashrc
    
    Zsh:
        pdfscalpel completion zsh > ~/.pdfscalpel-complete.zsh
        echo "source ~/.pdfscalpel-complete.zsh" >> ~/.zshrc
        source ~/.zshrc
    
    Fish:
        pdfscalpel completion fish > ~/.config/fish/completions/pdfscalpel.fish
    
    Examples:
        pdfscalpel completion bash
        pdfscalpel completion zsh > ~/.pdfscalpel-complete.zsh
    """
    import os
    shell = shell.lower()
    
    completion_script = {
        'bash': '''_pdfscalpel_completion() {
    local IFS=$'\\n'
    local response

    response=$(env COMP_WORDS="${COMP_WORDS[*]}" COMP_CWORD=$COMP_CWORD _PDFSCALPEL_COMPLETE=bash_complete $1)

    for completion in $response; do
        IFS=',' read type value <<< "$completion"

        if [[ $type == 'dir' ]]; then
            COMPREPLY=()
            compopt -o dirnames
        elif [[ $type == 'file' ]]; then
            COMPREPLY=()
            compopt -o default
        elif [[ $type == 'plain' ]]; then
            COMPREPLY+=($value)
        fi
    done

    return 0
}

_pdfscalpel_completion_setup() {
    complete -o nosort -F _pdfscalpel_completion pdfscalpel
}

_pdfscalpel_completion_setup;
''',
        'zsh': '''#compdef pdfscalpel

_pdfscalpel_completion() {
    local -a completions
    local -a completions_with_descriptions
    local -a response
    (( ! $+commands[pdfscalpel] )) && return 1

    response=("${(@f)$(env COMP_WORDS="${words[*]}" COMP_CWORD=$((CURRENT-1)) _PDFSCALPEL_COMPLETE=zsh_complete pdfscalpel)}")

    for type key descr in ${response}; do
        if [[ "$type" == "plain" ]]; then
            if [[ "$descr" == "_" ]]; then
                completions+=("$key")
            else
                completions_with_descriptions+=("$key":"$descr")
            fi
        elif [[ "$type" == "dir" ]]; then
            _path_files -/
        elif [[ "$type" == "file" ]]; then
            _path_files -f
        fi
    done

    if [ -n "$completions_with_descriptions" ]; then
        _describe -V unsorted completions_with_descriptions -U
    fi

    if [ -n "$completions" ]; then
        compadd -U -V unsorted -a completions
    fi
}

compdef _pdfscalpel_completion pdfscalpel;
''',
        'fish': '''function _pdfscalpel_completion;
    set -l response;

    for value in (env _PDFSCALPEL_COMPLETE=fish_complete COMP_WORDS=(commandline -cp) COMP_CWORD=(commandline -t) pdfscalpel);
        set response $response $value;
    end;

    for completion in $response;
        set -l metadata (string split "," $completion);

        if test $metadata[1] = "dir";
            __fish_complete_directories $metadata[2];
        else if test $metadata[1] = "file";
            __fish_complete_path $metadata[2];
        else if test $metadata[1] = "plain";
            echo $metadata[2];
        end;
    end;
end;

complete --no-files --command pdfscalpel --arguments "(_pdfscalpel_completion)";
'''
    }
    
    if shell in completion_script:
        click.echo(completion_script[shell])
    else:
        print_error(f"Unsupported shell: {shell}")
        sys.exit(1)


@cli.command('list-commands')
@click.option('--group', type=str, help='Filter by command group (analyze, extract, mutate, solve, generate)')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
def list_commands_cmd(group: Optional[str], format: str):
    """
    List all available commands
    
    Show a complete list of all PDFScalpel commands, optionally filtered by group.
    Useful for discovering available functionality and scripting.
    
    Examples:
        pdfscalpel list-commands
        pdfscalpel list-commands --group analyze
        pdfscalpel list-commands --format json
    """
    commands_dict = {
        'analyze': [
            'structure', 'metadata', 'encryption', 'malware', 'signatures',
            'form-security', 'anti-forensics', 'advanced-stego', 'watermark',
            'graph', 'entropy', 'intelligence', 'compliance', 'render-diff'
        ],
        'extract': [
            'text', 'images', 'javascript', 'attachments', 'forms',
            'streams', 'objects', 'hidden', 'revisions', 'web'
        ],
        'mutate': [
            'watermark', 'encrypt', 'decrypt', 'pages', 'bookmarks',
            'redaction', 'optimize'
        ],
        'solve': [
            'password', 'flag-hunt', 'stego', 'auto', 'repair'
        ],
        'generate': [
            'challenge', 'corrupted', 'polyglot', 'stego-data', 'watermark-samples'
        ],
        'other': [
            'check-deps', 'perf', 'plugin', 'completion', 'list-commands', 'commands'
        ]
    }
    
    if group:
        filtered = {group: commands_dict.get(group, [])}
        if not filtered[group]:
            print_error(f"Unknown group: {group}")
            print_info(f"Available groups: {', '.join(commands_dict.keys())}")
            sys.exit(1)
        commands_dict = filtered
    
    if format == 'json':
        click.echo(json.dumps(commands_dict, indent=2))
    else:
        for cmd_group, cmds in commands_dict.items():
            if cmds:
                click.secho(f"\n{cmd_group.upper()}", fg='cyan', bold=True)
                for cmd in cmds:
                    click.echo(f"  pdfscalpel {cmd_group} {cmd}" if cmd_group not in ['other'] else f"  pdfscalpel {cmd}")


@cli.command('commands')
@click.option('--search', '-s', type=str, help='Search commands by keyword')
def commands_quick_ref(search: Optional[str]):
    """
    Quick reference for common commands
    
    Shows frequently used commands organized by use case. Perfect for
    getting started or quickly finding the right command for your task.
    
    Examples:
        pdfscalpel commands
        pdfscalpel commands --search malware
        pdfscalpel commands --search signature
    """
    quick_ref = {
        'Forensic Analysis': [
            ('Malware detection', 'pdfscalpel analyze malware suspicious.pdf'),
            ('Digital signatures', 'pdfscalpel analyze signatures signed.pdf'),
            ('Form security', 'pdfscalpel analyze form-security form.pdf'),
            ('Anti-forensics', 'pdfscalpel analyze anti-forensics sanitized.pdf'),
            ('Advanced stego', 'pdfscalpel analyze advanced-stego file.pdf --deep'),
            ('Full intelligence', 'pdfscalpel analyze intelligence suspicious.pdf --report report.txt'),
        ],
        'Data Extraction': [
            ('Extract text', 'pdfscalpel extract text document.pdf -o output.txt'),
            ('Extract images', 'pdfscalpel extract images document.pdf -o images/'),
            ('Extract JavaScript', 'pdfscalpel extract javascript malicious.pdf -o scripts/'),
            ('Extract hidden data', 'pdfscalpel extract hidden document.pdf'),
            ('Extract revisions', 'pdfscalpel extract revisions modified.pdf -o revisions/'),
        ],
        'CTF Challenges': [
            ('Auto-solve', 'pdfscalpel solve auto challenge.pdf --ctf-mode --challenge-id ctf-001'),
            ('Hunt flags', 'pdfscalpel solve flag-hunt challenge.pdf --patterns ctf,flag'),
            ('Crack password', 'pdfscalpel solve password encrypted.pdf --ctf-mode --challenge-id ctf-001'),
            ('Detect stego', 'pdfscalpel solve stego challenge.pdf -o extracted/'),
        ],
        'PDF Repair': [
            ('Assess damage', 'pdfscalpel solve repair corrupted.pdf --assess-only'),
            ('Repair PDF', 'pdfscalpel solve repair broken.pdf --output fixed.pdf'),
            ('Full report', 'pdfscalpel solve repair damaged.pdf --output fixed.pdf --report report.json'),
        ],
        'Structure Analysis': [
            ('Analyze structure', 'pdfscalpel analyze structure document.pdf'),
            ('Check metadata', 'pdfscalpel analyze metadata document.pdf'),
            ('Check encryption', 'pdfscalpel analyze encryption encrypted.pdf --check-exploits'),
            ('Object graph', 'pdfscalpel analyze graph document.pdf -o graph.png --format png'),
            ('Entropy analysis', 'pdfscalpel analyze entropy document.pdf --heatmap -o entropy.png'),
        ],
        'Modification': [
            ('Remove watermark', 'pdfscalpel mutate watermark input.pdf output.pdf --remove auto'),
            ('Add password', 'pdfscalpel mutate encrypt input.pdf output.pdf --password secret'),
            ('Merge PDFs', 'pdfscalpel mutate pages file1.pdf file2.pdf -o merged.pdf --merge'),
            ('Optimize PDF', 'pdfscalpel mutate optimize input.pdf output.pdf --compress'),
        ],
    }
    
    if search:
        search_lower = search.lower()
        filtered_ref = {}
        for category, commands in quick_ref.items():
            filtered_commands = [
                (desc, cmd) for desc, cmd in commands
                if search_lower in desc.lower() or search_lower in cmd.lower()
            ]
            if filtered_commands:
                filtered_ref[category] = filtered_commands
        quick_ref = filtered_ref
        
        if not quick_ref:
            print_warning(f"No commands found matching: {search}")
            return
    
    click.secho("\n" + "=" * 65, fg='cyan', bold=True)
    click.secho("  PDFScalpel Quick Reference", fg='cyan', bold=True)
    click.secho("=" * 65 + "\n", fg='cyan', bold=True)
    
    for category, commands in quick_ref.items():
        click.secho(f"{category}", fg='yellow', bold=True)
        click.echo()
        for desc, cmd in commands:
            click.secho(f"  {desc:<20}", fg='green', nl=False)
            click.echo(f" {cmd}")
        click.echo()
    
    click.secho("For detailed help on any command:", fg='cyan')
    click.echo("  pdfscalpel <command> --help")
    click.echo("  pdfscalpel analyze malware --help")
    click.echo()


if __name__ == '__main__':
    cli()
