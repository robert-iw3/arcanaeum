import os
import json
import argparse
import logging
from pathlib import Path
import tqdm
import charset_normalizer
import gzip
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=level)

def validate_ndjson(output_file_path, is_compressed=False):
    open_func = gzip.open if is_compressed else open
    i = None  # Initialize i to None before the loop
    try:
        with open_func(output_file_path, 'rt', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                if line.strip():
                    json.loads(line)
        logging.info(f"NDJSON file '{output_file_path}' is valid.")
        return True
    except json.JSONDecodeError as e:
        logging.error(f"Invalid NDJSON in '{output_file_path}' at line {i if i is not None else 'unknown'}: {e}")
        return False
    except Exception as e:
        logging.error(f"Error validating NDJSON file '{output_file_path}': {e}")
        return False

def process_json_file(json_file, encoding='utf-8'):
    try:
        with open(json_file, 'rb') as f:
            raw_data = f.read()
            if not raw_data:
                logging.warning(f"File '{json_file}' is empty. Skipping.")
                return None
            detected = charset_normalizer.detect(raw_data)
            encoding = detected['encoding'] or 'utf-8'
        with open(json_file, 'r', encoding=encoding) as infile:
            data = json.load(infile)
        return json.dumps(data, separators=(',', ':'), ensure_ascii=False) + '\n'
    except Exception as e:
        logging.error(f"Error processing '{json_file}': {e}")
        return None

def merge_and_compact_json_to_ndjson(
    input_directory,
    output_directory,
    output_filename="ready_for_import_into_kibana.ndjson",
    overwrite=False,
    validate=False,
    compress=False,
    pattern="*.json",
    max_workers=1
):
    input_dir = Path(input_directory).resolve()
    output_dir = Path(output_directory).resolve()
    output_file_path = output_dir / (output_filename + '.gz' if compress else output_filename)

    if not input_dir.is_dir():
        logging.error(f"Input directory '{input_dir}' does not exist.")
        return False

    output_dir.mkdir(parents=True, exist_ok=True)

    if output_file_path.exists() and not overwrite:
        if input(f"Output file '{output_file_path}' exists. Overwrite? (y/n): ").lower() != 'y':
            logging.info("Operation cancelled by user.")
            return False

    json_files = sorted([f for f in input_dir.glob(pattern) if f.is_file()])
    if not json_files:
        logging.warning(f"No files matching '{pattern}' found in '{input_dir}'.")
        return False

    logging.info(f"Found {len(json_files)} JSON files in '{input_dir}'.")

    open_func = gzip.open if compress else open
    lock = threading.Lock()
    with open_func(output_file_path, 'wt', encoding='utf-8') as outfile:
        if max_workers > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_file = {executor.submit(process_json_file, f): f for f in json_files}
                for future in tqdm(as_completed(future_to_file), total=len(json_files), desc="Processing JSON files"):
                    result = future.result()
                    if result:
                        with lock:
                            outfile.write(result)
        else:
            for json_file in tqdm(json_files, desc="Processing JSON files"):
                result = process_json_file(json_file)
                if result:
                    outfile.write(result)

    logging.info(f"Created NDJSON file at '{output_file_path}'.")

    if validate:
        return validate_ndjson(output_file_path, compress)
    return True

def main():
    parser = argparse.ArgumentParser(description="Convert JSON files to a single NDJSON file.")
    parser.add_argument('--input-dir', default=os.path.join(os.getcwd(), "rules-editing"), help="Input directory")
    parser.add_argument('--output-dir', default=os.path.join(os.getcwd(), "final"), help="Output directory")
    parser.add_argument('--output-file', default="ready_for_import_into_kibana.ndjson", help="Output filename")
    parser.add_argument('--overwrite', action='store_true', help="Overwrite existing output file")
    parser.add_argument('--validate', action='store_true', help="Validate output NDJSON")
    parser.add_argument('--compress', action='store_true', help="Compress output to .ndjson.gz")
    parser.add_argument('--pattern', default='*.json', help="Glob pattern for JSON files")
    parser.add_argument('--max-workers', type=int, default=1, help="Number of parallel workers")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging")

    args = parser.parse_args()
    setup_logging(args.verbose)
    success = merge_and_compact_json_to_ndjson(
        args.input_dir,
        args.output_dir,
        args.output_file,
        args.overwrite,
        args.validate,
        args.compress,
        args.pattern,
        args.max_workers
    )
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()