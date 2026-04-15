import os
import json
import hashlib
import subprocess
from datetime import datetime

from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 900 * 1024 * 1024  # FIX 9: 900 MB upload limit
ALLOWED_EXTENSIONS = {'mp4', 'mov', 'avi', 'mkv', 'webm', 'flv'}

# FIX 5: Create uploads folder at module load time, not only inside __main__
# so it works when deployed via gunicorn or any other WSGI server
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_metadata(filepath):
    """Invoke ExifTool and return parsed metadata dict, or an error dict."""
    try:
        res = subprocess.run(
            ['exiftool', '-json', '-a', '-u', '-g', filepath],
            capture_output=True, text=True, timeout=30
        )
        # FIX 7: Guard against empty or missing stdout before calling json.loads
        # Original code called json.loads(res.stdout) without checking — crashes with JSONDecodeError
        if res.returncode != 0 or not res.stdout.strip():
            return {"error": res.stderr.strip() or "ExifTool returned no output"}
        return json.loads(res.stdout)[0]
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse ExifTool output: {e}"}
    except FileNotFoundError:
        return {"error": "ExifTool is not installed or not found in PATH. Install with: sudo apt install libimage-exiftool-perl"}
    except Exception as e:
        return {"error": str(e)}


def flatten_metadata(metadata):
    """Flatten the grouped ExifTool JSON into a single lowercase key-value dict."""
    flat = {}
    for k, v in metadata.items():
        if isinstance(v, dict):
            for sub_k, sub_v in v.items():
                flat[sub_k.lower()] = str(sub_v).lower()
        else:
            flat[k.lower()] = str(v).lower()
    return flat


def parse_exiftool_date(date_str):
    """
    FIX 3: Parse ExifTool date strings into datetime objects for proper comparison.
    The original code compared raw strings, which breaks when ExifTool appends
    timezone offsets (e.g. '2024:03:14 09:00:00+01:00'). Raw string comparison
    then ignores the offset, producing wrong results.
    """
    if not date_str:
        return None
    # Strip timezone offset (+HH:MM or -HH:MM) before parsing
    for sep in ['+', '-']:
        if sep in date_str[10:]:          # only strip offset, not date separators
            date_str = date_str[:date_str.index(sep, 10)]
    date_str = date_str.strip()
    for fmt in ('%Y:%m:%d %H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y:%m:%d'):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None


def run_heuristic_checks(metadata):
    """Apply five sequential forensic heuristic rules to extracted metadata."""
    flags = []
    flat  = flatten_metadata(metadata)

        # ── Check 1: Hardware Identifier ────────────────────────────────────────
    # Expanded to catch standard tags and Android-specific tags
    HARDWARE_FIELDS = ['make', 'model', 'samsungmodel', 'androidmodel', 'devicemodel', 'manufacturer']
    found_hw = [f for f in HARDWARE_FIELDS if flat.get(f, '').strip()]
    
    if not found_hw:
        flags.append({
            "flag":     "Missing Hardware Identifiers",
            "detail":   "No camera Make, Model, or Android identifier found. Authentic smartphone "
                        "and camera recordings always populate these EXIF fields.",
            "severity": "HIGH"
        })


    # ── Check 2: Software Encoder Signature ─────────────────────────────────
    # FIX: The original code only searched three field names. ExifTool exposes
    # encoder information under several field names depending on container format.
    # Expanded to cover all common variants. Also added more deepfake tool signatures.
    ENCODER_FIELDS = [
        'encoder', 'software', 'writing application',
        'writingapplication', 'handler_name', 'com.android.version'
    ]
    SUSPICIOUS_ENCODERS = [
        'ffmpeg', 'libavcodec', 'libx264', 'lavf',
        'handbrake', 'obs studio', 'x264', 'x265',
        'deepfacelab', 'openh264', 'faceswap'
    ]
    found_enc = next((flat[f] for f in ENCODER_FIELDS if flat.get(f)), "")

    if found_enc and any(s in found_enc for s in SUSPICIOUS_ENCODERS):
        flags.append({
            "flag":     "Suspicious Encoder Detected",
            "detail":   f"Encoder field reads: '{found_enc}'. This matches known AI rendering "
                        "or video processing software, not a hardware camera encoder.",
            "severity": "HIGH"
        })
    elif not found_enc:
        # FIX 10: Original code raised HIGH for a missing encoder, causing false positives
        # on MKV, WebM, and AVI files which legitimately omit the encoder field.
        # Downgraded to MEDIUM — it contributes to the verdict but is not decisive alone.
        flags.append({
            "flag":     "Encoder Data Absent",
            "detail":   "No encoder tag found. Inconclusive on its own — some container "
                        "formats (MKV, WebM, AVI) do not write this field.",
            "severity": "MEDIUM"
        })
    # ── Check 3: MakerNotes Presence ────────────────────────────────────────
    filetype       = flat.get('filetype', '').lower()
    has_makernotes = bool(flat.get('makernote') or flat.get('makernotes'))
    
    # Apple strictly writes MakerNotes to videos. Android/Samsung often do not.
    is_android = any(k in flat for k in ['samsungmodel', 'androidmodel', 'devicemodel']) or 'samsung' in flat.get('make', '').lower()
    
    if not has_makernotes and filetype in ('mp4', 'mov', 'quicktime') and not is_android:
        flags.append({
            "flag":     "Missing MakerNotes",
            "detail":   "No proprietary manufacturer sub-block found. Authentic Apple/iOS recordings always include this block.",
            "severity": "HIGH"
        })


    # ── Check 4: Timestamp Consistency ──────────────────────────────────────
    # FIX 3: Use parsed datetime objects, not raw strings.
    raw_create = flat.get('createdate') or flat.get('track create date') or ''
    raw_modify  = flat.get('modifydate') or flat.get('track modify date') or ''
    dt_create   = parse_exiftool_date(raw_create)
    dt_modify   = parse_exiftool_date(raw_modify)
    if dt_create and dt_modify and dt_modify < dt_create:
        flags.append({
            "flag":     "Timestamp Anomaly",
            "detail":   f"ModifyDate ({raw_modify.strip()}) precedes CreateDate "
                        f"({raw_create.strip()}). This indicates post-production re-encoding.",
            "severity": "HIGH"
        })

    # ── Check 5: Container Format Mismatch ──────────────────────────────────
    # FIX 11: Original code flagged MP4 + video/quicktime as a mismatch.
    # This is completely normal for Apple devices — iPhones record MP4 files
    # with the video/quicktime MIME type. That check would flag every iPhone video.
    # Replaced with a genuine mismatch table: only flag truly incompatible pairs.
    mime = flat.get('mimetype', '')
    GENUINE_MISMATCHES = {
        'mp4':  ['video/x-matroska', 'video/x-flv', 'video/webm'],
        'mov':  ['video/x-matroska', 'video/webm',  'video/x-flv'],
        'mkv':  ['video/mp4', 'video/quicktime',    'video/x-flv'],
        'webm': ['video/mp4', 'video/quicktime',    'video/x-matroska'],
    }
    ext = filetype  # ExifTool's FileType field gives the actual container format
    if ext in GENUINE_MISMATCHES and any(m in mime for m in GENUINE_MISMATCHES[ext]):
        flags.append({
            "flag":     "Container Format Mismatch",
            "detail":   f"Declared format '{ext.upper()}' conflicts with MIME type '{mime}'. "
                        "May indicate container re-wrapping.",
            "severity": "LOW"
        })

    return flags


def generate_verdict(flags):
    """
    FIX 1 & 2: Revised verdict logic.

    Original problems:
      - A single HIGH flag (e.g. missing MakerNotes on a legitimate phone video)
        immediately returned SUSPICIOUS, causing many false positives.
      - A deepfake with only LOW flags was classified as AUTHENTIC (false negative).
      - No INCONCLUSIVE state existed, despite the chapter describing one.

    Fixed logic:
      - 2+ HIGH flags                 → SUSPICIOUS
      - 1 HIGH + 1+ MEDIUM flags      → SUSPICIOUS
      - 1 HIGH alone                  → INCONCLUSIVE
      - 2+ MEDIUM flags alone         → INCONCLUSIVE
      - No significant flags          → AUTHENTIC
    """
    high   = [f for f in flags if f['severity'] == 'HIGH']
    medium = [f for f in flags if f['severity'] == 'MEDIUM']

    if len(high) >= 2:
        return {
            "verdict": "SUSPICIOUS",
            "explanation": (
                f"{len(high)} high-severity anomalies detected. Strong indicators of "
                "synthetic generation or post-production re-encoding."
            )
        }
    if len(high) == 1 and len(medium) >= 1:
        return {
            "verdict": "SUSPICIOUS",
            "explanation": (
                "One high-severity and one or more medium-severity anomalies detected. "
                "Consistent with software-based media manipulation."
            )
        }
    if len(high) == 1:
        return {
            "verdict": "INCONCLUSIVE",
            "explanation": (
                "One high-severity anomaly detected. This may indicate manipulation but is "
                "insufficient alone for a firm verdict. Manual review is recommended."
            )
        }
    if len(medium) >= 2:
        return {
            "verdict": "INCONCLUSIVE",
            "explanation": (
                "Multiple medium-severity anomalies found. This may result from metadata "
                "stripping by social media compression rather than deepfake generation. "
                "Manual review is recommended."
            )
        }
    return {
        "verdict": "AUTHENTIC",
        "explanation": (
            "No significant anomalies detected. Metadata is consistent with "
            "hardware-recorded camera footage."
        )
    }


def compute_sha256(filepath):
    """Compute SHA-256 hash of a file in streaming chunks to handle large files."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyse', methods=['POST'])
def analyse():
    if 'video' not in request.files:
        return jsonify({"error": "No file part in the request."}), 400

    file = request.files['video']
    if not file or not file.filename:
        return jsonify({"error": "No file selected."}), 400
    if not allowed_file(file.filename):
        return jsonify({
            "error": "Unsupported file type. Allowed formats: mp4, mov, avi, mkv, webm, flv"
        }), 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
    file.save(filepath)

    try:
        # Compute hash BEFORE metadata extraction so the digest is always captured
        file_hash = compute_sha256(filepath)

        meta = extract_metadata(filepath)
        if "error" in meta:
            return jsonify({"error": meta["error"]}), 500

        flags   = run_heuristic_checks(meta)
        verdict = generate_verdict(flags)

        return jsonify({
            "sha256":  file_hash,
            "flags":   flags,
            "verdict": verdict
        })

    finally:
        # Always delete the temporary file — runs even if an exception is raised
        if os.path.exists(filepath):
            os.remove(filepath)


@app.errorhandler(413)
def file_too_large(e):
    """FIX 9: Return a clean JSON error when upload exceeds MAX_CONTENT_LENGTH."""
    return jsonify({"error": "File too large. Maximum allowed upload size is 500 MB."}), 413


if __name__ == '__main__':
    app.run(debug=True)
