import os
import json
import hashlib
import subprocess
from datetime import datetime
 
from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
from flasgger import Swagger  # NEW: API documentation library
 
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB upload limit
ALLOWED_EXTENSIONS = {'mp4', 'mov', 'avi', 'mkv', 'webm', 'flv'}
 
# NEW: Swagger/Flasgger configuration
app.config['SWAGGER'] = {
    'title': 'DeepGuard Forensics API',
    'uiversion': 3,
    'description': 'A metadata-based deepfake detection API. '
                   'Upload a video file and receive a forensic verdict '
                   '(AUTHENTIC, SUSPICIOUS, or INCONCLUSIVE) based on '
                   'heuristic analysis of embedded metadata.',
    'version': '1.0.0',
    'contact': {
        'name': 'DeepGuard',
    },
}
swagger = Swagger(app)  # NEW: Initialise Swagger — auto-generates /apidocs
 
# Create uploads folder at module load time
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
    Parse ExifTool date strings into datetime objects for proper comparison.
    Strips timezone offsets before parsing to avoid string comparison errors.
    """
    if not date_str:
        return None
    for sep in ['+', '-']:
        if sep in date_str[10:]:
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
        # 1. SETUP VARIABLES (Add these now)
    filetype = flat.get('filetype', '').lower()
    
    make_val  = str(flat.get('make', '')).lower()
    model_val = str(flat.get('model', '')).lower()
    all_keys  = [str(k).lower() for k in flat.keys()]

    # 2. IDENTIFY DEVICE FAMILY
    is_android = any(brand in make_val or brand in model_val for brand in ['samsung', 'tecno', 'infinix', 'itel', 'transsion']) or \
                 any('android' in k for k in all_keys) or \
                 flat.get('androidversion') is not None

    is_apple = 'apple' in make_val or any('apple' in k for k in all_keys)

 
       # --- 1. Universal Device Identification ---
    # This identifies the "Family" of the device to avoid false positives.
    
    make_val  = str(flat.get('make', '')).lower()
    model_val = str(flat.get('model', '')).lower()
    all_keys  = [str(k).lower() for k in flat.keys()]

    # Capture itel, Samsung, Tecno, Infinix, etc.
    is_android = any(brand in make_val or brand in model_val for brand in ['samsung', 'tecno', 'infinix', 'itel', 'transsion', 'google', 'pixel']) or \
                 any('android' in k for k in all_keys) or \
                 flat.get('androidversion') is not None

    # Capture iPhone 13 and other Apple devices
    is_apple = 'apple' in make_val or any('apple' in k for k in all_keys)


    # --- 2. Refined Heuristic Checks ---

    # Check 1: Hardware Identifiers
    # FIX: Valid if we have Make, Model, OR the Android Version (for itel)
    has_hw_id = bool(flat.get('make') or flat.get('model') or flat.get('androidversion'))
    
    if not has_hw_id and not is_android:
        flags.append({
            "flag":     "Missing Hardware Identifiers",
            "detail":   "No camera Make, Model, or Android identifier found.",
            "severity": "HIGH"
        })


 
        # --- Check 2: Encoder / Software Signature ---
    found_enc = flat.get('encoder') or flat.get('software') or flat.get('writing library')
    
    if found_enc and any(x in str(found_enc).lower() for x in ['ffmpeg', 'lavf', 'handbrake', 'premiere', 'capcut', 'topaz']):
        flags.append({
            "flag":     "Suspicious Encoder Signature",
            "detail":   f"Video encoded with {found_enc}. This is common for AI-generated or edited content.",
            "severity": "HIGH"
        })
    elif not found_enc and not (is_android or is_apple):
        # We only flag missing encoder if we CANNOT identify the phone.
        # itel and iPhones often skip this tag, so we ignore it for them!
        flags.append({
            "flag":     "Encoder Data Absent",
            "detail":   "No encoder tag found. Inconclusive on its own.",
            "severity": "MEDIUM"
        })

 
        # Check 3: MakerNotes / Hardware Signature
    # FIX: Valid if MakerNotes exist OR if it's an identified Apple device.
    # ANDROID PROTECTION: If is_android is True, this check is skipped.
    has_sig = bool(flat.get('makernote') or flat.get('makernotes') or is_apple)
    
    if not has_sig and not is_android and filetype in ('mp4', 'mov', 'quicktime'):
        flags.append({
            "flag":     "Missing MakerNotes",
            "detail":   "No proprietary manufacturer signature found.",
            "severity": "HIGH"
        })



    # Check 4: Timestamp Consistency
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
 
    # Check 5: Container Format Mismatch
    mime = flat.get('mimetype', '')
    GENUINE_MISMATCHES = {
        'mp4':  ['video/x-matroska', 'video/x-flv', 'video/webm'],
        'mov':  ['video/x-matroska', 'video/webm',  'video/x-flv'],
        'mkv':  ['video/mp4', 'video/quicktime',    'video/x-flv'],
        'webm': ['video/mp4', 'video/quicktime',    'video/x-matroska'],
    } 
    ext = filetype
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
    Verdict logic:
      - 2+ HIGH flags              -> SUSPICIOUS
      - 1 HIGH + 1+ MEDIUM flags   -> SUSPICIOUS
      - 1 HIGH alone               -> INCONCLUSIVE
      - 2+ MEDIUM flags alone      -> INCONCLUSIVE
      - No significant flags       -> AUTHENTIC
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
    """
    Serve the DeepGuard frontend interface.
    ---
    tags:
      - Frontend
    responses:
      200:
        description: Returns the HTML forensic analysis interface
    """
    return render_template('index.html')
 
 
@app.route('/analyse', methods=['POST'])
def analyse():
    """
    Analyse a video file for deepfake metadata anomalies.
    ---
    tags:
      - Forensic Analysis
    consumes:
      - multipart/form-data
    parameters:
      - name: video
        in: formData
        type: file
        required: true
        description: >
          Video file to analyse. Supported formats: mp4, mov, avi, mkv, webm, flv.
          Maximum file size: 500 MB.
    responses:
      200:
        description: Forensic analysis completed successfully
        schema:
          type: object
          properties:
            sha256:
              type: string
              description: SHA-256 cryptographic fingerprint of the uploaded file
              example: "a3f5c...9d1e"
            verdict:
              type: object
              properties:
                verdict:
                  type: string
                  description: Final forensic verdict
                  enum: [AUTHENTIC, SUSPICIOUS, INCONCLUSIVE]
                  example: SUSPICIOUS
                explanation:
                  type: string
                  description: Plain-language explanation of the verdict
                  example: "2 high-severity anomalies detected."
            flags:
              type: array
              description: List of individual forensic anomalies detected
              items:
                type: object
                properties:
                  flag:
                    type: string
                    example: "Missing Hardware Identifiers"
                  detail:
                    type: string
                    example: "No camera Make or Model found."
                  severity:
                    type: string
                    enum: [HIGH, MEDIUM, LOW]
                    example: HIGH
      400:
        description: No file selected or unsupported file type
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Unsupported file type. Allowed formats: mp4, mov, avi, mkv, webm, flv"
      413:
        description: File exceeds the 500 MB size limit
        schema:
          type: object
          properties:
            error:
              type: string
              example: "File too large. Maximum allowed upload size is 500 MB."
      500:
        description: ExifTool extraction or internal server error
        schema:
          type: object
          properties:
            error:
              type: string
              example: "ExifTool is not installed or not found in PATH."
    """
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
        if os.path.exists(filepath):
            os.remove(filepath)
 
 
@app.errorhandler(413)
def file_too_large(e):
    """Return a clean JSON error when upload exceeds MAX_CONTENT_LENGTH."""
    return jsonify({"error": "File too large. Maximum allowed upload size is 500 MB."}), 413
 
 
if __name__ == '__main__':
    app.run(debug=True)
