%pip install cryptography

spark.catalog.setCurrentCatalog("purgo_databricks")

# -------------------------------------------------------------------------------------------------
# Databricks PySpark Script: Encrypt PII columns in purgo_playground.customer_360_raw table
# -------------------------------------------------------------------------------------------------
# Purpose:
#   - Encrypt PII columns (name, email, phone, zip) in purgo_playground.customer_360_raw
#   - Store encrypted data in a new table: purgo_playground.customer_360_raw_encrypted_<current_datetime>
#   - Save the AES-256-GCM encryption key as a JSON file in /Volumes/agilisium_playground/purgo_playground/de_dq
#   - Null or empty values in PII columns remain unchanged
#   - If output table exists, it is overwritten
#   - If clone table exists, it is dropped and recreated as a deep clone of the source
#   - All encryption is column-level, per value, and output columns are base64-encoded strings
#   - All error handling and logging is included as per requirements
# -------------------------------------------------------------------------------------------------
# Prerequisites:
#   - 'spark' session is available
#   - 'cryptography' package is installed
#   - Write access to /Volumes/agilisium_playground/purgo_playground/de_dq
#   - Unity Catalog: purgo_databricks, Schema: purgo_playground
# -------------------------------------------------------------------------------------------------

# -- Imports --
from pyspark.sql import functions as F  
from pyspark.sql.types import StringType  
from pyspark.sql.utils import AnalysisException  
from datetime import datetime, timezone  
import base64  
import os  
import json  
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  

# -- Configuration --
CATALOG = "purgo_databricks"
SCHEMA = "purgo_playground"
SRC_TABLE = f"{SCHEMA}.customer_360_raw"
CLONE_TABLE = f"{SCHEMA}.customer_360_raw_clone"
PII_COLS = ["name", "email", "phone", "zip"]
VOLUME_PATH = "/Volumes/agilisium_playground/purgo_playground/de_dq"
ENCRYPTION_ALGORITHM = "AES-256-GCM"

# -- Generate current datetime for output table and key file naming --
CURRENT_DATETIME = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
CURRENT_DATETIME_ISO = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
OUTPUT_TABLE = f"{SCHEMA}.customer_360_raw_encrypted_{CURRENT_DATETIME}"
KEY_FILENAME = f"encryption_key_{CURRENT_DATETIME}.json"
KEY_FILEPATH = os.path.join(VOLUME_PATH, KEY_FILENAME)

# -- Helper: Error logging --
def log_error(msg):
    print(f"[ERROR] {msg}")

# -- Helper: Check if table exists --
def table_exists(table_name):
    try:
        spark.table(table_name)
        return True
    except AnalysisException:
        return False

# -- Helper: Drop table if exists --
def drop_table_if_exists(table_name):
    try:
        spark.sql(f"DROP TABLE IF EXISTS {table_name}")
    except Exception as e:
        log_error(f"Failed to drop table {table_name}: {e}")
        raise

# -- Helper: Deep clone table --
def deep_clone_table(src_table, clone_table):
    try:
        spark.sql(f"CREATE TABLE {clone_table} DEEP CLONE {src_table}")
    except AnalysisException as e:
        log_error(f"Source table {src_table} does not exist")
        raise RuntimeError(f"Source table {src_table} does not exist")
    except Exception as e:
        log_error(f"Failed to deep clone table: {e}")
        raise

# -- Helper: Generate AES-256-GCM key --
def generate_aes256gcm_key():
    return AESGCM.generate_key(bit_length=256)

# -- Helper: Base64 encode key --
def base64_encode_key(key_bytes):
    return base64.b64encode(key_bytes).decode("utf-8")

# -- Helper: Encrypt value with AES-256-GCM, output base64(nonce + ciphertext) --
def encrypt_value_aesgcm(plaintext, key):
    if plaintext is None or (isinstance(plaintext, str) and plaintext == ""):
        return plaintext
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("utf-8")

# -- Helper: Save encryption key file as JSON --
def save_encryption_key_file(key_bytes, algorithm, created_at_iso, filepath):
    key_b64 = base64_encode_key(key_bytes)
    key_metadata = {
        "key": key_b64,
        "algorithm": algorithm,
        "created_at": created_at_iso
    }
    try:
        with open(filepath, "w") as f:
            json.dump(key_metadata, f)
    except Exception as e:
        log_error(f"Permission denied: Unable to write encryption key file to {filepath}")
        raise RuntimeError(f"Permission denied: Unable to write encryption key file to {filepath}")

# -- Helper: Validate output table schema matches input schema --
def validate_schema_match(table1, table2):
    schema1 = spark.table(table1).schema
    schema2 = spark.table(table2).schema
    if len(schema1) != len(schema2):
        raise RuntimeError(f"Schema column count mismatch: {table1} vs {table2}")
    for f1, f2 in zip(schema1, schema2):
        if f1.name != f2.name or f1.dataType != f2.dataType:
            raise RuntimeError(f"Schema mismatch in column {f1.name}: {f1.dataType} vs {f2.dataType}")

# -- Main Logic --

# 1. Drop clone table if exists, then create as deep clone of source
drop_table_if_exists(CLONE_TABLE)
deep_clone_table(SRC_TABLE, CLONE_TABLE)

# 2. Generate encryption key (AES-256-GCM only)
if ENCRYPTION_ALGORITHM != "AES-256-GCM":
    log_error(f"Unsupported encryption algorithm: {ENCRYPTION_ALGORITHM}. Only AES-256-GCM is supported.")
    raise RuntimeError(f"Unsupported encryption algorithm: {ENCRYPTION_ALGORITHM}. Only AES-256-GCM is supported.")
encryption_key = generate_aes256gcm_key()
encryption_key_b64 = base64_encode_key(encryption_key)

# 3. Save encryption key as JSON file in volume location
try:
    save_encryption_key_file(encryption_key, ENCRYPTION_ALGORITHM, CURRENT_DATETIME_ISO, KEY_FILEPATH)
except RuntimeError as e:
    log_error(str(e))
    raise

# 4. Read clone table
try:
    df = spark.table(CLONE_TABLE)
except AnalysisException:
    log_error(f"Clone table {CLONE_TABLE} does not exist after cloning")
    raise

# 5. Define UDF for encryption (per value, base64 output, null/empty passthrough)
def encrypt_udf_factory(key):
    def encrypt_udf(val):
        return encrypt_value_aesgcm(val, key)
    return F.udf(encrypt_udf, StringType())

encrypt_udf = encrypt_udf_factory(encryption_key)

# 6. Encrypt PII columns
for col in PII_COLS:
    df = df.withColumn(col, encrypt_udf(F.col(col)))

# 7. Ensure column count matches target schema before writing
input_schema = spark.table(CLONE_TABLE).schema
if len(df.columns) != len(input_schema):
    log_error("Column count mismatch before writing to output table")
    raise RuntimeError("Column count mismatch before writing to output table")

# 8. Write to output table (overwrite if exists)
try:
    df.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable(OUTPUT_TABLE)
except Exception as e:
    log_error(f"Permission denied: Unable to overwrite output table {OUTPUT_TABLE}")
    raise RuntimeError(f"Permission denied: Unable to overwrite output table {OUTPUT_TABLE}")

# 9. Validate output table schema matches input schema
validate_schema_match(CLONE_TABLE, OUTPUT_TABLE)

# 10. Log success
print(f"PII columns encrypted and written to {OUTPUT_TABLE}")
print(f"Encryption key saved to {KEY_FILEPATH}")

# -------------------------------------------------------------------------------------------------
# End of script
# -------------------------------------------------------------------------------------------------
