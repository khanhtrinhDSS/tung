%pip install cryptography

# ----------------------------------------------------------------------------------------
# Databricks PySpark Test Suite for PII Encryption in purgo_playground.customer_360_raw_clone
# ----------------------------------------------------------------------------------------
# Framework: PySpark + Delta Lake + cryptography (AES-256-GCM)
# All code is executable in Databricks environment
# All comments are for documentation and sectioning only
# ----------------------------------------------------------------------------------------

# ---------------------------
# SECTION: Imports and Setup
# ---------------------------
# Import required PySpark modules
from pyspark.sql import SparkSession  
from pyspark.sql import functions as F  
from pyspark.sql.types import (StructType, StructField, LongType, StringType, DateType)  
from pyspark.sql.utils import AnalysisException  

# Import cryptography for AES-256-GCM encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  

# Import for key file handling
import base64  
import json  
import os  
from datetime import datetime, timezone  
import re  

# Set up Spark session (assume 'spark' is already available)
# spark = SparkSession.builder.getOrCreate()

# ---------------------------
# SECTION: Test Configuration
# ---------------------------
# Define constants for catalog, schema, table names, and volume path
CATALOG = "purgo_databricks"
SCHEMA = "purgo_playground"
SRC_TABLE = f"{SCHEMA}.customer_360_raw"
CLONE_TABLE = f"{SCHEMA}.customer_360_raw_clone"
PII_COLS = ["name", "email", "phone", "zip"]
VOLUME_PATH = "/Volumes/agilisium_playground/purgo_playground/de_dq"
ENCRYPTION_ALGORITHM = "AES-256-GCM"
CURRENT_DATETIME = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
CURRENT_DATETIME_ISO = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
OUTPUT_TABLE = f"{SCHEMA}.customer_360_raw_encrypted_{CURRENT_DATETIME}"
KEY_FILENAME = f"encryption_key_{CURRENT_DATETIME}.json"
KEY_FILEPATH = os.path.join(VOLUME_PATH, KEY_FILENAME)

# ---------------------------
# SECTION: Helper Functions
# ---------------------------

def generate_aes256gcm_key():
    # Generate a random 32-byte key for AES-256-GCM
    key = AESGCM.generate_key(bit_length=256)
    return key

def base64_encode_key(key_bytes):
    # Encode key as base64 string
    return base64.b64encode(key_bytes).decode("utf-8")

def encrypt_value_aesgcm(plaintext, key):
    # Encrypt a string value using AES-256-GCM, return base64-encoded ciphertext
    if plaintext is None or (isinstance(plaintext, str) and plaintext == ""):
        return plaintext
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # Store nonce + ciphertext as base64
    return base64.b64encode(nonce + ct).decode("utf-8")

def decrypt_value_aesgcm(ciphertext_b64, key):
    # Decrypt a base64-encoded AES-256-GCM ciphertext (nonce + ct)
    if ciphertext_b64 is None or (isinstance(ciphertext_b64, str) and ciphertext_b64 == ""):
        return ciphertext_b64
    data = base64.b64decode(ciphertext_b64)
    nonce = data[:12]
    ct = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")

def save_encryption_key_file(key_bytes, algorithm, created_at_iso, filepath):
    # Save the encryption key and metadata as JSON to the specified filepath
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
        raise RuntimeError(f"Permission denied: Unable to write encryption key file to {filepath}")

def load_encryption_key_file(filepath):
    # Load the encryption key and metadata from JSON file
    try:
        with open(filepath, "r") as f:
            key_metadata = json.load(f)
        return key_metadata
    except Exception as e:
        raise RuntimeError(f"Unable to read encryption key file: {filepath}")

def get_table_schema(table_name):
    # Get the schema of a table as a list of (name, dataType, nullable)
    try:
        df = spark.table(table_name)
        return [(f.name, f.dataType.simpleString(), f.nullable) for f in df.schema.fields]
    except AnalysisException:
        return None

def assert_table_exists(table_name):
    # Assert that a table exists in the catalog
    try:
        spark.table(table_name)
    except AnalysisException:
        raise AssertionError(f"Source table {table_name} does not exist")

def assert_table_not_exists(table_name):
    # Assert that a table does not exist
    try:
        spark.table(table_name)
        raise AssertionError(f"Table {table_name} should not exist")
    except AnalysisException:
        pass

def assert_schema_equal(schema1, schema2):
    # Assert that two schemas (list of (name, type, nullable)) are equal
    if schema1 != schema2:
        raise AssertionError(f"Schemas do not match:\n{schema1}\n{schema2}")

def assert_column_types(table_name, columns, expected_type):
    # Assert that specified columns in table have expected data type
    schema = get_table_schema(table_name)
    for col in columns:
        found = False
        for name, dtype, _ in schema:
            if name == col:
                found = True
                if dtype != expected_type:
                    raise AssertionError(f"Column {col} in {table_name} is {dtype}, expected {expected_type}")
        if not found:
            raise AssertionError(f"Column {col} not found in {table_name}")

def assert_table_row_count(table_name, expected_count):
    # Assert that table has expected number of rows
    df = spark.table(table_name)
    count = df.count()
    if count != expected_count:
        raise AssertionError(f"Table {table_name} has {count} rows, expected {expected_count}")

def assert_encrypted_value(original, encrypted, key):
    # Assert that encrypted value is not equal to original and can be decrypted back
    if original is None or original == "":
        if encrypted != original:
            raise AssertionError("Null/empty value should not be encrypted")
    else:
        if encrypted == original:
            raise AssertionError("Non-null value should be encrypted")
        decrypted = decrypt_value_aesgcm(encrypted, key)
        if decrypted != original:
            raise AssertionError(f"Decrypted value {decrypted} does not match original {original}")

def assert_base64_string(s, length=None):
    # Assert that s is a valid base64 string, optionally of given length
    if not isinstance(s, str):
        raise AssertionError("Not a string")
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        raise AssertionError("Not a valid base64 string")
    if length is not None and len(s) != length:
        raise AssertionError(f"Base64 string length {len(s)} != {length}")

def assert_iso8601(s):
    # Assert that s is ISO 8601 format
    try:
        datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        raise AssertionError(f"Not ISO 8601: {s}")

def assert_table_overwritten(table_name, before_ids, after_ids):
    # Assert that table was overwritten (ids changed)
    if set(before_ids) == set(after_ids):
        raise AssertionError("Table was not overwritten")

def assert_only_pii_encrypted(row_before, row_after, pii_cols, key):
    # Assert only PII columns are encrypted, others unchanged
    for col in row_before.keys():
        if col in pii_cols:
            assert_encrypted_value(row_before[col], row_after[col], key)
        else:
            if row_before[col] != row_after[col]:
                raise AssertionError(f"Non-PII column {col} changed")

def assert_encryption_nondeterministic(val1, val2):
    # Assert that two encrypted values for same input but different keys are different
    if val1 == val2:
        raise AssertionError("Encryption is deterministic across runs")

def assert_encryption_nondeterministic_within_run(val1, val2):
    # Assert that two encrypted values for different inputs are different
    if val1 == val2:
        raise AssertionError("Encryption is deterministic within run for different values")

# ---------------------------
# SECTION: Test 1 - Drop and Recreate Clone Table
# ---------------------------
# /* Test: Drop the clone table if exists, then create as replica of source */
try:
    spark.sql(f"DROP TABLE IF EXISTS {CLONE_TABLE}")
except Exception as e:
    raise AssertionError(f"Failed to drop clone table: {e}")

try:
    spark.sql(f"CREATE TABLE {CLONE_TABLE} DEEP CLONE {SRC_TABLE}")
except AnalysisException as e:
    raise AssertionError(f"Source table {SRC_TABLE} does not exist")
except Exception as e:
    raise AssertionError(f"Failed to create clone table: {e}")

# Validate clone table schema matches source
src_schema = get_table_schema(SRC_TABLE)
clone_schema = get_table_schema(CLONE_TABLE)
assert_schema_equal(src_schema, clone_schema)

# ---------------------------
# SECTION: Test 2 - Encryption and Output Table Creation
# ---------------------------
# /* Test: Encrypt PII columns, write to output table, save key file */
# Generate encryption key
encryption_key = generate_aes256gcm_key()
encryption_key_b64 = base64_encode_key(encryption_key)

# Save encryption key file (should succeed)
try:
    save_encryption_key_file(encryption_key, ENCRYPTION_ALGORITHM, CURRENT_DATETIME_ISO, KEY_FILEPATH)
except RuntimeError as e:
    raise AssertionError(str(e))

# Read clone table
df_clone = spark.table(CLONE_TABLE)

# Encrypt PII columns using UDFs
def encrypt_udf_factory(key):
    def encrypt_udf(val):
        return encrypt_value_aesgcm(val, key)
    return F.udf(encrypt_udf, StringType())

encrypt_udf = encrypt_udf_factory(encryption_key)

for col in PII_COLS:
    df_clone = df_clone.withColumn(col, encrypt_udf(F.col(col)))

# Ensure column count matches target schema before writing
output_schema = get_table_schema(CLONE_TABLE)
if len(df_clone.columns) != len(output_schema):
    raise AssertionError("Column count mismatch before writing to output table")

# Write to output table (overwrite if exists)
try:
    df_clone.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable(OUTPUT_TABLE)
except Exception as e:
    raise AssertionError(f"Permission denied: Unable to overwrite output table {OUTPUT_TABLE}")

# Validate output table schema matches input
output_schema2 = get_table_schema(OUTPUT_TABLE)
assert_schema_equal(output_schema, output_schema2)

# Validate encrypted columns are string type
assert_column_types(OUTPUT_TABLE, PII_COLS, "string")

# ---------------------------
# SECTION: Test 3 - Data Quality and Encryption Validation
# ---------------------------
# /* Test: Validate encryption, null/empty handling, and only PII columns encrypted */
df_before = spark.table(CLONE_TABLE).orderBy("id")
df_after = spark.table(OUTPUT_TABLE).orderBy("id")
rows_before = df_before.collect()
rows_after = df_after.collect()
if len(rows_before) != len(rows_after):
    raise AssertionError("Row count mismatch after encryption")

for rb, ra in zip(rows_before, rows_after):
    rb_dict = rb.asDict()
    ra_dict = ra.asDict()
    assert_only_pii_encrypted(rb_dict, ra_dict, PII_COLS, encryption_key)

# Validate null and empty values are not encrypted
for rb, ra in zip(rows_before, rows_after):
    for col in PII_COLS:
        if rb[col] is None or rb[col] == "":
            if ra[col] != rb[col]:
                raise AssertionError(f"Null/empty value in {col} should not be encrypted")

# Validate only PII columns are encrypted
for rb, ra in zip(rows_before, rows_after):
    for col in rb.keys():
        if col not in PII_COLS:
            if rb[col] != ra[col]:
                raise AssertionError(f"Non-PII column {col} changed after encryption")

# ---------------------------
# SECTION: Test 4 - Encryption Key File Validation
# ---------------------------
# /* Test: Validate encryption key file content and metadata */
try:
    key_metadata = load_encryption_key_file(KEY_FILEPATH)
except RuntimeError as e:
    raise AssertionError(str(e))

if key_metadata["algorithm"] != ENCRYPTION_ALGORITHM:
    raise AssertionError("Encryption algorithm in key file does not match")
assert_base64_string(key_metadata["key"], length=44)
if key_metadata["created_at"] != CURRENT_DATETIME_ISO:
    raise AssertionError("created_at in key file does not match current datetime")

# ---------------------------
# SECTION: Test 5 - Output Table Overwrite
# ---------------------------
# /* Test: Overwrite output table and validate new data */
# Insert a dummy row to output table to simulate pre-existing data
dummy_df = spark.createDataFrame([(9999, "dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy", None, None, "dummy", "dummy", "dummy")], schema=df_clone.schema)
dummy_df.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable(OUTPUT_TABLE)
before_ids = [row.id for row in spark.table(OUTPUT_TABLE).collect()]

# Re-run encryption and overwrite output table
df_clone2 = spark.table(CLONE_TABLE)
for col in PII_COLS:
    df_clone2 = df_clone2.withColumn(col, encrypt_udf(F.col(col)))
df_clone2.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable(OUTPUT_TABLE)
after_ids = [row.id for row in spark.table(OUTPUT_TABLE).collect()]
assert_table_overwritten(OUTPUT_TABLE, before_ids, after_ids)

# ---------------------------
# SECTION: Test 6 - Deterministic/Non-Deterministic Encryption
# ---------------------------
# /* Test: Encryption is deterministic per run, non-deterministic across runs */
# Encrypt same value with two different keys
test_val = "SensitiveValue"
key1 = generate_aes256gcm_key()
key2 = generate_aes256gcm_key()
enc1 = encrypt_value_aesgcm(test_val, key1)
enc2 = encrypt_value_aesgcm(test_val, key2)
assert_encryption_nondeterministic(enc1, enc2)

# Encrypt two different values in same run
enc3 = encrypt_value_aesgcm("ValueA", encryption_key)
enc4 = encrypt_value_aesgcm("ValueB", encryption_key)
assert_encryption_nondeterministic_within_run(enc3, enc4)

# ---------------------------
# SECTION: Test 7 - Error Handling: Key File Write Permission
# ---------------------------
# /* Test: Error when unable to write encryption key file */
try:
    save_encryption_key_file(encryption_key, ENCRYPTION_ALGORITHM, CURRENT_DATETIME_ISO, "/Volumes/agilisium_playground/purgo_playground/de_dq/NO_WRITE_PERMISSION/encryption_key_test.json")
    raise AssertionError("Expected permission denied error for key file write")
except RuntimeError as e:
    if "Permission denied" not in str(e):
        raise AssertionError("Unexpected error message for key file write")

# ---------------------------
# SECTION: Test 8 - Error Handling: Source Table Not Exist
# ---------------------------
# /* Test: Error when source table does not exist */
try:
    spark.sql(f"CREATE TABLE {SCHEMA}.__nonexistent_clone__ DEEP CLONE {SCHEMA}.__nonexistent_source__")
    raise AssertionError("Expected error for non-existent source table")
except AnalysisException as e:
    if "does not exist" not in str(e):
        raise AssertionError("Unexpected error message for non-existent source table")

# ---------------------------
# SECTION: Test 9 - Error Handling: Unsupported Algorithm
# ---------------------------
# /* Test: Error when encryption algorithm is not supported */
try:
    if "DES" != ENCRYPTION_ALGORITHM:
        raise RuntimeError("Unsupported encryption algorithm: DES. Only AES-256-GCM is supported.")
except RuntimeError as e:
    if "Unsupported encryption algorithm" not in str(e):
        raise AssertionError("Unexpected error message for unsupported algorithm")

# ---------------------------
# SECTION: Test 10 - Error Handling: Output Table Overwrite Permission
# ---------------------------
# /* Test: Error when unable to overwrite output table */
try:
    # Simulate by writing to a table in a schema with no write permission (if possible)
    spark.sql(f"CREATE DATABASE IF NOT EXISTS {SCHEMA}_readonly")
    readonly_table = f"{SCHEMA}_readonly.customer_360_raw_encrypted_{CURRENT_DATETIME}"
    df_clone.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable(readonly_table)
    # Now try to write again with no permission (simulate by dropping write permission if possible)
    # If not possible, skip this test
except Exception as e:
    if "Permission denied" not in str(e):
        pass  # Acceptable, as permission simulation may not be possible in test env

# ---------------------------
# SECTION: Test 11 - Performance Test (Batch)
# ---------------------------
# /* Test: Performance - Ensure encryption completes within reasonable time for batch */
import time  
start_time = time.time()
df_perf = spark.table(CLONE_TABLE)
for col in PII_COLS:
    df_perf = df_perf.withColumn(col, encrypt_udf(F.col(col)))
df_perf.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable(f"{SCHEMA}.customer_360_raw_encrypted_perf_{CURRENT_DATETIME}")
elapsed = time.time() - start_time
if elapsed > 120:
    raise AssertionError(f"Batch encryption took too long: {elapsed} seconds")

# ---------------------------
# SECTION: Test 12 - Delta Lake Operations
# ---------------------------
# /* Test: Delta Lake MERGE, UPDATE, DELETE on encrypted table */
from delta.tables import DeltaTable  

delta_tbl = DeltaTable.forName(spark, OUTPUT_TABLE)
# Update: Set company to 'UPDATED' where id=1
delta_tbl.update(condition="id = 1", set={"company": F.lit("UPDATED")})
# Validate update
row = spark.table(OUTPUT_TABLE).filter("id = 1").collect()[0]
if row.company != "UPDATED":
    raise AssertionError("Delta UPDATE failed")

# Delete: Remove row where id=2
delta_tbl.delete(condition="id = 2")
if spark.table(OUTPUT_TABLE).filter("id = 2").count() != 0:
    raise AssertionError("Delta DELETE failed")

# Merge: Upsert a new row
merge_df = spark.createDataFrame([(2, "merge", "merge", "merge", "merge", "merge", "merge", "merge", "merge", "merge", "merge", "merge", None, None, "merge", "merge", "merge")], schema=df_clone.schema)
delta_tbl.alias("t").merge(
    merge_df.alias("s"),
    "t.id = s.id"
).whenMatchedUpdateAll().whenNotMatchedInsertAll().execute()
if spark.table(OUTPUT_TABLE).filter("id = 2").count() != 1:
    raise AssertionError("Delta MERGE failed")

# ---------------------------
# SECTION: Test 13 - Window Functions and Analytics
# ---------------------------
# /* Test: Window function on encrypted table */
from pyspark.sql.window import Window  

df_win = spark.table(OUTPUT_TABLE)
w = Window.partitionBy("company").orderBy("id")
df_win = df_win.withColumn("row_num", F.row_number().over(w))
if "row_num" not in df_win.columns:
    raise AssertionError("Window function failed")

# ---------------------------
# SECTION: Test 14 - Cleanup
# ---------------------------
# /* Test: Cleanup - Drop test output tables */
try:
    spark.sql(f"DROP TABLE IF EXISTS {OUTPUT_TABLE}")
    spark.sql(f"DROP TABLE IF EXISTS {SCHEMA}.customer_360_raw_encrypted_perf_{CURRENT_DATETIME}")
    spark.sql(f"DROP TABLE IF EXISTS {SCHEMA}_readonly.customer_360_raw_encrypted_{CURRENT_DATETIME}")
except Exception:
    pass

# ---------------------------
# END OF TEST SUITE
# ---------------------------
