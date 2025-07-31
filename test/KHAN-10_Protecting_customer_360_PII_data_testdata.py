%pip install cryptography

# Databricks PySpark test data generation for purgo_playground.customer_360_raw_clone
# All imports are required for test data generation and encryption

from pyspark.sql import SparkSession  
from pyspark.sql.types import (StructType, StructField, LongType, StringType, DateType)  
from pyspark.sql import functions as F  
import base64  
import os  
import json  
from datetime import datetime  
from random import randint, choice, random  
import string  
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  

# Initialize Spark session
spark = SparkSession.builder.getOrCreate()

# Define schema for purgo_playground.customer_360_raw_clone
schema = StructType([
    StructField("id", LongType(), True),
    StructField("name", StringType(), True),
    StructField("email", StringType(), True),
    StructField("phone", StringType(), True),
    StructField("company", StringType(), True),
    StructField("job_title", StringType(), True),
    StructField("address", StringType(), True),
    StructField("city", StringType(), True),
    StructField("state", StringType(), True),
    StructField("country", StringType(), True),
    StructField("industry", StringType(), True),
    StructField("account_manager", StringType(), True),
    StructField("creation_date", DateType(), True),
    StructField("last_interaction_date", DateType(), True),
    StructField("purchase_history", StringType(), True),
    StructField("notes", StringType(), True),
    StructField("zip", StringType(), True)
])

# Helper functions for test data
def random_string(length=10):
    return ''.join(choice(string.ascii_letters) for _ in range(length))

def random_email():
    return random_string(5) + '@' + random_string(3) + '.com'

def random_phone():
    return ''.join(choice(string.digits) for _ in range(10))

def random_zip():
    return ''.join(choice(string.digits) for _ in range(5))

def random_date(start_year=2020, end_year=2024):
    year = randint(start_year, end_year)
    month = randint(1, 12)
    day = randint(1, 28)
    return f"{year}-{month:02d}-{day:02d}"

def random_unicode_string(length=8):
    # Includes some multi-byte and special characters
    chars = string.ascii_letters + string.digits + "éüß漢字😊!@#$%^&*()"
    return ''.join(choice(chars) for _ in range(length))

# Generate 25 diverse test records
test_data = [
    # Happy path
    (1, "John Smith", "john@abc.com", "1234567890", "ABC Inc", "Manager", "123 St", "NY", "NY", "USA", "Tech", "Alice", "2024-07-30", "2024-07-29", "PH1", "Note1", "10001"),
    (2, "", "jane@xyz.com", "", "XYZ LLC", "Director", "456 Ave", "LA", "CA", "USA", "Finance", "Bob", "2024-07-28", "2024-07-27", "PH2", "Note2", ""),
    (3, None, None, None, "DEF Ltd", "Analyst", "789 Rd", "SF", "CA", "USA", "Health", "Carol", "2024-07-26", "2024-07-25", "PH3", "Note3", None),
    # Edge: all PII empty
    (4, "", "", "", "GHI", "Lead", "101 St", "CHI", "IL", "USA", "Retail", "Dave", "2024-07-25", "2024-07-24", "PH4", "Note4", ""),
    # Edge: special/multibyte chars
    (5, "Élise Müller", "élise.müller@exämple.com", "+49-123-4567", "Müller & Söhne", "Entwickler", "Straße 1", "Berlin", "BE", "DE", "IT", "Jürgen", "2024-03-21", "2024-03-22", "PH5", "Notiz", "10115"),
    (6, "山田太郎", "taro.yamada@例え.jp", "08012345678", "株式会社サンプル", "エンジニア", "中央区1-1", "東京", "13", "JP", "Tech", "佐藤", "2024-01-15", "2024-01-16", "PH6", "メモ", "100-0001"),
    (7, "O'Connor", "oconnor.o'neil@irish.ie", "353871234567", "O'Neil & Sons", "CEO", "1 Main St", "Dublin", "D", "IE", "Legal", "Sean", "2023-12-01", "2023-12-02", "PH7", "Note7", "D02X285"),
    (8, "李雷", "li.lei@例子.cn", "13812345678", "示例公司", "经理", "长安街1号", "北京", "BJ", "CN", "Manufacturing", "王芳", "2022-11-11", "2022-11-12", "PH8", "备注", "100000"),
    # Edge: max length, special chars
    (9, random_unicode_string(50), random_unicode_string(30) + "@test.com", random_unicode_string(20), "MaxLen Inc", "Maximizer", "999 Long Rd", "Bigcity", "XX", "ZZ", "Max", "Maximus", "2024-07-01", "2024-07-02", "PH9", "Long note", random_unicode_string(10)),
    # Edge: min length
    (10, "A", "a@b.c", "1", "Min Inc", "Minimizer", "1 Rd", "Small", "S", "US", "Mini", "M", "2024-06-01", "2024-06-02", "PH10", "Short", "1"),
    # Error: out-of-range zip (too long)
    (11, "Test User", "test@user.com", "5555555555", "TestCo", "Tester", "Test St", "Testville", "TS", "US", "QA", "QAMgr", "2024-05-01", "2024-05-02", "PH11", "Note11", "123456789012345"),
    # Error: invalid email format
    (12, "Invalid Email", "not-an-email", "5551234567", "Err Inc", "Err", "Err Rd", "Errcity", "ER", "US", "Err", "ErrMgr", "2024-04-01", "2024-04-02", "PH12", "Note12", "54321"),
    # Error: phone with letters
    (13, "Phone Error", "phone@err.com", "12ABCD3456", "PhoneCo", "PhoneMgr", "Phone St", "Phonetown", "PH", "US", "Telecom", "TelMgr", "2024-03-01", "2024-03-02", "PH13", "Note13", "67890"),
    # NULL handling: some PII null, some not
    (14, None, "null@pii.com", None, "NullCo", "NullMgr", "Null St", "Nullcity", "NU", "US", "Null", "NullMgr", "2024-02-01", "2024-02-02", "PH14", "Note14", None),
    (15, "Null Email", None, "5550001111", "NullMail", "MailMgr", "Mail St", "Mailcity", "MA", "US", "Mail", "MailMgr", "2024-01-01", "2024-01-02", "PH15", "Note15", "11111"),
    (16, "Null Phone", "nullphone@pii.com", None, "NullPhone", "PhoneMgr", "Phone St", "Phonecity", "PH", "US", "Phone", "PhoneMgr", "2023-12-01", "2023-12-02", "PH16", "Note16", "22222"),
    (17, "Null Zip", "nullzip@pii.com", "5552223333", "NullZip", "ZipMgr", "Zip St", "Zipcity", "ZI", "US", "Zip", "ZipMgr", "2023-11-01", "2023-11-02", "PH17", "Note17", None),
    # Special: whitespace only
    (18, " ", " ", " ", "White Inc", "WhiteMgr", "White St", "Whitecity", "WH", "US", "White", "WhiteMgr", "2023-10-01", "2023-10-02", "PH18", "Note18", " "),
    # Special: emoji in PII
    (19, "😊", "smile😊@mail.com", "12345😊678", "Emoji Inc", "EmojiMgr", "Emoji St", "Emojicity", "EM", "US", "Emoji", "EmojiMgr", "2023-09-01", "2023-09-02", "PH19", "Note19", "54321"),
    # Special: SQL injection attempt
    (20, "'; DROP TABLE users;--", "hacker@evil.com", "9999999999", "Hackers", "Hacker", "Evil St", "Hackcity", "HK", "US", "Cyber", "HackMgr", "2023-08-01", "2023-08-02", "PH20", "Note20", "00000"),
    # Special: multi-byte, right-to-left
    (21, "مرحبا", "arabic@مثال.كوم", "٠١٢٣٤٥٦٧٨٩", "شركة", "مدير", "شارع ١", "دبي", "DU", "AE", "IT", "مدير", "2023-07-01", "2023-07-02", "PH21", "ملاحظة", "12345"),
    # Special: long unicode
    (22, "𠜎𠜱𠝹𠱓", "unicode@𠜎.com", "𠜎𠜱𠝹𠱓", "Unicode Inc", "UnicodeMgr", "Unicode St", "Unicodecity", "UN", "US", "Unicode", "UnicodeMgr", "2023-06-01", "2023-06-02", "PH22", "Note22", "99999"),
    # Edge: all fields null
    (23, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None),
    # Edge: all fields empty
    (24, None, "", "", "", "", "", "", "", "", "", "", None, None, "", "", ""),
    # Edge: random data
    (25, randint(100, 999), random_unicode_string(12), random_email(), random_phone(), random_string(8), random_string(6), random_string(10), random_string(5), random_string(2), random_string(3), random_string(7), random_string(5), random_date(), random_date(), random_string(4), random_string(6), random_zip()),
]

# Convert date strings to datetime.date objects for Spark
from datetime import date  
def to_date(val):
    if val is None or val == "":
        return None
    try:
        return datetime.strptime(val, "%Y-%m-%d").date()
    except Exception:
        return None

test_data_converted = []
for row in test_data:
    row = list(row)
    # creation_date
    row[12] = to_date(row[12])
    # last_interaction_date
    row[13] = to_date(row[13])
    test_data_converted.append(tuple(row))

# Create DataFrame
df = spark.createDataFrame(test_data_converted, schema=schema)

# Write test data to purgo_playground.customer_360_raw_clone (overwrite)
df.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable("purgo_playground.customer_360_raw_clone")

# -- Test data generation complete for purgo_playground.customer_360_raw_clone --
