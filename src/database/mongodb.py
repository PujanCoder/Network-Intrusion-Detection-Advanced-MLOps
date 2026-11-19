import os

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")

DATABASE_NAME = os.getenv(
    "MONGODB_DATABASE",
    "network_intrusion_db"
)

RAW_COLLECTION = os.getenv(
    "MONGODB_RAW_COLLECTION",
    "raw_flows"
)

if not MONGODB_URI:
    raise ValueError("MONGODB_URI is missing from .env")


client = MongoClient(
    MONGODB_URI,
    serverSelectionTimeoutMS=5000
)

database = client[DATABASE_NAME]

raw_flows = database[RAW_COLLECTION]


def test_connection():

    try:
        client.admin.command("ping")

        print("MongoDB connection successful!")

        print(f"Database: {DATABASE_NAME}")

        print(f"Collection: {RAW_COLLECTION}")

    except ConnectionFailure as error:

        raise RuntimeError(
            f"MongoDB connection failed: {error}"
        )


if __name__ == "__main__":
    test_connection()
    client.close()