"""Database migration utility for MediAssist.

This module provides functions to migrate data from CSV files to the database.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime

from app import Case, User, app, db


def migrate() -> None:
    """Migrate users and cases from CSV files to the database.

    Reads users.csv and cases.csv from the current directory and imports
    them into the database, skipping any records that already exist.
    """
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()

        print("Migrating Users...")
        _migrate_users()

        print("Migrating Cases...")
        _migrate_cases()


def _migrate_users() -> None:
    """Migrate users from users.csv to the database."""
    if not os.path.exists("users.csv"):
        print("users.csv not found.")
        return

    with open("users.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                user_id = int(row["id"])
                if not User.query.get(user_id):
                    user = User(
                        id=user_id,
                        username=row["username"],
                        password_hash=row["password_hash"],
                        role=row["role"],
                        full_name=row["full_name"],
                        specialty=row.get("specialty"),
                        doctor_unique_id=row.get("doctor_unique_id"),
                    )
                    db.session.add(user)
            except Exception as e:
                print(f"Error migrating user {row.get('username')}: {e}")

    db.session.commit()
    print("Users migrated.")


def _migrate_cases() -> None:
    """Migrate cases from cases.csv to the database."""
    if not os.path.exists("cases.csv"):
        print("cases.csv not found.")
        return

    with open("cases.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            case_id = row["case_id"]
            if not Case.query.get(case_id):
                try:
                    timestamp = _parse_timestamp(row["timestamp"])
                    new_case = Case(
                        id=case_id,
                        patient_id=int(row["patient_id"]),
                        doctor_id=int(row["doctor_id"]),
                        timestamp=timestamp,
                        raw_data=json.loads(row["raw_data_json"]),
                        ai_analysis=json.loads(row["ai_analysis_json"]),
                        status=row["status"],
                    )
                    db.session.add(new_case)
                except Exception as e:
                    print(f"Error migrating case {case_id}: {e}")

    db.session.commit()
    print("Cases migrated.")


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse a timestamp string into a datetime object.

    Args:
        ts_str: The timestamp string to parse.

    Returns:
        A datetime object, defaulting to now() if parsing fails.
    """
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        try:
            return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            return datetime.now()


if __name__ == "__main__":
    migrate()
