
import csv
import json
import os
from datetime import datetime
from app import app, db, User, Case

def migrate():
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        print("Migrating Users...")
        # MIGRATE USERS
        if os.path.exists('users.csv'):
            with open('users.csv', 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        user_id = int(row['id'])
                        if not User.query.get(user_id):
                            user = User(
                                id=user_id,
                                username=row['username'],
                                password_hash=row['password_hash'],
                                role=row['role'],
                                full_name=row['full_name'],
                                specialty=row.get('specialty'),
                                doctor_unique_id=row.get('doctor_unique_id')
                            )
                            db.session.add(user)
                    except Exception as e:
                        print(f"Error migrating user {row.get('username')}: {e}")
            db.session.commit()
            print("Users migrated.")
        else:
            print("users.csv not found.")

        print("Migrating Cases...")
        # MIGRATE CASES
        if os.path.exists('cases.csv'):
            with open('cases.csv', 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    case_id = row['case_id']
                    if not Case.query.get(case_id):
                        try:
                            # Handle timestamp parsing
                            ts_str = row['timestamp']
                            try:
                                timestamp = datetime.fromisoformat(ts_str)
                            except ValueError:
                                try:
                                    timestamp = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S.%f')
                                except:
                                    timestamp = datetime.now()

                            new_case = Case(
                                id=case_id,
                                patient_id=int(row['patient_id']),
                                doctor_id=int(row['doctor_id']),
                                timestamp=timestamp,
                                raw_data=json.loads(row['raw_data_json']),
                                ai_analysis=json.loads(row['ai_analysis_json']),
                                status=row['status']
                            )
                            db.session.add(new_case)
                        except Exception as e:
                            print(f"Error migrating case {case_id}: {e}")
            db.session.commit()
            print("Cases migrated.")
        else:
            print("cases.csv not found.")

if __name__ == '__main__':
    migrate()
