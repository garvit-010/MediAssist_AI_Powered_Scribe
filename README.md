# MediAssist - AI-Powered Clinical Scribe & Patient Communication System

MediAssist is a full-stack, role-based medical documentation system that converts raw patient symptoms into dual-purpose clinical intelligence. It bridges the communication gap between patients and doctors while preserving clinical accuracy, trust, and documentation efficiency.

## Key Features

- **Dual-View Generation:** Generates synchronized outputs for two distinct audiences:
    - **Patient View:** Plain-language summary (Hindi/English) for better understanding.
    - **Doctor View:** Structured SOAP notes (English) for clinical records.
    
- **Local AI Privacy:** Utilizes **Llama 3** (via Ollama) running locally to ensure patient data privacy and offline capability.

- **Enterprise-Grade Database:** Powered by **PostgreSQL (Neon DB)** for scalable, secure, and relational data storage, replacing legacy CSV systems.

- **Role-Based Access Control (RBAC):**
    - Patients: Submit symptoms, view their own case summaries.
    - Doctors: Review assigned cases, access detailed clinical SOAP notes.

- **Strict Structured Output:** Enforces deterministic JSON outputs from the AI model to ensure consistency and machine-readability.

- **Multi-Language Support:** Full support for English and Hindi to cater to diverse patient demographics.

## System Architecture

The application is built using a modern, lightweight stack:

- **Backend:** Flask (Python)
- **Database:** PostgreSQL (via Neon Serverless Postgres)
- **ORM:** SQLAlchemy
- **AI Logic:** Llama 3 (running via Ollama)
- **Frontend:** HTML5, CSS3, JavaScript (Jinja2 Templates)

## Screenshots

### Login Page
![Login Page](./assets/Login_Page.jpeg)

### Patient Registration / Intake
![Registration Form](./assets/reg_form.jpeg)

### AI-Generated Patient Summary (Patient View)
![AI Summary](./assets/AI_summary.jpeg)

### Doctor Dashboard
![Doctor Dashboard](./assets/Doc_Dashboard.jpeg)

### Clinical SOAP Note (Doctor View)
![SOAP Note](./assets/Doc_Soap.jpeg)

## Installation and Setup

Follow these steps to set up the project locally.

### 1. Prerequisites

Ensure you have the following installed:
- Python 3.9 or higher
- [Ollama](https://ollama.com/) (for running Llama 3 locally)
- A Neon PostgreSQL database (or any PostgreSQL instance)

### 2. Configure AI Model

1. Install Ollama from the official website.
2. Pull the Llama 3 model:
   ```bash
   ollama pull llama3
   ```
3. Ensure the Ollama service is running on `http://localhost:11434`.

### 3. Clone Repository

```bash
git clone https://github.com/your-username/MediAssist_AI_Powered_Scribe.git
cd MediAssist_AI_Powered_Scribe
```

### 4. Install Dependencies

Create a virtual environment and install the required packages:

```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### 5. Environment Configuration

Create a `.env` file in the root directory and add the following configuration:

```ini
# Flask Security
FLASK_SECRET_KEY="your-secure-random-key"

# Database Connection (Neon Postgres)
DATABASE_URL="postgresql://user:password@endpoint.neon.tech/dbname?sslmode=require"

# AI Configuration (Optional override)
# OLLAMA_API_URL="http://localhost:11434/api/generate"
```

### 6. Database Initialization

Initialize the database schema and migrate any existing data:

```bash
# This will create tables and migrate data from legacy CSV files if present
python migrate_db.py
```

### 7. Run the Application

Start the Flask development server:

```bash
python app.py
```

## 🐳 Docker Support

To run the application using Docker:

1. **Build and Run:**
   ```bash
   docker-compose up --build
   ```

Access the application at `http://127.0.0.1:5000`.

## Demo Workflow

1. **Patient Access:**
   - Log in as a patient (Demo credentials created during migration).
   - Navigate to **Intake Form**.
   - Input symptoms and select a doctor.
   - Submit for AI Processing.

2. **AI Processing:**
   - The system sends data to the local Llama 3 model.
   - Generates a patient-friendly summary and a clinical SOAP note.

3. **Doctor Review:**
   - Log in as a doctor.
   - View the **Doctor Dashboard**.
   - Select the patient case to view the structured SOAP note and risk assessment.

## License

This project is licensed under the MIT License.
