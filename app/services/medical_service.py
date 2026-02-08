import re
from typing import Optional

NER_MEDICATIONS = [
    "Paracetamol", "Ibuprofen", "Aspirin", "Metformin", "Amoxicillin",
    "Lisinopril", "Atorvastatin", "Albuterol", "Tylenol", "Advil",
]
NER_CONDITIONS = [
    "Viral Fever", "Migraine", "Diabetes", "Hypertension", "Asthma",
    "Pneumonia", "Bronchitis", "Covid-19", "Influenza", "Headache",
    "Fever", "Infection", "Nausea",
]

ICD10_COMMON_CODES: dict[str, str] = {
    "fever": "R50.9", "viral fever": "B34.9", "typhoid": "A01.0",
    "cough": "R05", "dry cough": "R05.3", "headache": "R51",
    "migraine": "G43.9", "common cold": "J00", "flu": "J11.1",
    "influenza": "J11.1", "pneumonia": "J18.9", "bronchitis": "J40",
    "asthma": "J45.909", "hypertension": "I10", "high blood pressure": "I10",
    "diabetes": "E11.9", "abdominal pain": "R10.9", "chest pain": "R07.9",
    "nausea": "R11.0", "vomiting": "R11.1", "diarrhea": "R19.7",
    "fatigue": "R53.83", "anxiety": "F41.9", "depression": "F32.9",
    "infection": "B99.9",
}

def highlight_entities(text: Optional[str]) -> str:
    if not text:
        return ""
    text = re.sub(r"(\d+\s?(mg|ml|g|kg|mcg))", r'<span class="entity-dosage">\1</span>', text, flags=re.IGNORECASE)
    for med in NER_MEDICATIONS:
        pattern = re.compile(r"\b(" + re.escape(med) + r")\b", re.IGNORECASE)
        text = pattern.sub(r'<span class="entity-med">\1</span>', text)
    for cond in NER_CONDITIONS:
        pattern = re.compile(r"\b(" + re.escape(cond) + r")\b", re.IGNORECASE)
        text = pattern.sub(r'<span class="entity-condition">\1</span>', text)
    return text

def get_icd_code(diagnosis: Optional[str]) -> str:
    if not diagnosis:
        return "Not Found"
    text = diagnosis.lower()
    for key, code in ICD10_COMMON_CODES.items():
        if key in text:
            return code
    if "pain" in text: return "R52"
    if "viral" in text: return "B34.9"
    if "bacterial" in text: return "A49.9"
    return "Unspecified"

def clean_medical_text(text: Optional[str]) -> str:
    if not text:
        return ""
    text = re.sub(r"\[\*\*", "", text)
    text = re.sub(r"\*\*\]", "", text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    return text.strip()
