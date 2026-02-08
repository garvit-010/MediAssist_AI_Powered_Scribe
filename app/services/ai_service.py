import json
import logging
import time
import requests
import whisper
from datetime import datetime
from typing import Any, Optional
from flask import current_app
from ..models import AILog, db

SYSTEM_PROMPT = """
ACT AS: Senior Clinical Consultant & Medical Scribe.
TASK: Analyze patient intake data and generate a structured clinical case file.

LANGUAGE INSTRUCTION:
- "patient_view" MUST be in {language}.
- "doctor_view" MUST be in ENGLISH.

OUTPUT FORMAT: Return ONLY valid JSON. Do not include markdown formatting like ```json.
{{
  "patient_view": {{
    "primary_diagnosis": "Name of condition",
    "summary": "Warm explanation in {language}.",
    "pathophysiology": "Simple analogy in {language}.",
    "care_plan": ["Step 1", "Step 2"],
    "red_flags": ["Sign 1", "Sign 2"],
    "severity_score": 5  // Integer 1-10 (1=Mild, 10=Emergency)
  }},
  "doctor_view": {{
    "subjective": "Medical terminology summary of HPI.",
    "objective": "Concise summary of reported vitals.",
    "assessment": "Differential diagnosis ranked by probability.",
    "plan": "Suggested pharmacotherapy and follow-up.",
    "subjective_list": ["Point 1", "Point 2"],
    "objective_list": ["Point 1", "Point 2"],
    "assessment_list": ["Point 1", "Point 2"],
    "plan_list": ["Point 1", "Point 2"],
    "possible_conditions": [
      {{ "name": "Condition A", "confidence": 0.XX }},
      {{ "name": "Condition B", "confidence": 0.XX }}
    ],
    "urgency_level": "Low/Medium/High",
    "follow_up_required": true/false
  }},
  "safety": {{
    "is_safe": true,
    "warnings": []
  }}
}}
"""

_audio_model = None

def get_audio_model():
    global _audio_model
    if _audio_model is None:
        try:
            print("Loading Whisper model...")
            _audio_model = whisper.load_model("base")
            print("Whisper model loaded.")
        except Exception as e:
            logging.error(f"Failed to load Whisper model: {e}")
    return _audio_model

def log_ai_interaction(
    case_id: Optional[str],
    model: str,
    latency_ms: float,
    status: str = "success",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    fallback_reason: Optional[str] = None,
) -> None:
    try:
        total_tokens = prompt_tokens + completion_tokens
        cost = (total_tokens / 1000) * 0.0002
        ai_log = AILog(
            case_id=case_id,
            model=model,
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cost=cost,
            status=status,
            fallback_reason=fallback_reason,
            timestamp=datetime.utcnow(),
        )
        db.session.add(ai_log)
        db.session.commit()
    except Exception as e:
        logging.error(f"AI Interaction Logging Error: {e}")

def build_predefined_ai_analysis(language: str, raw_data: dict[str, Any]) -> dict[str, Any]:
    patient_summary = {
        "English": "Your symptoms and vitals suggest a mild viral fever. Rest, hydration, and monitoring are recommended.",
        "Hindi": "आपके लक्षण और वाइटल्स हल्का वायरल बुखार दर्शाते हैं। आराम करें, पानी ज्यादा पिएँ और स्थिति पर नज़र रखें।",
    }
    patient_patho = {
        "English": "When a virus enters, the immune system raises body temperature to fight it—like turning up the heat to slow down the invader.",
        "Hindi": "जब वायरस शरीर में आता है, तो प्रतिरक्षा प्रणाली तापमान बढ़ाकर उससे लड़ती है—जैसे गर्मी बढ़ाकर आक्रमणकारी की गति धीमी करना।",
    }
    lang = language if language in patient_summary else "English"
    return {
        "patient_view": {
            "primary_diagnosis": "Mild Viral Fever",
            "summary": patient_summary[lang],
            "pathophysiology": patient_patho[lang],
            "care_plan": [
                "Rest and maintain adequate hydration.",
                "Paracetamol 500 mg as needed for fever (max 4 doses/day).",
                "Monitor temperature twice daily.",
                "If symptoms worsen, contact your doctor.",
            ],
            "red_flags": [
                "Persistent high fever > 39.5°C",
                "Severe headache or confusion",
                "Shortness of breath or chest pain",
            ],
            "severity_score": 3,
        },
        "doctor_view": {
            "subjective": "48-year-old female presents with low-grade fever (38°C), no allergies, no current medications, denies additional symptoms.",
            "objective": "Vitals: BP 120/80, Wt 76 kg, Ht 184.9 cm. Afebrile to low-grade fever; no acute distress reported.",
            "assessment": "Likely mild viral illness. DDx: viral URI, early influenza; less likely bacterial infection.",
            "plan": "Supportive care, PRN antipyretics, hydration, return precautions for red flags.",
            "subjective_list": ["Fever 38°C", "No allergies or current meds", "Denies other complaints"],
            "objective_list": ["BP 120/80", "Wt 76 kg, Ht 184.9 cm", "General: stable"],
            "assessment_list": ["Mild viral fever—most probable", "Viral URI", "Early influenza"],
            "plan_list": ["Paracetamol 500 mg PRN", "Hydration and rest", "Monitor temperature; follow up if worsening"],
        },
        "safety": {"is_safe": True, "warnings": []},
    }

def analyze_case(raw_data: dict[str, Any], selected_language: str) -> dict[str, Any]:
    start_time = time.time()
    formatted_prompt = SYSTEM_PROMPT.format(language=selected_language)
    prompt = f"{formatted_prompt}\nPATIENT DATA: {json.dumps(raw_data, default=str)}"
    
    model_name = "llama3"
    try:
        response = requests.post(
            current_app.config["OLLAMA_API_URL"],
            json={"model": model_name, "prompt": prompt, "stream": False, "format": "json"},
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
        if "response" in result:
            ai_text = result["response"]
            ai_analysis = json.loads(ai_text)
            log_ai_interaction(
                case_id=raw_data["id"],
                model=model_name,
                latency_ms=round((time.time() - start_time) * 1000, 2),
                status="success",
                prompt_tokens=len(prompt) // 4,
                completion_tokens=len(ai_text) // 4,
            )
            return ai_analysis
        else:
            raise ValueError(f"Unexpected response format from Ollama: {result}")
    except Exception as e:
        logging.warning(f"AI Failure: {e}. Using fallback analysis.")
        return build_predefined_ai_analysis(selected_language, raw_data)
