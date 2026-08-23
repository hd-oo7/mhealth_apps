"""Privacy-policy retrieval and structured extraction for a single app.
"""

from __future__ import annotations

import os
import re
import time

from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By

DATASAFETY_URL = "https://play.google.com/store/apps/datasafety?id={app_id}&hl=en_US&gl=US"

POLICY_QUESTIONS = [
    "Answer the following questions in English, formatted exactly as instructed. "
    "Start each answer with the corresponding label. Keep responses concise, "
    "clear, and free of unnecessary words.",
    "Q1: Does the privacy policy specify the types of data collected or "
    "explicitly state that no user data is collected? Begin with 'A1: Specified' "
    "or 'A1: Not mentioned'. If applicable, list the data collected, separated "
    "by commas, without additional comments.",
    "Q2: Does the policy describe data collection practices for all, some, or "
    "none of the collected data? Start with 'A2: All', 'A2: Partial', "
    "'A2: Not at all', or 'A2: Not applicable' (if no data is collected). "
    "Provide a brief explanation (max 20 words).",
    "Q3: Does the privacy policy specify the types of data shared with third "
    "parties or explicitly state that no user data is shared? Begin with "
    "'A3: Specified' or 'A3: Not mentioned'. If applicable, list the shared "
    "data, separated by commas, without extra commentary.",
    "Q4: Does the policy describe data sharing practices for all, some, or "
    "none of the shared data? Start with 'A4: All', 'A4: Partial', "
    "'A4: Not at all', or 'A4: Not applicable' (if no data is shared). "
    "Provide a brief explanation (max 20 words).",
    "Q5: Does the policy explain who receives the shared data? Start with "
    "'A5: Yes', 'A5: No', or 'A5: Not applicable' (if no data is shared). "
    "Provide a brief explanation (max 20 words).",
    "Q6: Does the policy describe users' rights to access, correct, delete, "
    "or opt out of marketing communications? Start with 'A6: All', "
    "'A6: Partial', or 'A6: Not at all'. Provide a brief explanation "
    "(max 20 words).",
    "Q7: Does the policy mention if the data is encrypted during transit? "
    "Start with 'A7: Encrypted', 'A7: Not encrypted', or 'A7: Not mentioned'. "
    "Provide a brief explanation (max 20 words).",
    "Q8: Does the policy outline security measures against unauthorized "
    "access or breaches? Start with 'A8: Detailed', 'A8: Brief', or "
    "'A8: Not mentioned'. Provide a brief explanation (max 20 words).",
    "Q9: Is contact information provided for questions or complaints? Start "
    "with 'A9: Yes' or 'A9: No'. Provide a brief explanation (max 20 words).",
    "Q10: Does the policy address children's data and parental consent? "
    "Start with 'A10: Detailed', 'A10: Brief', or 'A10: Not mentioned'. "
    "Provide a brief explanation (max 20 words).",
    "Q11: Does the policy explain compliance with privacy laws? List the "
    "laws (e.g., GDPR, HIPAA, CCPA, COPPA) separated by commas, without "
    "extra words.",
    "Q12: How would you rate the policy's disclosure? Start with "
    "'A12: Clear', 'A12: Vague', 'A12: Incorrect', or 'A12: Omitted'. "
    "Provide a brief explanation (max 20 words).",
]

_ANSWER_RE = re.compile(r"A(\d+):\s*(.*?)(?=\nA\d+:|\Z)", re.S)


def find_policy_url(app_id: str, driver) -> str | None:
    try:
        driver.get(DATASAFETY_URL.format(app_id=app_id))
        time.sleep(3)
        link = driver.find_element(
            By.XPATH, '//div[contains(@class, "viuTPb")]//a[contains(@class, "GO2pB")]')
        return link.get_attribute("href")
    except Exception:
        return None


def fetch_policy_text(app_id: str, driver) -> str | None:
    """Retrieve and clean the privacy-policy text for one app. Returns None
    if the store listing has no policy link or the page failed to load
    (both are meaningful, and are recorded upstream as `policy_retrieved =
    False` rather than treated as an error).
    """
    url = find_policy_url(app_id, driver)
    if not url:
        return None
    try:
        driver.get(url)
        time.sleep(3)
        soup = BeautifulSoup(driver.page_source, "html.parser")
        text = soup.get_text()
        return "\n".join(line for line in text.split("\n") if line.strip())
    except Exception as e:
        print(f"[privacy_policy] failed to load policy page for {app_id}: {e}")
        return None


def save_policy_text(app_id: str, text: str, policy_dir: str) -> None:
    os.makedirs(policy_dir, exist_ok=True)
    with open(os.path.join(policy_dir, f"{app_id}.txt"), "w", encoding="utf-8") as f:
        f.write(text)


def _parse_answers(raw: str) -> dict[str, str]:
    return {f"A{m.group(1)}": m.group(2).strip() for m in _ANSWER_RE.finditer(raw)}


def analyze_with_llm(app_id: str, policy_text: str) -> dict | None:
    """
    Requires GEMINI_API_KEY in the environment; returns None (with a clear
    message) rather than raising if it isn't set, so callers can proceed
    without the LLM-parsed side of the record.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        print("[privacy_policy] GEMINI_API_KEY not set; skipping LLM analysis "
              "(Data Safety is still used for the declared side).")
        return None

    import google.generativeai as genai

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name="models/gemini-2.5-flash-tts",
        generation_config={
            "temperature": 0.2, "top_p": 0.95, "top_k": 40,
            "max_output_tokens": 8192, "response_mime_type": "text/plain",
        },
    )

    try:
        response = model.generate_content(POLICY_QUESTIONS + [policy_text])
    except Exception as e:
        print(f"[privacy_policy] LLM call failed for {app_id}: {e}")
        return None
    if not response or not response.text:
        return None

    answers = _parse_answers(response.text)

    def _strip_prefix(value: str) -> str:
        # "Specified\nemail, phone number" -> "email, phone number"
        return re.sub(r"^(Specified|Not mentioned)\s*", "", value, flags=re.I).strip()

    return {
        "app_id": app_id,
        "raw_answers": response.text,
        "data_safety_data_collected": _strip_prefix(answers.get("A1", "")) or None,
        "data_safety_data_shared": _strip_prefix(answers.get("A3", "")) or None,
        "encryption_in_transit": answers.get("A7"),
        "compliance_mentioned": answers.get("A11"),
        "disclosure_rating": answers.get("A12"),
    }


def collect(app_id: str, driver, policy_dir: str) -> dict:
    """Retrieve the policy (caching to disk like the batch pipeline does)
    and run the LLM extraction on it.
    """
    cache_path = os.path.join(policy_dir, f"{app_id}.txt")
    if os.path.exists(cache_path):
        with open(cache_path, encoding="utf-8") as f:
            text = f.read()
    else:
        text = fetch_policy_text(app_id, driver)
        if text:
            save_policy_text(app_id, text, policy_dir)

    result = {
        "app_id": app_id,
        "policy_retrieved": text is not None,
        "data_safety_data_collected": None,
        "data_safety_data_shared": None,
    }
    if text:
        llm_result = analyze_with_llm(app_id, text)
        if llm_result:
            result.update(llm_result)
    return result
