"""Google Play Data Safety scraping for a single app.

Reuses the extraction logic from code/scrappers/step4_data_safety_scrapper.ipynb
(data-shared / data-collected via plain HTTP, security practices via Selenium,
since that block is JS-rendered), adapted to run on demand for one app_id
instead of batch-processing the whole corpus.
"""

from __future__ import annotations

import requests
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By

DATASAFETY_URL = "https://play.google.com/store/apps/datasafety?id={app_id}&hl=en_US&gl=US"


def _get_page(app_id: str) -> BeautifulSoup | None:
    try:
        response = requests.get(DATASAFETY_URL.format(app_id=app_id), timeout=15)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"[data_safety] fetch failed for {app_id}: {e}")
        return None
    return BeautifulSoup(response.content, "html.parser")


def get_shared_data(app_id: str) -> list[dict]:
    """Data types the app declares it shares with third parties."""
    soup = _get_page(app_id)
    if soup is None:
        return []

    entries = []
    first_section = soup.find("div", class_="Mf2Txd")
    if not first_section:
        return entries

    for element in first_section.find_all(class_="GcNQi"):
        purpose_elements = element.find_all("div", class_="FnWDne")
        purpose = purpose_elements[0].get_text(strip=True) if purpose_elements else None
        for data_safety_data_shared in element.find_all("span", class_="qcuwR"):
            entries.append({
                "app_id": app_id,
                "data_safety_data_shared": data_safety_data_shared.get_text(strip=True),
                "data_safety_shared_purpose": purpose,
            })
    return entries


def get_collected_data(app_id: str) -> list[dict]:
    """Data types the app declares it collects."""
    soup = _get_page(app_id)
    if soup is None:
        return []

    entries = []
    sections = soup.find_all("div", class_="Mf2Txd")
    if len(sections) <= 1:
        return entries

    second_section = sections[1]
    for element in second_section.find_all(class_="GcNQi"):
        purpose_elements = element.find_all("div", class_="FnWDne")
        purpose = purpose_elements[0].get_text(strip=True) if purpose_elements else None
        for data_safety_data_collected in element.find_all("span", class_="qcuwR"):
            entries.append({
                "app_id": app_id,
                "data_safety_data_collected": data_safety_data_collected.get_text(strip=True),
                "data_safety_collected_purpose": purpose,
            })
    return entries


def get_security_practices(app_id: str, driver) -> list[str]:
    """Developer-declared security practices (encryption in transit, ability
    to request deletion, independent security review, etc). Requires a
    Selenium driver since this block is rendered client-side.
    """
    practices = []
    try:
        driver.get(DATASAFETY_URL.format(app_id=app_id))
        section = driver.find_element(
            By.XPATH, "/html/body/c-wiz[2]/div/div/div[1]/div[2]/div/div[4]/div")
        for item in section.find_elements(By.CLASS_NAME, "Vwijed"):
            try:
                text = item.find_element(By.CLASS_NAME, "aFEzEb").text.strip()
                if text:
                    practices.append(text)
            except Exception:
                continue
    except Exception as e:
        print(f"[data_safety] security practices unavailable for {app_id}: {e}")
    return practices


def collect(app_id: str, driver) -> dict:
    """Run all three Data Safety extractors for one app and return a
    consolidated dict: declared collected/shared data types (comma-separated,
    matching the `data_safety_data_collected` / `data_safety_data_shared` columns the rest of the
    pipeline expects) plus the raw security-practices list.
    """
    shared = get_shared_data(app_id)
    collected = get_collected_data(app_id)
    practices = get_security_practices(app_id, driver)

    return {
        "app_id": app_id,
        "data_safety_data_shared": ", ".join(sorted({e["data_safety_data_shared"] for e in shared})) or None,
        "data_safety_data_collected": ", ".join(sorted({e["data_safety_data_collected"] for e in collected})) or None,
        "data_safety_security_practices": ", ".join(practices) or None,
        "is_privacy_policy": None,  # filled in by sources/privacy_policy.py
        "_raw_shared": shared,
        "_raw_collected": collected,
    }
