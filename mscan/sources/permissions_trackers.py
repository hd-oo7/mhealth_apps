"""Static APK permission and tracker extraction for a single app, via
$\\varepsilon$xodus (reports.exodus-privacy.eu.org).

Reuses the extraction logic from
code/scrappers/step2_permission_tracker_scrapper.ipynb, adapted to run on
demand for one app_id.
"""

from __future__ import annotations

from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

EXODUS_URL = "https://reports.exodus-privacy.eu.org/en/reports/{app_id}/latest/"


def collect(app_id: str, driver) -> dict:
    result = {
        "app_id": app_id,
        "permissions": None,
        "num_permissions": 0,
        "dangerous_permissions": None,
        "num_dangerous_permissions": 0,
        "trackers": None,
        "num_trackers": 0,
        "exodus_report_found": False,
    }

    try:
        driver.get(EXODUS_URL.format(app_id=app_id))
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div.col-md-8.col-12")))

        permissions, dangerous = [], []
        for paragraph in driver.find_elements(By.CSS_SELECTOR, "p.text-truncate"):
            name_el = paragraph.find_element(By.CSS_SELECTOR, 'span[data-toggle="tooltip"]')
            name = name_el.get_attribute("data-original-title")
            is_dangerous = paragraph.find_elements(
                By.CSS_SELECTOR, 'img[src*="/static/img/danger.svg"]')
            permissions.append(name)
            if is_dangerous:
                dangerous.append(name)

        trackers_section = driver.find_element(By.XPATH, "/html/body/div/div[4]/div[2]")
        trackers = [link.text for link in
                    trackers_section.find_elements(By.CSS_SELECTOR, "a.link.black")]

        result.update({
            "permissions": ", ".join(permissions) or None,
            "num_permissions": len(permissions),
            "dangerous_permissions": ", ".join(dangerous) or None,
            "num_dangerous_permissions": len(dangerous),
            "trackers": ", ".join(trackers) or None,
            "num_trackers": len(trackers),
            "exodus_report_found": True,
        })
    except (NoSuchElementException, TimeoutException):
        print(f"[permissions_trackers] no exodus report found for {app_id} "
              "(not yet analyzed by exodus, or an invalid app_id)")
    except Exception as e:
        print(f"[permissions_trackers] extraction failed for {app_id}: {e}")

    return result
