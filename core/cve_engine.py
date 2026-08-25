import requests

class CVEEngine:

    def __init__(self):
        self.base_url = "https://cve.circl.lu/api/search/"

    def clean_service_name(self, banner):
        if banner == "Unknown service" or not banner:
            return None
        return banner.split("/")[0].split()[0].strip()

    def fetch_cves(self, service_name, limit=3):
        service_clean = self.clean_service_name(service_name)
        if service_clean is None:
            return []

        try:
            response = requests.get(
                f"{self.base_url}{service_clean}", timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                results = []
                for item in data[:limit]:
                    cve_entry = {
                        "cve_id": item.get("id", "N/A"),
                        "summary": item.get("summary", "")[:100] + "...",
                        "cvss": item.get("cvss", 0.0),
                    }
                    results.append(cve_entry)
                return results
            return []
        except Exception:
            return []