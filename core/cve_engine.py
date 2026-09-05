import requests


class CVEEngine:

    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {"User-Agent": "VulnScope-Scanner/1.0"}

    def clean_service_name(self, banner):
        if not banner or banner == "Unknown service":
            return None
        # Transforma "Apache/2.4.49" in "Apache 2.4.49"
        cleaned = banner.split("\n")[0].replace("/", " ").strip()
        parts = cleaned.split()
        if len(parts) >= 2:
            return f"{parts[0]} {parts[1]}"
        return parts[0] if parts else None

    def fetch_cves(self, service_name, limit=3):
        query = self.clean_service_name(service_name)
        if not query:
            return []

        params = {"keywordSearch": query, "resultsPerPage": limit}

        try:
            response = requests.get(
                self.base_url,
                headers=self.headers,
                params=params,
                timeout=10,
            )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                results = []

                for item in vulnerabilities:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "N/A")

                    # Extragere descriere in engleza
                    descriptions = cve_data.get("descriptions", [])
                    summary = "No description available"
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            summary = desc.get("value", "")
                            break

                    # Extragere scor CVSS v3.1 / v3.0 / v2.0
                    metrics = cve_data.get("metrics", {})
                    cvss = 0.0
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0]["cvssData"].get(
                            "baseScore", 0.0
                        )
                    elif "cvssMetricV30" in metrics:
                        cvss = metrics["cvssMetricV30"][0]["cvssData"].get(
                            "baseScore", 0.0
                        )
                    elif "cvssMetricV2" in metrics:
                        cvss = metrics["cvssMetricV2"][0]["cvssData"].get(
                            "baseScore", 0.0
                        )

                    results.append(
                        {
                            "cve_id": cve_id,
                            "summary": (
                                (summary[:100] + "...")
                                if len(summary) > 100
                                else summary
                            ),
                            "cvss": float(cvss),
                        }
                    )
                return results

            return []
        except Exception:
            return []