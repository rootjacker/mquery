import requests


class MWDBAnalysisMetadata:
    __depends_on__ = [
        'CuckooAnalysisMetadata'
    ]

    def __init__(self):
        pass

    def extract(self, matched_fname, dependent_meta):
        if not dependent_meta.get("cuckoo_hash"):
            return {}

        hash = dependent_meta.get("cuckoo_hash")["value"]

        mwdb_url = "https://malwaredb.cert.pl/api/malware/sample/{}"
        obj = {}

        res = requests.get(mwdb_url.format(hash), verify=False)
        res.raise_for_status()

        for tag in res.json().get('tags'):
            obj["mwdb_tag_{}".format(tag)] = {
                "display_text": tag
            }

        obj["mwdb_analysis"] = {
            "display_text": "mwdb",
            "url": "https://malwaredb.cert.pl/sample.html?h={}".format(dependent_meta.get("cuckoo_hash")["value"])
        }

        return obj
