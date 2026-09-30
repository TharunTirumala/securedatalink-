import urllib.request
import json

FID = "539f018133934f46a17ee0e93d072e84"

# 1. POST /api/lab/files/{id}/verify
req = urllib.request.Request(
    f"http://127.0.0.1:8000/api/lab/files/{FID}/verify",
    data=json.dumps({"mode": "working"}).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)
with urllib.request.urlopen(req) as res:
    post_data = json.loads(res.read().decode("utf-8"))

print("=== POST /verify response ===")
print("Status: 200")
print("Top-level keys:", list(post_data.keys()))
if "feed" in post_data:
    feed = post_data["feed"]
    print("Feed keys:", list(feed.keys()))
    print("Feed counts:", feed.get("counts"))
    print("Feed rows count:", len(feed.get("rows", [])))
    print("First 3 feed rows:")
    for r in feed.get("rows", [])[:3]:
        print("  ", r)

# 2. GET /api/lab/files/{id}/verify/last?view=feed
url = f"http://127.0.0.1:8000/api/lab/files/{FID}/verify/last?mode=working&view=feed"
with urllib.request.urlopen(url) as res:
    get_data = json.loads(res.read().decode("utf-8"))

print("\n=== GET /verify/last?view=feed response ===")
print("URL:", url)
print("Status: 200")
print("Top-level keys:", list(get_data.keys()))
print("Counts:", get_data.get("counts"))
print("Rows count:", len(get_data.get("rows", [])))
print("First 3 rows:")
for r in get_data.get("rows", [])[:3]:
    print("  ", r)
