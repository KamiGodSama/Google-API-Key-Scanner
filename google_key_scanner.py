#!/usr/bin/env python3
"""
All-in-One Google API Key Scanner
Combines checks from KeyHacks & gmapsapiscanner
For authorized security assessments only.
"""

import requests
import json
import sys
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for clean output (use with caution)
warnings.simplefilter('ignore', InsecureRequestWarning)

# ----------------------------- CONFIGURATION -----------------------------
REQUEST_TIMEOUT = 15
REQUEST_KWARGS = {"verify": False, "timeout": REQUEST_TIMEOUT}

# ----------------------------- HELPER FUNCTIONS -----------------------------
def print_vulnerable(service_name, poc, cost_info=""):
    """Print vulnerable result with PoC."""
    print(f"\n[!] \033[1;31;40mVULNERABLE\033[0m: {service_name} {cost_info}")
    print(f"    PoC: {poc}")

def print_not_vulnerable(service_name, reason=""):
    """Print not vulnerable result."""
    print(f"[+] {service_name}: Not vulnerable. {reason}")

def extract_error(response, keys=("error_message", "errorMessage", "error")):
    """Safely extract error message from JSON response."""
    try:
        data = response.json()
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            data = data[0]
        for key in keys:
            if key in data:
                val = data[key]
                if isinstance(val, dict) and "message" in val:
                    return val["message"]
                if isinstance(val, str):
                    return val
        if "error" in data and isinstance(data["error"], dict):
            return data["error"].get("message", str(data["error"]))
    except (json.JSONDecodeError, TypeError):
        pass
    return f"HTTP {response.status_code}"

# ----------------------------- SCANNER FUNCTIONS -----------------------------

def scan_maps_apis(api_key):
    """Scan all Google Maps Platform APIs."""
    print("\n[*] Scanning Google Maps APIs...")

    # 1. Static Maps
    url = f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if resp.status_code == 200:
            print_vulnerable("Static Maps", url, "($2/1k requests)")
        else:
            print_not_vulnerable("Static Maps")
    except Exception as e:
        print_not_vulnerable("Static Maps", f"Error: {e}")

    # 2. Street View
    url = f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if resp.status_code == 200:
            print_vulnerable("Street View", url, "($7/1k requests)")
        else:
            print_not_vulnerable("Street View")
    except Exception as e:
        print_not_vulnerable("Street View", f"Error: {e}")

    # 3. Directions
    url = f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error_message" not in resp.text:
            print_vulnerable("Directions", url, "($5/1k requests)")
        else:
            print_not_vulnerable("Directions", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Directions", f"Error: {e}")

    # 4. Geocoding
    url = f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error_message" not in resp.text:
            print_vulnerable("Geocoding", url, "($5/1k requests)")
        else:
            print_not_vulnerable("Geocoding", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Geocoding", f"Error: {e}")

    # 5. Distance Matrix
    url = f"https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615,-73.9976592&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error_message" not in resp.text:
            print_vulnerable("Distance Matrix", url, "($5/1k elements)")
        else:
            print_not_vulnerable("Distance Matrix", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Distance Matrix", f"Error: {e}")

    # 6. Find Place from Text
    url = f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error_message" not in resp.text:
            print_vulnerable("Find Place from Text", url, "($17/1k requests)")
        else:
            print_not_vulnerable("Find Place from Text", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Find Place from Text", f"Error: {e}")

    # 7. Autocomplete
    url = f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=(cities)&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error_message" not in resp.text:
            print_vulnerable("Autocomplete", url, "($2.83/1k requests)")
        else:
            print_not_vulnerable("Autocomplete", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Autocomplete", f"Error: {e}")

    # 8. Elevation
    url = f"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error_message" not in resp.text:
            print_vulnerable("Elevation", url, "($5/1k requests)")
        else:
            print_not_vulnerable("Elevation", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Elevation", f"Error: {e}")

    # 9. Timezone
    url = f"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "errorMessage" not in resp.text:
            print_vulnerable("Timezone", url, "($5/1k requests)")
        else:
            print_not_vulnerable("Timezone", extract_error(resp, ("errorMessage", "error_message")))
    except Exception as e:
        print_not_vulnerable("Timezone", f"Error: {e}")

    # 10. Roads - Nearest Roads
    url = f"https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error" not in resp.text:
            print_vulnerable("Nearest Roads", url, "($10/1k requests)")
        else:
            print_not_vulnerable("Nearest Roads", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Nearest Roads", f"Error: {e}")

    # 11. Roads - Snap to Roads
    url = f"https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error" not in resp.text:
            print_vulnerable("Snap to Roads", url, "($10/1k requests)")
        else:
            print_not_vulnerable("Snap to Roads", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Snap to Roads", f"Error: {e}")

    # 12. Roads - Speed Limits
    url = f"https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error" not in resp.text:
            print_vulnerable("Speed Limits", url, "($20/1k requests)")
        else:
            print_not_vulnerable("Speed Limits", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Speed Limits", f"Error: {e}")

    # 13. Geolocation
    url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={api_key}"
    postdata = {'considerIp': 'true'}
    try:
        resp = requests.post(url, data=postdata, **REQUEST_KWARGS)
        if "error" not in resp.text:
            poc_curl = f'curl -i -s -k -X POST -H "Host: www.googleapis.com" -H "Content-Length: 22" --data-binary \'{{"considerIp": "true"}}\' "{url}"'
            print_vulnerable("Geolocation", poc_curl, "($5/1k requests)")
        else:
            print_not_vulnerable("Geolocation", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Geolocation", f"Error: {e}")

    # 14. Place Details
    url = f"https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error_message" not in resp.text:
            print_vulnerable("Place Details", url, "($17/1k requests)")
        else:
            print_not_vulnerable("Place Details", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Place Details", f"Error: {e}")

    # 15. Nearby Search
    url = f"https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error_message" not in resp.text:
            print_vulnerable("Nearby Search", url, "($32/1k requests)")
        else:
            print_not_vulnerable("Nearby Search", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Nearby Search", f"Error: {e}")

    # 16. Text Search
    url = f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if "error_message" not in resp.text:
            print_vulnerable("Text Search", url, "($32/1k requests)")
        else:
            print_not_vulnerable("Text Search", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Text Search", f"Error: {e}")

    # 17. Places Photo
    url = f"https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS, allow_redirects=False)
        if resp.status_code == 302:
            print_vulnerable("Places Photo", url, "($7/1k requests)")
        else:
            print_not_vulnerable("Places Photo", "Verbose responses not enabled.")
    except Exception as e:
        print_not_vulnerable("Places Photo", f"Error: {e}")

    # 18. Address Validation
    url = f"https://addressvalidation.googleapis.com/v1:validateAddress?key={api_key}"
    payload = {"address": {"regionCode": "US", "addressLines": ["1600 Amphitheatre Pkwy, Mountain View, CA"]}}
    try:
        resp = requests.post(url, json=payload, **REQUEST_KWARGS)
        if resp.status_code == 200 and "error" not in resp.text:
            poc_curl = f'curl -X POST -H "Content-Type: application/json" -d \'{{"address":{{"regionCode":"US","addressLines":["1600 Amphitheatre Pkwy"]}}}}\' "{url}"'
            print_vulnerable("Address Validation", poc_curl, "($5/1k requests)")
        else:
            print_not_vulnerable("Address Validation", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Address Validation", f"Error: {e}")

    # 19. Air Quality
    url = f"https://airquality.googleapis.com/v1/currentConditions:lookup?key={api_key}"
    payload = {"location": {"latitude": 37.419734, "longitude": -122.0827784}}
    try:
        resp = requests.post(url, json=payload, **REQUEST_KWARGS)
        if resp.status_code == 200 and "error" not in resp.text:
            poc_curl = f'curl -X POST -H "Content-Type: application/json" -d \'{{"location":{{"latitude":37.42,"longitude":-122.08}}}}\' "{url}"'
            print_vulnerable("Air Quality", poc_curl, "(Paid per request)")
        else:
            print_not_vulnerable("Air Quality", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Air Quality", f"Error: {e}")

    # 20. Aerial View
    url = f"https://aerialview.googleapis.com/v1/videos:lookupVideoMetadata?key={api_key}&address=600%20Montgomery%20St%2C%20San%20Francisco%2C%20CA%2094111"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if resp.status_code == 200 and "error" not in resp.text:
            print_vulnerable("Aerial View", url, "(Paid per request)")
        else:
            print_not_vulnerable("Aerial View", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Aerial View", f"Error: {e}")

    # 21. Routes API - computeRoutes
    url = f"https://routes.googleapis.com/directions/v2:computeRoutes?key={api_key}"
    headers = {"Content-Type": "application/json", "X-Goog-FieldMask": "routes.duration,routes.distanceMeters,routes.polyline.encodedPolyline"}
    payload = {
        "origin": {"location": {"latLng": {"latitude": 37.419734, "longitude": -122.0827784}}},
        "destination": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}},
        "travelMode": "DRIVE"
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, **REQUEST_KWARGS)
        if resp.status_code == 200 and "error" not in resp.text and "routes" in resp.text:
            poc_curl = f'curl -X POST -H "Content-Type: application/json" -H "X-Goog-FieldMask: routes.duration,routes.distanceMeters" -d \'{{"origin":{{"location":{{"latLng":{{"latitude":37.42,"longitude":-122.08}}}}}},"destination":{{"location":{{"latLng":{{"latitude":37.43,"longitude":-122.09}}}}}},"travelMode":"DRIVE"}}\' "{url}"'
            print_vulnerable("Routes (computeRoutes)", poc_curl, "(Paid per request)")
        else:
            print_not_vulnerable("Routes (computeRoutes)", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Routes (computeRoutes)", f"Error: {e}")

    # 22. Routes API - computeRouteMatrix
    url = f"https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key={api_key}"
    headers = {"Content-Type": "application/json", "X-Goog-FieldMask": "originIndex,destinationIndex,status,distanceMeters,duration"}
    payload = {
        "origins": [{"waypoint": {"location": {"latLng": {"latitude": 37.419734, "longitude": -122.0827784}}}}],
        "destinations": [
            {"waypoint": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}}},
            {"waypoint": {"location": {"latLng": {"latitude": 37.4250, "longitude": -122.0860}}}}
        ],
        "travelMode": "DRIVE"
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, **REQUEST_KWARGS)
        if resp.status_code == 200 and "error" not in resp.text:
            poc_curl = f'curl -X POST -H "Content-Type: application/json" -H "X-Goog-FieldMask: originIndex,destinationIndex,status,distanceMeters,duration" -d \'{{"origins":[{{"waypoint":{{"location":{{"latLng":{{"latitude":37.42,"longitude":-122.08}}}}}}}}],"destinations":[{{"waypoint":{{"location":{{"latLng":{{"latitude":37.43,"longitude":-122.09}}}}}}}}],"travelMode":"DRIVE"}}\' "{url}"'
            print_vulnerable("Routes (computeRouteMatrix)", poc_curl, "(Paid per element)")
        else:
            print_not_vulnerable("Routes (computeRouteMatrix)", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Routes (computeRouteMatrix)", f"Error: {e}")

def scan_other_google_apis(api_key):
    """Scan non-Maps Google APIs."""
    print("\n[*] Scanning other Google APIs...")

    # 1. Firebase / Identity Toolkit
    url = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key={api_key}"
    payload = {"token": "dummy", "returnSecureToken": True}
    try:
        resp = requests.post(url, json=payload, **REQUEST_KWARGS)
        # Expected error: "INVALID_CUSTOM_TOKEN" confirms key is valid
        if resp.status_code == 400 and "INVALID_CUSTOM_TOKEN" in resp.text:
            poc_curl = f'curl -X POST -H "Content-Type: application/json" -d \'{{"token":"dummy","returnSecureToken":true}}\' "{url}"'
            print_vulnerable("Firebase / Identity Toolkit", poc_curl, "(Can authenticate users)")
        else:
            print_not_vulnerable("Firebase / Identity Toolkit", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Firebase / Identity Toolkit", f"Error: {e}")

    # 2. Firebase Cloud Messaging (FCM)
    url = "https://fcm.googleapis.com/fcm/send"
    headers = {"Authorization": f"key={api_key}", "Content-Type": "application/json"}
    payload = {"registration_ids": ["ABC"]}
    try:
        resp = requests.post(url, json=payload, headers=headers, **REQUEST_KWARGS)
        # 200 with "InvalidRegistration" means key is valid
        if resp.status_code == 200:
            poc_curl = f'curl --header "Authorization: key={api_key}" --header "Content-Type: application/json" https://fcm.googleapis.com/fcm/send -d \'{{"registration_ids":["ABC"]}}\''
            print_vulnerable("FCM (Push Notifications)", poc_curl, "(Can send push notifications)")
        else:
            print_not_vulnerable("FCM", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("FCM", f"Error: {e}")

    # 3. Google reCAPTCHA
    # Note: reCAPTCHA keys start with '6L' and are 40 chars
    if api_key.startswith("6L") and len(api_key) == 40:
        url = "https://www.google.com/recaptcha/api/siteverify"
        payload = {"secret": api_key, "response": "dummy"}
        try:
            resp = requests.post(url, data=payload, **REQUEST_KWARGS)
            if resp.status_code == 200:
                data = resp.json()
                if "error-codes" in data:
                    poc_curl = f'curl -X POST -d "secret={api_key}&response=dummy" "{url}"'
                    print_vulnerable("reCAPTCHA", poc_curl, "(Can verify CAPTCHA responses)")
                else:
                    print_not_vulnerable("reCAPTCHA", "Key appears invalid")
            else:
                print_not_vulnerable("reCAPTCHA", extract_error(resp))
        except Exception as e:
            print_not_vulnerable("reCAPTCHA", f"Error: {e}")
    else:
        print("[+] reCAPTCHA: Skipped (key format doesn't match)")

    # 4. Gemini Files API (Data Leak Risk)
    # Based on Truffle Security research: https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules
    url = f"https://generativelanguage.googleapis.com/v1beta/files?key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if resp.status_code == 200:
            print_vulnerable("Gemini Files", url, "(Potential data leak - can list files)")
        else:
            print_not_vulnerable("Gemini Files", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Gemini Files", f"Error: {e}")

    # 5. Gemini Cached Contents
    url = f"https://generativelanguage.googleapis.com/v1beta/cachedContents?key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if resp.status_code == 200:
            print_vulnerable("Gemini Cached Contents", url, "(Potential data leak - can list cached content)")
        else:
            print_not_vulnerable("Gemini Cached Contents", extract_error(resp, ("error",)))
    except Exception as e:
        print_not_vulnerable("Gemini Cached Contents", f"Error: {e}")

    # 6. Google Cloud Storage (try listing buckets - requires proper IAM)
    # Note: This may not work with API keys alone, but worth a try
    url = f"https://storage.googleapis.com/storage/v1/b?key={api_key}"
    try:
        resp = requests.get(url, **REQUEST_KWARGS)
        if resp.status_code == 200:
            print_vulnerable("Cloud Storage (List Buckets)", url, "(Can list storage buckets)")
        elif resp.status_code == 403 and "permission" in resp.text.lower():
            print_not_vulnerable("Cloud Storage (List Buckets)", "403 Forbidden - key lacks permission")
        else:
            print_not_vulnerable("Cloud Storage (List Buckets)", extract_error(resp))
    except Exception as e:
        print_not_vulnerable("Cloud Storage (List Buckets)", f"Error: {e}")

def scan_google_cloud_credentials(key_or_path):
    """
    Check if the input is a Google Cloud service account JSON file.
    If so, attempt to activate it and print access token.
    """
    import os
    if os.path.isfile(key_or_path):
        try:
            with open(key_or_path, 'r') as f:
                data = json.load(f)
            if data.get("type") == "service_account" and "private_key" in data:
                print("\n[!] This appears to be a Google Cloud Service Account JSON file!")
                print("[*] To test these credentials, run:")
                print(f"    gcloud auth activate-service-account --key-file={key_or_path}")
                print("    gcloud auth print-access-token")
                print("[!] If successful, this grants access to GCP resources.")
                return True
        except:
            pass
    return False

# ----------------------------- MAIN -----------------------------
def main():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║     Google API Key Scanner - Security Assessment Tool        ║
║            Authorized use only                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    if len(sys.argv) < 2:
        api_key = input("[?] Enter your Google API key: ").strip()
    else:
        api_key = sys.argv[1]

    if not api_key:
        print("[!] No API key provided.")
        sys.exit(1)

    print(f"[*] Testing API key: {api_key[:8]}... (truncated)")

    # Check if it's a service account JSON file
    if scan_google_cloud_credentials(api_key):
        return

    # Run all scans
    scan_maps_apis(api_key)
    scan_other_google_apis(api_key)

    print("\n" + "="*60)
    print("[*] Scan complete. Review the results above.")
    print("[!] Remember: Even 'Not Vulnerable' results should be verified manually.")
    print("="*60)

if __name__ == "__main__":
    main()
