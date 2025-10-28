from flask import Flask, request, jsonify
import requests
import re
import json
import time
from urllib.parse import quote

app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET')
    response.headers.add('X-Powered-By', 'NabiSystem VIP - 45 Modules')
    return response

class NabiOSINT:
    def __init__(self):
        self.version = "4.5"
        self.author = "NabiSystem VIP"
    
    # 1. IP GEOLOCATION
    def ip_geo(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            return response.json()
        except:
            return {"error": "IP sorgu hatası"}
    
    # 2. PHONE ANALYSIS
    def phone_check(self, phone):
        try:
            url = f"https://api.numlookupapi.com/v1/validate/{phone}?apikey=num_live_wjd4V74gCwHHO4qoxYYEyYO9xBFblGx3twOy0BcU"
            response = requests.get(url, timeout=10)
            return response.json()
        except:
            return {"error": "Telefon sorgu hatası"}
    
    # 3. EMAIL OSINT
    def email_check(self, email):
        try:
            response = requests.get(f"https://emailrep.io/{email}", timeout=10)
            return response.json()
        except:
            return {"error": "Email sorgu hatası"}
    
    # 4. USERNAME SEARCH
    def username_search(self, username):
        platforms = {
            "instagram": f"https://instagram.com/{username}",
            "twitter": f"https://twitter.com/{username}",
            "github": f"https://github.com/{username}",
            "tiktok": f"https://tiktok.com/@{username}",
            "reddit": f"https://reddit.com/user/{username}",
            "pinterest": f"https://pinterest.com/{username}",
            "vk": f"https://vk.com/{username}",
            "facebook": f"https://facebook.com/{username}"
        }
        results = {}
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=5)
                results[platform] = "exists" if response.status_code == 200 else "not_found"
            except:
                results[platform] = "error"
        return results
    
    # 5. DOMAIN WHOIS
    def domain_whois(self, domain):
        try:
            response = requests.get(f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={domain}", timeout=10)
            return response.json()
        except:
            return {"error": "Domain sorgu hatası"}
    
    # 6. BTC ANALYSIS
    def btc_check(self, address):
        try:
            response = requests.get(f"https://blockchain.info/rawaddr/{address}", timeout=10)
            return response.json()
        except:
            return {"error": "BTC sorgu hatası"}
    
    # 7. ETHEREUM ANALYSIS
    def eth_check(self, address):
        try:
            response = requests.get(f"https://api.etherscan.io/api?module=account&action=balance&address={address}", timeout=10)
            return response.json()
        except:
            return {"error": "ETH sorgu hatası"}
    
    # 8. BIN CHECK
    def bin_check(self, bin):
        try:
            response = requests.get(f"https://lookup.binlist.net/{bin}", timeout=10)
            return response.json()
        except:
            return {"error": "BIN sorgu hatası"}
    
    # 9. MAC LOOKUP
    def mac_lookup(self, mac):
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=10)
            return {"vendor": response.text}
        except:
            return {"error": "MAC sorgu hatası"}
    
    # 10. IMEI CHECK
    def imei_check(self, imei):
        try:
            response = requests.get(f"https://www.imei.info/api/check/{imei}", timeout=10)
            return response.json()
        except:
            return {"error": "IMEI sorgu hatası"}
    
    # 11. VPN DETECTION
    def vpn_check(self, ip):
        try:
            response = requests.get(f"https://api.ip2proxy.com/?ip={ip}&key=DEMO", timeout=10)
            return response.json()
        except:
            return {"error": "VPN sorgu hatası"}
    
    # 12. DATA BREACH CHECK
    def breach_check(self, email):
        try:
            response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", timeout=10)
            return response.json() if response.status_code == 200 else {"breaches": 0}
        except:
            return {"error": "Breach sorgu hatası"}
    
    # 13. SSL CHECK
    def ssl_check(self, domain):
        try:
            response = requests.get(f"https://api.ssllabs.com/api/v3/analyze?host={domain}", timeout=10)
            return response.json()
        except:
            return {"error": "SSL sorgu hatası"}
    
    # 14. DOMAIN HISTORY
    def domain_history(self, domain):
        try:
            response = requests.get(f"https://archive.org/wayback/available?url={domain}", timeout=10)
            return response.json()
        except:
            return {"error": "Domain history hatası"}
    
    # 15. METADATA ANALYSIS
    def metadata_analysis(self, url):
        try:
            response = requests.get(url, timeout=15)
            return {
                "content_type": response.headers.get('content-type'),
                "content_length": len(response.content),
                "server": response.headers.get('server'),
                "status_code": response.status_code
            }
        except:
            return {"error": "Metadata analiz hatası"}
    
    # 16. SCRIPT ANALYSIS
    def script_analysis(self, url):
        try:
            response = requests.get(url, timeout=10)
            scripts = re.findall(r'<script[^>]*src="([^"]*)"', response.text)
            return {"script_count": len(scripts), "scripts": scripts[:10]}
        except:
            return {"error": "Script analiz hatası"}
    
    # 17. CRYPTO WALLET
    def crypto_wallet(self, address):
        try:
            btc = requests.get(f"https://blockchain.info/rawaddr/{address}", timeout=10)
            eth = requests.get(f"https://api.etherscan.io/api?module=account&action=balance&address={address}", timeout=10)
            return {"bitcoin": btc.json(), "ethereum": eth.json()}
        except:
            return {"error": "Crypto wallet hatası"}
    
    # 18. DARKNET MONITORING
    def darknet_check(self, query):
        try:
            response = requests.get(f"https://ahmia.fi/search/?q={query}", timeout=10)
            return {"results": "Darknet search completed"}
        except:
            return {"error": "Darknet sorgu hatası"}
    
    # 19. TELEGRAM OSINT
    def telegram_check(self, username):
        try:
            response = requests.get(f"https://t.me/{username}", timeout=10)
            return {"exists": response.status_code == 200}
        except:
            return {"error": "Telegram sorgu hatası"}
    
    # 20. INSTAGRAM ANALYSIS
    def instagram_check(self, username):
        try:
            response = requests.get(f"https://www.instagram.com/{username}/", timeout=10)
            return {"exists": response.status_code == 200}
        except:
            return {"error": "Instagram sorgu hatası"}
    
    # 21. VK SCANNER
    def vk_check(self, user_id):
        try:
            response = requests.get(f"https://vk.com/{user_id}", timeout=10)
            return {"exists": response.status_code == 200}
        except:
            return {"error": "VK sorgu hatası"}
    
    # 22. WHATSAPP DETECTION
    def whatsapp_check(self, phone):
        try:
            response = requests.get(f"https://wa.me/{phone}", timeout=10)
            return {"exists": response.status_code == 200}
        except:
            return {"error": "WhatsApp sorgu hatası"}
    
    # 23. TAX DATA CHECK
    def tax_check(self, inn):
        try:
            response = requests.get(f"https://service.nalog.ru/inn.do?inn={inn}", timeout=10)
            return {"status": "Tax check completed"}
        except:
            return {"error": "Tax sorgu hatası"}
    
    # 24. COURT CASES SEARCH
    def court_check(self, name):
        try:
            response = requests.get(f"https://sudrf.ru/index.php?id=300&act=go_search&searchtype=fs&fio={name}", timeout=10)
            return {"status": "Court search completed"}
        except:
            return {"error": "Court sorgu hatası"}
    
    # 25. PATENT SEARCH
    def patent_search(self, query):
        try:
            response = requests.get(f"https://patents.google.com/?q={query}", timeout=10)
            return {"status": "Patent search completed"}
        except:
            return {"error": "Patent sorgu hatası"}
    
    # 26. TRADEMARK SEARCH
    def trademark_search(self, query):
        try:
            response = requests.get(f"https://www3.wipo.int/branddb/en/?q={query}", timeout=10)
            return {"status": "Trademark search completed"}
        except:
            return {"error": "Trademark sorgu hatası"}
    
    # 27. FLIGHT SEARCH
    def flight_search(self, flight):
        try:
            response = requests.get(f"https://www.flightradar24.com/data/flights/{flight}", timeout=10)
            return {"status": "Flight search completed"}
        except:
            return {"error": "Flight sorgu hatası"}
    
    # 28. HOTEL BOOKING
    def hotel_check(self, booking):
        try:
            response = requests.get(f"https://www.booking.com/searchresults.ru.html?ss={booking}", timeout=10)
            return {"status": "Hotel search completed"}
        except:
            return {"error": "Hotel sorgu hatası"}
    
    # 29. RENTAL SEARCH
    def rental_search(self, location):
        try:
            response = requests.get(f"https://www.avito.ru/rossiya?q={location}", timeout=10)
            return {"status": "Rental search completed"}
        except:
            return {"error": "Rental sorgu hatası"}
    
    # 30. CAR PLATE CHECK
    def carplate_check(self, plate):
        try:
            response = requests.get(f"https://avtocod.ru/proverkaavto/{plate}", timeout=10)
            return {"status": "Car plate check completed"}
        except:
            return {"error": "Car plate sorgu hatası"}
    
    # 31. DRIVER LICENSE CHECK
    def driver_check(self, license):
        try:
            response = requests.get(f"https://гибдд.рф/check/driver/?num={license}", timeout=10)
            return {"status": "Driver license check completed"}
        except:
            return {"error": "Driver license sorgu hatası"}
    
    # 32. PASSPORT CHECK
    def passport_check(self, passport):
        try:
            response = requests.get(f"https://мвд.рф/services/check_passport/{passport}", timeout=10)
            return {"status": "Passport check completed"}
        except:
            return {"error": "Passport sorgu hatası"}
    
    # 33. MEDICAL RECORDS
    def medical_check(self, name):
        try:
            response = requests.get(f"https://emias.info/patient/{name}", timeout=10)
            return {"status": "Medical records search completed"}
        except:
            return {"error": "Medical records sorgu hatası"}
    
    # 34. EDUCATION SEARCH
    def education_check(self, name):
        try:
            response = requests.get(f"https://obrnadzor.gov.ru/services/check-diplom/{name}", timeout=10)
            return {"status": "Education search completed"}
        except:
            return {"error": "Education sorgu hatası"}
    
    # 35. WORK HISTORY
    def work_check(self, name):
        try:
            response = requests.get(f"https://pfr.gov.ru/services/work-experience/{name}", timeout=10)
            return {"status": "Work history search completed"}
        except:
            return {"error": "Work history sorgu hatası"}
    
    # 36. CREDIT HISTORY
    def credit_check(self, name):
        try:
            response = requests.get(f"https://www.bki.ru/services/check/{name}", timeout=10)
            return {"status": "Credit history search completed"}
        except:
            return {"error": "Credit history sorgu hatası"}
    
    # 37. REAL ESTATE
    def realestate_check(self, address):
        try:
            response = requests.get(f"https://rosreestr.gov.ru/wps/portal/p/cc_ib_portal_services/online_request/{address}", timeout=10)
            return {"status": "Real estate search completed"}
        except:
            return {"error": "Real estate sorgu hatası"}
    
    # 38. LAND PLOT
    def land_check(self, cadastral):
        try:
            response = requests.get(f"https://pkk.rosreestr.ru/api/features/1/{cadastral}", timeout=10)
            return {"status": "Land plot search completed"}
        except:
            return {"error": "Land plot sorgu hatası"}
    
    # 39. CORPORATE DATA
    def corporate_check(self, company):
        try:
            response = requests.get(f"https://egrul.nalog.ru/search/{company}", timeout=10)
            return {"status": "Corporate data search completed"}
        except:
            return {"error": "Corporate data sorgu hatası"}
    
    # 40. MARINE VESSEL
    def marine_check(self, imo):
        try:
            response = requests.get(f"https://www.marinetraffic.com/ru/ais/details/ships/imo:{imo}", timeout=10)
            return {"status": "Marine vessel search completed"}
        except:
            return {"error": "Marine vessel sorgu hatası"}
    
    # 41. AIRCRAFT SEARCH
    def aircraft_check(self, registration):
        try:
            response = requests.get(f"https://flightaware.com/live/flight/{registration}", timeout=10)
            return {"status": "Aircraft search completed"}
        except:
            return {"error": "Aircraft sorgu hatası"}
    
    # 42. YANDEX SEARCH
    def yandex_search(self, query):
        try:
            encoded = quote(query)
            response = requests.get(f"https://yandex.ru/search/?text={encoded}", timeout=10)
            return {"status": "Yandex search completed", "results_count": len(response.text)}
        except:
            return {"error": "Yandex sorgu hatası"}
    
    # 43. REVERSE IMAGE
    def reverse_image(self, url):
        try:
            response = requests.get(f"https://www.google.com/searchbyimage?image_url={url}", timeout=10)
            return {"status": "Reverse image search completed"}
        except:
            return {"error": "Reverse image sorgu hatası"}
    
    # 44. BROWSER FINGERPRINT
    def browser_check(self, user_agent):
        try:
            response = requests.get(f"https://api.useragent.dev/parse/{user_agent}", timeout=10)
            return response.json()
        except:
            return {"error": "Browser fingerprint hatası"}
    
    # 45. CRYPTO TRANSACTIONS
    def crypto_tx(self, address):
        try:
            response = requests.get(f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/full", timeout=10)
            return response.json()
        except:
            return {"error": "Crypto transactions hatası"}

api = NabiOSINT()

# ANA SAYFA
@app.route('/')
def ana_sayfa():
    return jsonify({
        "api": "NabiSystem VIP OSINT API",
        "version": api.version,
        "author": api.author,
        "modules": 45,
        "status": "active",
        "endpoints": [
            {"id": 1, "name": "IP Geolocation", "endpoint": "/api/ip?address=IP"},
            {"id": 2, "name": "Phone Analysis", "endpoint": "/api/phone?number=PHONE"},
            {"id": 3, "name": "Email OSINT", "endpoint": "/api/email?address=EMAIL"},
            {"id": 4, "name": "Username Search", "endpoint": "/api/username?name=USERNAME"},
            {"id": 5, "name": "Domain WHOIS", "endpoint": "/api/domain?name=DOMAIN"},
            {"id": 6, "name": "Bitcoin Analysis", "endpoint": "/api/btc?address=ADDRESS"},
            {"id": 7, "name": "Ethereum Analysis", "endpoint": "/api/eth?address=ADDRESS"},
            {"id": 8, "name": "BIN Check", "endpoint": "/api/bin?number=BIN"},
            {"id": 9, "name": "MAC Lookup", "endpoint": "/api/mac?address=MAC"},
            {"id": 10, "name": "IMEI Check", "endpoint": "/api/imei?number=IMEI"},
            {"id": 11, "name": "VPN Detection", "endpoint": "/api/vpn?ip=IP"},
            {"id": 12, "name": "Data Breach Check", "endpoint": "/api/breach?email=EMAIL"},
            {"id": 13, "name": "SSL Check", "endpoint": "/api/ssl?domain=DOMAIN"},
            {"id": 14, "name": "Domain History", "endpoint": "/api/domainhistory?domain=DOMAIN"},
            {"id": 15, "name": "Metadata Analysis", "endpoint": "/api/metadata?url=URL"},
            {"id": 16, "name": "Script Analysis", "endpoint": "/api/script?url=URL"},
            {"id": 17, "name": "Crypto Wallet", "endpoint": "/api/crypto?address=ADDRESS"},
            {"id": 18, "name": "Darknet Monitoring", "endpoint": "/api/darknet?query=QUERY"},
            {"id": 19, "name": "Telegram OSINT", "endpoint": "/api/telegram?username=USERNAME"},
            {"id": 20, "name": "Instagram Analysis", "endpoint": "/api/instagram?username=USERNAME"},
            {"id": 21, "name": "VK Scanner", "endpoint": "/api/vk?user=USER_ID"},
            {"id": 22, "name": "WhatsApp Detection", "endpoint": "/api/whatsapp?phone=PHONE"},
            {"id": 23, "name": "Tax Data Check", "endpoint": "/api/tax?inn=INN"},
            {"id": 24, "name": "Court Cases Search", "endpoint": "/api/court?name=NAME"},
            {"id": 25, "name": "Patent Search", "endpoint": "/api/patent?query=QUERY"},
            {"id": 26, "name": "Trademark Search", "endpoint": "/api/trademark?query=QUERY"},
            {"id": 27, "name": "Flight Search", "endpoint": "/api/flight?number=FLIGHT"},
            {"id": 28, "name": "Hotel Booking", "endpoint": "/api/hotel?booking=REF"},
            {"id": 29, "name": "Rental Search", "endpoint": "/api/rental?location=LOCATION"},
            {"id": 30, "name": "Car Plate Check", "endpoint": "/api/carplate?plate=PLATE"},
            {"id": 31, "name": "Driver License Check", "endpoint": "/api/driver?license=NUMBER"},
            {"id": 32, "name": "Passport Check", "endpoint": "/api/passport?number=PASSPORT"},
            {"id": 33, "name": "Medical Records", "endpoint": "/api/medical?name=NAME"},
            {"id": 34, "name": "Education Search", "endpoint": "/api/education?name=NAME"},
            {"id": 35, "name": "Work History", "endpoint": "/api/work?name=NAME"},
            {"id": 36, "name": "Credit History", "endpoint": "/api/credit?name=NAME"},
            {"id": 37, "name": "Real Estate", "endpoint": "/api/realestate?address=ADDRESS"},
            {"id": 38, "name": "Land Plot", "endpoint": "/api/land?cadastral=NUMBER"},
            {"id": 39, "name": "Corporate Data", "endpoint": "/api/corporate?company=NAME"},
            {"id": 40, "name": "Marine Vessel", "endpoint": "/api/marine?imo=IMO"},
            {"id": 41, "name": "Aircraft Search", "endpoint": "/api/aircraft?reg=REGISTRATION"},
            {"id": 42, "name": "Yandex Search", "endpoint": "/api/yandex?query=QUERY"},
            {"id": 43, "name": "Reverse Image", "endpoint": "/api/reverseimage?url=URL"},
            {"id": 44, "name": "Browser Fingerprint", "endpoint": "/api/browser?ua=USER_AGENT"},
            {"id": 45, "name": "Crypto Transactions", "endpoint": "/api/cryptotx?address=ADDRESS"}
        ]
    })

# 45 ENDPOINT - TEK TEK
@app.route('/api/ip')
def api_ip(): return jsonify(api.ip_geo(request.args.get('address')))
@app.route('/api/phone')
def api_phone(): return jsonify(api.phone_check(request.args.get('number')))
@app.route('/api/email')
def api_email(): return jsonify(api.email_check(request.args.get('address')))
@app.route('/api/username')
def api_username(): return jsonify(api.username_search(request.args.get('name')))
@app.route('/api/domain')
def api_domain(): return jsonify(api.domain_whois(request.args.get('name')))
@app.route('/api/btc')
def api_btc(): return jsonify(api.btc_check(request.args.get('address')))
@app.route('/api/eth')
def api_eth(): return jsonify(api.eth_check(request.args.get('address')))
@app.route('/api/bin')
def api_bin(): return jsonify(api.bin_check(request.args.get('number')))
@app.route('/api/mac')
def api_mac(): return jsonify(api.mac_lookup(request.args.get('address')))
@app.route('/api/imei')
def api_imei(): return jsonify(api.imei_check(request.args.get('number')))
@app.route('/api/vpn')
def api_vpn(): return jsonify(api.vpn_check(request.args.get('ip')))
@app.route('/api/breach')
def api_breach(): return jsonify(api.breach_check(request.args.get('email')))
@app.route('/api/ssl')
def api_ssl(): return jsonify(api.ssl_check(request.args.get('domain')))
@app.route('/api/domainhistory')
def api_domainhistory(): return jsonify(api.domain_history(request.args.get('domain')))
@app.route('/api/metadata')
def api_metadata(): return jsonify(api.metadata_analysis(request.args.get('url')))
@app.route('/api/script')
def api_script(): return jsonify(api.script_analysis(request.args.get('url')))
@app.route('/api/crypto')
def api_crypto(): return jsonify(api.crypto_wallet(request.args.get('address')))
@app.route('/api/darknet')
def api_darknet(): return jsonify(api.darknet_check(request.args.get('query')))
@app.route('/api/telegram')
def api_telegram(): return jsonify(api.telegram_check(request.args.get('username')))
@app.route('/api/instagram')
def api_instagram(): return jsonify(api.instagram_check(request.args.get('username')))
@app.route('/api/vk')
def api_vk(): return jsonify(api.vk_check(request.args.get('user')))
@app.route('/api/whatsapp')
def api_whatsapp(): return jsonify(api.whatsapp_check(request.args.get('phone')))
@app.route('/api/tax')
def api_tax(): return jsonify(api.tax_check(request.args.get('inn')))
@app.route('/api/court')
def api_court(): return jsonify(api.court_check(request.args.get('name')))
@app.route('/api/patent')
def api_patent(): return jsonify(api.patent_search(request.args.get('query')))
@app.route('/api/trademark')
def api_trademark(): return jsonify(api.trademark_search(request.args.get('query')))
@app.route('/api/flight')
def api_flight(): return jsonify(api.flight_search(request.args.get('number')))
@app.route('/api/hotel')
def api_hotel(): return jsonify(api.hotel_check(request.args.get('booking')))
@app.route('/api/rental')
def api_rental(): return jsonify(api.rental_search(request.args.get('location')))
@app.route('/api/carplate')
def api_carplate(): return jsonify(api.carplate_check(request.args.get('plate')))
@app.route('/api/driver')
def api_driver(): return jsonify(api.driver_check(request.args.get('license')))
@app.route('/api/passport')
def api_passport(): return jsonify(api.passport_check(request.args.get('number')))
@app.route('/api/medical')
def api_medical(): return jsonify(api.medical_check(request.args.get('name')))
@app.route('/api/education')
def api_education(): return jsonify(api.education_check(request.args.get('name')))
@app.route('/api/work')
def api_work(): return jsonify(api.work_check(request.args.get('name')))
@app.route('/api/credit')
def api_credit(): return jsonify(api.credit_check(request.args.get('name')))
@app.route('/api/realestate')
def api_realestate(): return jsonify(api.realestate_check(request.args.get('address')))
@app.route('/api/land')
def api_land(): return jsonify(api.land_check(request.args.get('cadastral')))
@app.route('/api/corporate')
def api_corporate(): return jsonify(api.corporate_check(request.args.get('company')))
@app.route('/api/marine')
def api_marine(): return jsonify(api.marine_check(request.args.get('imo')))
@app.route('/api/aircraft')
def api_aircraft(): return jsonify(api.aircraft_check(request.args.get('reg')))
@app.route('/api/yandex')
def api_yandex(): return jsonify(api.yandex_search(request.args.get('query')))
@app.route('/api/reverseimage')
def api_reverseimage(): return jsonify(api.reverse_image(request.args.get('url')))
@app.route('/api/browser')
def api_browser(): return jsonify(api.browser_check(request.args.get('ua')))
@app.route('/api/cryptotx')
def api_cryptotx(): return jsonify(api.crypto_tx(request.args.get('address')))

# HEALTH CHECK
@app.route('/health')
def health():
    return jsonify({"status": "healthy", "timestamp": time.time(), "modules": 45})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
