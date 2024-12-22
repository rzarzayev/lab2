import re
import csv
import json
from collections import Counter
import os

class RegexSistemLogAnalizi:
    def __init__(self, log_fayli, qara_siyahi_fayli):
        self.log_fayli = log_fayli
        self.qara_siyahi_fayli = qara_siyahi_fayli
        self.url_ve_statuslar = []
        self.status_404_saylari = Counter()
        self.qara_siyahi_domenler = set()
        self.uygun_url_melumatlari = []

    def url_ve_statuslari_cixar(self):
        with open(self.log_fayli, 'r', encoding='utf-8') as log:
            for setir in log:
                tapilan = re.search(r'\"(?:GET|POST|PUT|DELETE) (http://[^\s]+) HTTP/1\.1\" (\d{3})', setir)
                if tapilan:
                    url, status = tapilan.groups()
                    self.url_ve_statuslar.append((url, status))
                    if status == "404":
                        self.status_404_saylari[url] += 1

    def url_status_hesabatini_yarat(self, fayl_yolu):
        with open(fayl_yolu, 'w', encoding='utf-8') as fayl:
            for url, status in self.url_ve_statuslar:
                fayl.write(f"{url} {status}\n")

    def status_404_csv_yarat(self, csv_yolu):
        with open(csv_yolu, 'w', newline='', encoding='utf-8') as csv_fayli:
            yazici = csv.writer(csv_fayli)
            yazici.writerow(["URL", "404 Sayı"])
            for url, say in self.status_404_saylari.items():
                yazici.writerow([url, say])

    def qara_siyahi_domenlerini_cixar(self):
        if not os.path.exists(self.qara_siyahi_fayli):
            raise FileNotFoundError(f"Qara siyahı faylı tapılmadı: {self.qara_siyahi_fayli}")
        with open(self.qara_siyahi_fayli, 'r', encoding='utf-8') as html_fayli:
            for setir in html_fayli:
                domenler = re.findall(r'<li>(.*?)</li>', setir)
                self.qara_siyahi_domenler.update(domenler)

    def qara_siyahi_ile_muqayise_et(self):
        for url, status in self.url_ve_statuslar:
            domen = re.search(r'://(.*?)/', url)
            if domen and domen.group(1) in self.qara_siyahi_domenler:
                self.uygun_url_melumatlari.append({
                    "url": url,
                    "status": status,
                    "say": self.status_404_saylari.get(url, 0)
                })

    def alert_json_yarat(self, fayl_yolu):
        with open(fayl_yolu, 'w', encoding='utf-8') as json_fayli:
            json.dump(self.uygun_url_melumatlari, json_fayli, indent=4, ensure_ascii=False)

    def xulase_hesabat_yarat(self, fayl_yolu):
        xulase = {
            "umumi_url_sayi": len(self.url_ve_statuslar),
            "umumi_404_sayi": len(self.status_404_saylari),
            "qara_siyahi_uygunlari": len(self.uygun_url_melumatlari)
        }
        with open(fayl_yolu, 'w', encoding='utf-8') as json_fayli:
            json.dump(xulase, json_fayli, indent=4, ensure_ascii=False)

# Fayl yolları
log_fayli = "access_log.txt"
qara_siyahi_fayli = "threat_feed.html"
url_status_hesabati = "url_status_report.txt"
status_404_csv = "malware_candidates.csv"
alert_json = "alert.json"
xulase_json = "summary_report.json"

# Analiz əməliyyatları
analiz = RegexSistemLogAnalizi(log_fayli, qara_siyahi_fayli)

try:
    analiz.url_ve_statuslari_cixar()
    analiz.url_status_hesabatini_yarat(url_status_hesabati)
    analiz.status_404_csv_yarat(status_404_csv)
    analiz.qara_siyahi_domenlerini_cixar()
    analiz.qara_siyahi_ile_muqayise_et()
    analiz.alert_json_yarat(alert_json)
    analiz.xulase_hesabat_yarat(xulase_json)
except FileNotFoundError as e:
    print(e)
