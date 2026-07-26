import requests
import random
from typing import Dict, List, Optional

class FreeProxyRouter:
    def __init__(self):
        # Array berisi all source trusted that updated tiap jam
        self.sources = [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt"
        ]
        self.proxies: List[str] = []

    def refresh_proxies(self) -> int:
        """Fetching dan menggabungkan list proxy gratis from seluruh source tanpa duplikasi."""
        # Using set() agar IP that kembar otomatis tereliminasi
        unique_proxies = set()
        print("\n[INFO] 🔄 Starting proses Proxy Aggregation from berbagai sumber...")

        for url in self.sources:
            try:
                # Ambil nama domain for log penanda
                domain_name = url.split('/')[2]
                response = requests.get(url, timeout=7)
                
                if response.status_code == 200:
                    # Normalisasi newline (\r\n ke \n) lalu pecah per baris
                    lines = response.text.replace("\r", "").split("\n")
                    
                    count_before = len(unique_proxies)
                    for line in lines:
                        cleaned = line.strip()
                        # Validasi simpel: pastikan baris not kosong dan berisi format IP:PORT
                        if cleaned and ":" in cleaned:
                            unique_proxies.add(cleaned)
                            
                    added_count = len(unique_proxies) - count_before
                    print(f"[+] Success menyedot from {domain_name} -> Adding {added_count} proxy unik.")
            
            except Exception as e:
                print(f"[-] Failed mengambil from {url[:30]}... Error: {str(e)}")

        # Convert kembali from set ke list agar can di-comot pake random.choice
        self.proxies = list(unique_proxies)
        print(f"[SUCCESS] 🎉 Penggabungan selesai! Total pool proxy siap pakai: {len(self.proxies)} IP.\n")
        return len(self.proxies)

    def get_proxy(self) -> Optional[Dict[str, str]]:
        """Fetching satu proxy acak from pool gabungan."""
        if not self.proxies:
            count = self.refresh_proxies()
            if count == 0:
                print("[WARN] Seluruh source proxy failed. Fallback using IP lokal.")
                return None

        selected_proxy = random.choice(self.proxies)
        proxy_url = f"http://{selected_proxy}"
        return {
            "http": proxy_url,
            "https": proxy_url
        }

    def remove_dead_proxy(self, proxy_dict: Dict[str, str]):
        """Deleting proxy from memori jika terdeteksi mati saat executed agent."""
        if not proxy_dict:
            return
        proxy_url = proxy_dict.get("http", "").replace("http://", "")
        if proxy_url in self.proxies:
            self.proxies.remove(proxy_url)
            print(f"[PROXY-ROUTER] ❌ Mengeliminasi proxy mati: {proxy_url}. Sisa pool: {len(self.proxies)}")

# Inisialisasi global instance
proxy_router = FreeProxyRouter()