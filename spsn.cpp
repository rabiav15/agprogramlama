#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <map>
#include <chrono>
#include <netdb.h>
#include <cstring>
#include <vector>

// --- RENK KODLARI ---
#define RESET   "\033[0m"
#define RED     "\033[31m"      // Hatalar için
#define GREEN   "\033[32m"      // Başarılı cevaplar için
#define YELLOW  "\033[33m"      // Uyarılar (Source Quench vb.) için
#define BLUE    "\033[34m"      // İstekler (Echo Request) için
#define MAGENTA "\033[35m"      // Ulaşılamaz hataları için
#define CYAN    "\033[36m"      // Bilgi ve Yönlendirme için
#define BOLD    "\033[1m"       // Kalın yazı

using namespace std::chrono;

// Ping sürelerini tutmak için (Seq No -> Zaman)
std::map<uint16_t, time_point<steady_clock>> ping_timers;

// Arayüz tipini (Ethernet mi Loopback mi?) tutan global değişken
int g_datalink_type = 0;

// --- YARDIMCI FONKSİYON: DNS ÇÖZÜMLEME ---
std::string get_hostname(const char* ip_str) {
    struct sockaddr_in sa;
    char host[NI_MAXHOST];
    
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &sa.sin_addr);

    // İsim çözülemezse IP'yi olduğu gibi döndür, çözülürse ismi döndür
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                    host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
        return std::string(host);
    }
    return std::string(ip_str);
}

// --- PAKET İŞLEYİCİ ---
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int ethernet_header_len = 14; 

    // 1. ADIM: LINK LAYER (Arayüz Tipi) KONTROLÜ
    if (g_datalink_type == DLT_EN10MB) { // Ethernet / Wi-Fi
        struct ether_header *eth = (struct ether_header *)packet;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;
        ethernet_header_len = 14;
    } 
    else if (g_datalink_type == DLT_LINUX_SLL) { // Linux Any / Loopback
        // SLL başlığında protokol tipi 14. byte'tan sonra gelir (2 byte)
        uint16_t protocol_type = ntohs(*((uint16_t *)(packet + 14)));
        if (protocol_type != ETHERTYPE_IP) return;
        ethernet_header_len = 16; 
    }

    // 2. ADIM: IP BAŞLIĞI
    const struct ip *ip_header = (struct ip*)(packet + ethernet_header_len);
    if (ip_header->ip_v != 4) return;       // Sadece IPv4
    if (ip_header->ip_p != IPPROTO_ICMP) return; // Sadece ICMP

    int ip_header_len = ip_header->ip_hl * 4;
    
    // 3. ADIM: ICMP BAŞLIĞI
    const struct icmp *icmp_header = (struct icmp*)(packet + ethernet_header_len + ip_header_len);

    // IP Adreslerini Al
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // DNS İsimlerini Bul (Biraz yavaşlatabilir ama detaylı çıktı için gerekli)
    std::string src_host = get_hostname(src_ip);
    std::string dst_host = get_hostname(dst_ip);

    int type = icmp_header->icmp_type;
    int code = icmp_header->icmp_code;
    uint16_t seq = ntohs(icmp_header->icmp_seq);

    // --- ÇIKTI FORMATLAMA ---
    
    // TYPE 8: ECHO REQUEST (PING İSTEĞİ)
    if (type == ICMP_ECHO) {
        ping_timers[seq] = steady_clock::now(); // Zamanı başlat
        std::cout << BLUE << "[GİDEN - PING] " << RESET 
                  << src_host << " (" << src_ip << ") --> " 
                  << dst_host << " (" << dst_ip << ") | Seq: " << seq << std::endl;
    }
    
    // TYPE 0: ECHO REPLY (PING CEVABI)
    else if (type == ICMP_ECHOREPLY) {
        double elapsed_ms = 0.0;
        std::string time_str = "???";
        
        // Eğer giden paketin zamanını kaydettiysek süreyi hesapla
        if (ping_timers.find(seq) != ping_timers.end()) {
            auto end_time = steady_clock::now();
            auto start_time = ping_timers[seq];
            elapsed_ms = duration<double, std::milli>(end_time - start_time).count();
            time_str = std::to_string(elapsed_ms);
            ping_timers.erase(seq); // Map'ten sil
        }

        const char* color = (elapsed_ms < 50.0) ? GREEN : (elapsed_ms < 200 ? YELLOW : RED);
        
        std::cout << color << "[GELEN - CEVAP] " << RESET 
                  << "Kaynak: " << src_host << " (" << src_ip << ")"
                  << " | Seq: " << seq 
                  << " | Süre: " << color << time_str << " ms" << RESET << std::endl;
        std::cout << "-----------------------------------------------------" << std::endl;
    }

    // TYPE 3: DESTINATION UNREACHABLE
    else if (type == ICMP_DEST_UNREACH) {
        std::cout << MAGENTA << BOLD << "[HATA - TYPE 3] HEDEF ULAŞILAMAZ" << RESET << std::endl;
        std::cout << "  -> Gönderen: " << src_host << " (" << src_ip << ")" << std::endl;
        std::cout << "  -> Sebep (Kod " << code << "): ";
        switch(code) {
            case ICMP_NET_UNREACH: std::cout << "Ağ Ulaşılamaz (Network Unreachable)"; break;
            case ICMP_HOST_UNREACH: std::cout << "Host Ulaşılamaz (Host Unreachable)"; break;
            case ICMP_PROT_UNREACH: std::cout << "Protokol Kapalı (Protocol Unreachable)"; break;
            case ICMP_PORT_UNREACH: std::cout << "Port Kapalı (Port Unreachable)"; break;
            default: std::cout << "Diğer Hata"; break;
        }
        std::cout << RESET << std::endl << "-----------------------------------------------------" << std::endl;
    }

    // TYPE 4: SOURCE QUENCH
    else if (type == ICMP_SOURCE_QUENCH) {
        std::cout << RED << BOLD << "[UYARI - TYPE 4] SOURCE QUENCH (AĞ TIKALI)" << RESET << std::endl;
        std::cout << "  -> Kaynak: " << src_host << " (" << src_ip << ")" << std::endl;
        std::cout << "  -> Mesaj: 'Lütfen paket gönderim hızını düşürün!'" << std::endl;
        std::cout << "-----------------------------------------------------" << std::endl;
    }

    // TYPE 5: REDIRECT
    else if (type == ICMP_REDIRECT) {
        char gw_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(icmp_header->icmp_gwaddr), gw_ip, INET_ADDRSTRLEN);
        
        std::cout << CYAN << BOLD << "[BİLGİ - TYPE 5] REDIRECT (YÖNLENDİRME)" << RESET << std::endl;
        std::cout << "  -> Uyaran Router: " << src_host << " (" << src_ip << ")" << std::endl;
        std::cout << "  -> Yeni Rota (Gateway): " << gw_ip << std::endl;
        std::cout << "-----------------------------------------------------" << std::endl;
    }

    // TYPE 11: TIME EXCEEDED
    else if (type == ICMP_TIME_EXCEEDED) {
        std::cout << RED << "[HATA - TYPE 11] ZAMAN AŞIMI (TTL EXPIRED)" << RESET << std::endl;
        std::cout << "  -> Kaynak: " << src_host << " (" << src_ip << ")" << std::endl;
        std::cout << "  -> Paket hedefe varamadan yolda öldü." << std::endl;
        std::cout << "-----------------------------------------------------" << std::endl;
    }

    // TYPE 12: PARAMETER PROBLEM
    else if (type == ICMP_PARAMETERPROB) {
        std::cout << YELLOW << BOLD << "[HATA - TYPE 12] PARAMETRE PROBLEMİ" << RESET << std::endl;
        std::cout << "  -> Kaynak: " << src_host << " (" << src_ip << ")" << std::endl;
        std::cout << "  -> Hatalı Byte İşaretçisi (Pointer): " << (int)icmp_header->icmp_pptr << std::endl;
        std::cout << "-----------------------------------------------------" << std::endl;
    }
}

int main(int argc, char *argv[]) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc == 2) {
        dev = argv[1];
    } else {
        // Parametre girilmezse varsayılan cihazı bulmaya çalış
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            std::cerr << "Cihaz bulunamadı. Lütfen parametre girin: ./super_sniffer any" << std::endl;
            return 1;
        }
    }

    std::cout << "-----------------------------------------------------" << std::endl;
    std::cout << "Dinleniyor: " << BOLD << dev << RESET << std::endl;
    std::cout << "Mod: " << CYAN << "Universal (Ethernet & Loopback Destekli)" << RESET << std::endl;
    std::cout << "-----------------------------------------------------" << std::endl;

    // Promiscuous modda aç (Timeout: 1000ms)
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Pcap açılamadı: " << errbuf << std::endl;
        return 1;
    }

    // Arayüz tipini öğren (Ethernet mi? Loopback mi?)
    g_datalink_type = pcap_datalink(handle);

    // Filtre: Sadece ICMP
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "icmp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Filtre derlenemedi" << std::endl;
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Filtre ayarlanamadı" << std::endl;
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
