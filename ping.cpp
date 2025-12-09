#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>

// Renk Kodları
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"
#define MAGENTA "\033[35m"

unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Kullanım: " << argv[0] << " <IP Adresi> [Opsiyonel TTL]" << std::endl;
        return 1;
    }

    char *target_input = argv[1];
    int set_ttl = (argc == 3) ? atoi(argv[2]) : 64; // Varsayılan TTL 64, argüman verilirse değişir

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, target_input, &dest_addr.sin_addr) <= 0) {
        std::cout << RED << "[HATA] Tip: 12 | Geçersiz IP Adresi Parameter problem)." << RESET << std::endl;
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("Socket hatası (Root yetkisi gerekli)");
        return 1;
    }

    // TTL Ayarı (Type 11 - Time Exceeded test etmek için düşürülebilir)
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &set_ttl, sizeof(set_ttl)) != 0) {
        perror("TTL ayarlanamadı");
    }

    struct timeval tv;
    tv.tv_sec = 2; 
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Paket Hazırlama
    char packet[64];
    memset(packet, 0, sizeof(packet));
    struct icmp *icmp_hdr = (struct icmp *)packet;
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = getpid() & 0xFFFF;
    icmp_hdr->icmp_seq = 1;
    
    const char *msg = "TestPayload";
    memcpy(packet + sizeof(struct icmp), msg, strlen(msg));
    icmp_hdr->icmp_cksum = calculate_checksum(packet, sizeof(struct icmp) + strlen(msg));

    std::cout << "Hedef: " << target_input << " | TTL: " << set_ttl << " | Ping gönderiliyor..." << std::endl;
    
    if (sendto(sock, packet, sizeof(struct icmp) + strlen(msg), 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("Gönderme hatası");
        close(sock);
        return 1;
    }

    // YANIT DİNLEME VE HATA ANALİZİ
    char recv_buffer[1024];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (true) {
        int len = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*)&src_addr, &addr_len);
        
        if (len < 0) {
            std::cout << RED << "[BAŞARISIZ] Tip: 11 | Zaman aşımı (Time exceeded). Cevap yok." << RESET << std::endl;
            break;
        }

        struct ip *ip_hdr = (struct ip*)recv_buffer;
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        struct icmp *recv_icmp = (struct icmp*)(recv_buffer + ip_hdr_len);
        
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(src_addr.sin_addr), sender_ip, INET_ADDRSTRLEN);

        // --- HATA TİPLERİNİ KONTROL ET (Görseldeki Tabloya Göre) ---
        
        // Type 0: Echo Reply (Başarılı)
        if (recv_icmp->icmp_type == ICMP_ECHOREPLY) {
            std::cout << GREEN << "[BAŞARILI] " << sender_ip << " adresinden yanıt (Echo Reply)." << RESET << std::endl;
            break; 
        }
        // Type 3: Destination Unreachable
        else if (recv_icmp->icmp_type == ICMP_DEST_UNREACH) {
            std::cout << MAGENTA << "[HATA - TYPE 3] Hedef Ulaşılamaz! Kaynak: " << sender_ip << RESET << std::endl;
            std::cout << "Kod: " << (int)recv_icmp->icmp_code;
            switch(recv_icmp->icmp_code) {
                case ICMP_NET_UNREACH: std::cout << " (Network Unreachable)" << std::endl; break;
                case ICMP_HOST_UNREACH: std::cout << " (Host Unreachable)" << std::endl; break;
                case ICMP_PROT_UNREACH: std::cout << " (Protocol Unreachable)" << std::endl; break;
                case ICMP_PORT_UNREACH: std::cout << " (Port Unreachable)" << std::endl; break; // Ping'de nadir görülür
                default: std::cout << " (Diğer Hata)" << std::endl; break;
            }
            break;
        }
        // Type 4: Source Quench (Eski bir özellik, ağ tıkanıklığı)
        else if (recv_icmp->icmp_type == ICMP_SOURCE_QUENCH) {
            std::cout << YELLOW << "[HATA - TYPE 4] Source Quench (Ağ Tıkanıklığı)! Kaynak: " << sender_ip << RESET << std::endl;
            break;
        }
        // Type 5: Redirect
        else if (recv_icmp->icmp_type == ICMP_REDIRECT) {
            std::cout << CYAN << "[BİLGİ - TYPE 5] Redirect (Yönlendirme). Kaynak: " << sender_ip << RESET << std::endl;
            break;
        }
        // Type 11: Time Exceeded (TTL Bitti - Traceroute mantığı)
        else if (recv_icmp->icmp_type == ICMP_TIME_EXCEEDED) {
            std::cout << RED << "[HATA - TYPE 11] Zaman Aşımı (TTL Expired)! Kaynak: " << sender_ip << RESET << std::endl;
            if (recv_icmp->icmp_code == 0) std::cout << " -> Transit sırasında TTL bitti." << std::endl;
            else if (recv_icmp->icmp_code == 1) std::cout << " -> Parçalama sırasında süre doldu." << std::endl;
            break;
        }
        // Type 12: Parameter Problem
        else if (recv_icmp->icmp_type == ICMP_PARAMETERPROB) {
            std::cout << RED << "[HATA - TYPE 12] Parametre Problemi (IP Başlığı Hatalı). Kaynak: " << sender_ip << RESET << std::endl;
            break;
        }
        
        // Not: Ping atarken başka ICMP paketleri de ağda dolaşıyor olabilir, kendi ID'mizi kontrol etmek gerekebilir.
        // Ancak basitlik adına ilk gelen ilgili ICMP mesajını basıyoruz.
    }

    close(sock);
    return 0;
}
