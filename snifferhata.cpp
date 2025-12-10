#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

// Checksum hesaplama
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
    if (argc != 3) {
        std::cerr << "Kullanım: " << argv[0] << " <Hedef IP (Sizin IP)> <Hata Kodu>" << std::endl;
        std::cerr << "Hata Kodları: 0 = Network Unreachable, 1 = Host Unreachable" << std::endl;
        return 1;
    }

    char *target_ip = argv[1];
    int error_code = atoi(argv[2]);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("Socket hatası");
        return 1;
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &dest_addr.sin_addr);

    // --- PAKET HAZIRLAMA ---
    char packet[1024];
    memset(packet, 0, sizeof(packet));

    // 1. ICMP Başlığı (HATA MESAJI)
    struct icmp *icmp_hdr = (struct icmp *)packet;
    icmp_hdr->icmp_type = ICMP_DEST_UNREACH; // TYPE 3 (Hedef Ulaşılamaz)
    icmp_hdr->icmp_code = error_code;        // Code 0 veya 1
    icmp_hdr->icmp_id = htons(1234);
    icmp_hdr->icmp_seq = htons(1);

    // 2. PAYLOAD (Hata mesajları, hataya sebep olan paketin IP başlığını içermelidir)
    // Sanki biz daha önce bir yere paket atmışız da o yüzden hata geliyormuş gibi yapıyoruz.
    struct ip *orig_ip = (struct ip *)(packet + 8); // ICMP header sonrası
    orig_ip->ip_hl = 5;
    orig_ip->ip_v = 4;
    orig_ip->ip_tos = 0;
    orig_ip->ip_len = htons(28);
    orig_ip->ip_id = htons(5555);
    orig_ip->ip_off = 0;
    orig_ip->ip_ttl = 64;
    orig_ip->ip_p = IPPROTO_ICMP; // Orijinal paket ICMP olsun
    inet_pton(AF_INET, target_ip, &orig_ip->ip_src); // Kaynak: Biz
    inet_pton(AF_INET, "1.2.3.4", &orig_ip->ip_dst); // Hedef: Rastgele ulaşılmaz bir yer

    // Paketin toplam boyutu
    int packet_len = 8 + 20; // ICMP Hdr + Fake IP Hdr

    // Checksum
    icmp_hdr->icmp_cksum = calculate_checksum(packet, packet_len);

    // --- GÖNDERME ---
    std::cout << " Paket Gönderiliyor -> " << target_ip << std::endl;
    std::cout << "Tip: 3 (Destination Unreachable) | Kod: " << error_code << std::endl;

    if (sendto(sock, packet, packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("Gönderme hatası");
    } else {
        std::cout << "" << std::endl;
    }

    close(sock);
    return 0;
}
