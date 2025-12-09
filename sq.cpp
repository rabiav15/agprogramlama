#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

// Checksum Hesaplama
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
        perror("Socket hatası");
        return 1;
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &dest_addr.sin_addr);

    // --- PAKET OLUŞTURMA ---
    char packet[1024];
    memset(packet, 0, sizeof(packet));

    // 1. ICMP BAŞLIĞI (TYPE 4 - SOURCE QUENCH)
    struct icmp *icmp_hdr = (struct icmp *)packet;
    icmp_hdr->icmp_type = ICMP_SOURCE_QUENCH; // TYPE 4
    icmp_hdr->icmp_code = 0;                  // Code her zaman 0'dır.
    
    // Type 4'te özel bir alan (Pointer veya Gateway gibi) yoktur.
    // İlk 4 byte "unused" (kullanılmaz) olarak 0 kalır.

    // 2. ORİJİNAL IP BAŞLIĞI
    // Tıkanıklığa sebep olan (güya) paketimiz
    struct ip *orig_ip = (struct ip *)(packet + 8); 
    orig_ip->ip_hl = 5;
    orig_ip->ip_v = 4;
    orig_ip->ip_tos = 0;
    orig_ip->ip_len = htons(100); // Biraz büyük bir paket gibi gösterelim
    orig_ip->ip_id = htons(7777);
    orig_ip->ip_off = 0;
    orig_ip->ip_ttl = 64;
    orig_ip->ip_p = IPPROTO_UDP; // UDP ile çok veri basmışız gibi
    inet_pton(AF_INET, argv[1], &orig_ip->ip_src);   // Kaynak: Biz
    inet_pton(AF_INET, "10.0.0.5", &orig_ip->ip_dst); // Hedef: Herhangi bir yer

    // Paketin toplam boyutu
    int packet_len = 8 + 20;

    // Checksum
    icmp_hdr->icmp_cksum = calculate_checksum(packet, packet_len);

    // --- GÖNDERME ---
    std::cout << "Source Quench (Type 4) Paketi Gönderiliyor -> " << argv[1] << std::endl;
    std::cout << "Mesaj: 'Lütfen veri gönderim hızını düşürün (Congestion Control).'" << std::endl;

    if (sendto(sock, packet, packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("Gönderme hatası");
    } else {
        std::cout << "Paket başarıyla gönderildi!" << std::endl;
    }

    close(sock);
    return 0;
}
