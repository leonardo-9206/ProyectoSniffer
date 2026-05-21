#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>
#include <sstream>
#include <winsock2.h>

using namespace std;

/* Estructura para almacenar una dirección IP (4 bytes) */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

/* Estructura de la cabecera IPv4 */
typedef struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
} ip_header;

/* Cabecera UDP (8 bytes) */
typedef struct udp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
} udp_header;

/* Cabecera TCP (20 bytes mínimo) */
typedef struct tcp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_int   seq;            // Sequence number
    u_int   ack;            // Acknowledgement number
    u_char  data_offset;    // Data offset
    u_char  flags;          // Flags
    u_short window;         // Window size
    u_short crc;            // Checksum
    u_short urp;            // Urgent pointer
} tcp_header;

/* Estructura para almacenar el paquete capturado en RAM */
struct PaqueteCapturado {
    string ip_origen;
    string ip_destino;
    string protocolo;
    int puerto_origen;
    int puerto_destino;
    string servicio;
};

// Vector global para guardar los paquetes capturados
vector<PaqueteCapturado> lista_paquetes;

// Función para convertir la IP a String
string ipToString(ip_address ip) {
    stringstream ss;
    ss << (int)ip.byte1 << "." << (int)ip.byte2 << "." << (int)ip.byte3 << "." << (int)ip.byte4;
    return ss.str();
}

// Función para mapear los puertos a los servicios requeridos por el profesor
string obtenerServicio(int puerto) {
    switch (puerto) {
        case 20: return "FTP (Data)";
        case 21: return "FTP (Control)";
        case 22: return "SSH / SFTP";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: return "DHCP (Server)";
        case 68: return "DHCP (Client)";
        case 69: return "TFTP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 123: return "NTP";
        case 143: return "IMAP";
        case 161: return "SNMP";
        case 179: return "BGP";
        case 389: return "LDAP";
        case 443: return "HTTPS";
        case 445: return "SMB / CIFS";
        case 514: return "Syslog";
        case 587: return "SMTP (Secure)";
        case 636: return "LDAPS";
        case 993: return "IMAPS";
        default: return "Desconocido";
    }
}

// Función Callback: Se ejecuta cada vez que Npcap captura un paquete
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    ip_header *ih;
    udp_header *uh;
    tcp_header *th;
    u_int ip_len;

    // 1. Saltar la cabecera Ethernet (siempre 14 bytes)
    ih = (ip_header *)(pkt_data + 14);

    // 2. Procesar solo si la versión de IP es 4 (IPv4)
    if ((ih->ver_ihl >> 4) == 4) {
        PaqueteCapturado paquete;
        paquete.ip_origen = ipToString(ih->saddr);
        paquete.ip_destino = ipToString(ih->daddr);
        paquete.puerto_origen = 0;
        paquete.puerto_destino = 0;
        paquete.servicio = "Desconocido";

        // Extraer la longitud de la cabecera IP
        ip_len = (ih->ver_ihl & 0xf) * 4;

        // 3. Determinar la Capa de Transporte (Puertos)
        if (ih->proto == 6) { // TCP
            paquete.protocolo = "TCP";
            th = (tcp_header *)((u_char*)ih + ip_len);
            paquete.puerto_origen = ntohs(th->sport); // ntohs convierte del formato de red a host
            paquete.puerto_destino = ntohs(th->dport);
        } else if (ih->proto == 17) { // UDP
            paquete.protocolo = "UDP";
            uh = (udp_header *)((u_char*)ih + ip_len);
            paquete.puerto_origen = ntohs(uh->sport);
            paquete.puerto_destino = ntohs(uh->dport);
        } else if (ih->proto == 1) { // ICMP
            paquete.protocolo = "ICMP";
        } else {
            paquete.protocolo = "Otro (" + to_string(ih->proto) + ")";
        }

        // 4. Mapear el servicio según los requerimientos del profesor
        if (paquete.puerto_origen > 0 || paquete.puerto_destino > 0) {
            string servicio_dst = obtenerServicio(paquete.puerto_destino);
            string servicio_src = obtenerServicio(paquete.puerto_origen);
            
            // Preferimos nombrar el paquete por el destino al que nos conectamos, 
            // pero si viene del servidor, tomamos el puerto de origen.
            if (servicio_dst != "Desconocido") paquete.servicio = servicio_dst;
            else if (servicio_src != "Desconocido") paquete.servicio = servicio_src;
        }

        // 5. Guardar en la memoria (vector)
        lista_paquetes.push_back(paquete);

        // 6. Imprimir la salida final en consola para probar
        cout << "[" << paquete.protocolo << " | " << paquete.servicio << "] " 
             << paquete.ip_origen << ":" << paquete.puerto_origen << " ---> " 
             << paquete.ip_destino << ":" << paquete.puerto_destino << endl;
    }
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    cout << "--- SNIFFER C++ ---" << endl;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error en pcap_findalldevs: " << errbuf << endl;
        return 1;
    }

    if (alldevs == nullptr) {
        cout << "No se encontraron interfaces. Revisa permisos o instalación de Npcap." << endl;
        return 0;
    }

    for (d = alldevs; d != nullptr; d = d->next) {
        cout << ++i << ". " << d->name << " (" << (d->description ? d->description : "Sin descripcion") << ")" << endl;
    }

    cout << "\nElige una interfaz para sniffear (1-" << i << "): ";
    cin >> inum;

    if (inum < 1 || inum > i) {
        cout << "Numero de interfaz invalido." << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    cout << "\nAbrimos: " << d->description << "..." << endl;

    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == nullptr) {
        cerr << "Error al abrir la interfaz." << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_freealldevs(alldevs);

    cout << "Escuchando trafico... (Capturaremos 50 paquetes para prueba)" << endl;
    
    // Capturar 50 paquetes como prueba (cambiar el 50 a 0 para modo infinito)
    pcap_loop(adhandle, 50, packet_handler, nullptr);

    pcap_close(adhandle);
    
    cout << "\nCaptura detenida. Paquetes procesados en RAM: " << lista_paquetes.size() << endl;

    return 0;
}
