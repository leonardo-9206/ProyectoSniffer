#include <iostream>
#include <pcap.h>

using namespace std;

/* Estructura para almacenar una dirección IP (4 bytes) */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

/* Estructura de la cabecera IPv4 (Basado en el tutorial de Npcap) */
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


// Función Callback: Se ejecuta cada vez que Npcap captura un paquete
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    ip_header *ih;

    // 1. Saltar la cabecera Ethernet
    // La capa de enlace Ethernet siempre mide exactamente 14 bytes de longitud.
    // Al sumar 14 a 'pkt_data', nos posicionamos exactamente donde empieza la cabecera IP.
    ih = (ip_header *)(pkt_data + 14);

    // 2. Extraer y mostrar las direcciones IP de Origen y Destino
    // Solo procesamos si la versión de IP es 4 (IPv4)
    if ((ih->ver_ihl >> 4) == 4) {
        cout << "Origen: " 
             << (int)ih->saddr.byte1 << "." << (int)ih->saddr.byte2 << "." << (int)ih->saddr.byte3 << "." << (int)ih->saddr.byte4 
             << "  ------>  Destino: " 
             << (int)ih->daddr.byte1 << "." << (int)ih->daddr.byte2 << "." << (int)ih->daddr.byte3 << "." << (int)ih->daddr.byte4 
             << " | Protocolo: " << (int)ih->proto 
             << endl;
    }
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    cout << "Iniciando Sniffer C++..." << endl;

    // Obtener la lista de dispositivos de red
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error en pcap_findalldevs: " << errbuf << endl;
        return 1;
    }

    if (alldevs == nullptr) {
        cout << "No se encontraron interfaces de red. Asegúrate de que Npcap esté instalado." << endl;
        return 0;
    }

    cout << "Interfaces de red disponibles:" << endl;
    for (d = alldevs; d != nullptr; d = d->next) {
        cout << ++i << ". " << d->name;
        if (d->description)
            cout << " (" << d->description << ")";
        else
            cout << " (Sin descripción disponible)";
        cout << endl;
    }

    // Pedir al usuario que seleccione una interfaz
    cout << "\nIngresa el numero de la interfaz que deseas sniffear (1-" << i << "): ";
    cin >> inum;

    if (inum < 1 || inum > i) {
        cout << "Número de interfaz fuera de rango." << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Saltar a la interfaz seleccionada
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    cout << "\nAbriendo interfaz: " << d->description << "..." << endl;

    // Abrir el adaptador en modo promiscuo
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == nullptr) {
        cerr << "\nError al abrir el adaptador. Npcap no soporta esta interfaz." << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Ya no necesitamos la lista de dispositivos
    pcap_freealldevs(alldevs);

    // Iniciar la captura de paquetes
    cout << "Escuchando tráfico en " << d->description << "...\n" << endl;
    
    pcap_loop(adhandle, 0, packet_handler, nullptr);

    pcap_close(adhandle);

    return 0;
}
