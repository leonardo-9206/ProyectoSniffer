#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>
#include <sstream>
#include <winsock2.h>
#include <thread>
#include <chrono>
#include <conio.h>
#include <fstream> // Para exportar a CSV

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
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short crc;
    ip_address  saddr;
    ip_address  daddr;
} ip_header;

/* Cabecera UDP (8 bytes) */
typedef struct udp_header {
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
} udp_header;

/* Cabecera TCP (20 bytes mínimo) */
typedef struct tcp_header {
    u_short sport;
    u_short dport;
    u_int   seq;
    u_int   ack;
    u_char  data_offset;
    u_char  flags;
    u_short window;
    u_short crc;
    u_short urp;
} tcp_header;

/* Estructura para almacenar el paquete capturado en RAM */
struct PaqueteCapturado {
    string ip_origen;
    string ip_destino;
    string protocolo;
    int puerto_origen;
    int puerto_destino;
    string servicio;
    vector<unsigned char> raw_data; // AQUI GUARDAMOS LOS BYTES CRUDOS DEL PAQUETE
};

// Vector global para guardar los paquetes capturados
vector<PaqueteCapturado> lista_paquetes;

// Función para exportar la RAM al CSV
void exportarCSV(const string& nombre_archivo, bool append) {
    ofstream archivo;
    if (append) {
        archivo.open(nombre_archivo, ios::app); // Modo "Append" (Añadir al final)
    } else {
        archivo.open(nombre_archivo); // Modo Normal (Sobrescribe y crea nuevo)
        // Escribimos las cabeceras del CSV
        archivo << "Protocolo,Servicio,IP Origen,Puerto Origen,IP Destino,Puerto Destino,Bytes Totales" << endl;
    }

    if (!archivo.is_open()) {
        cerr << "Error al abrir el archivo " << nombre_archivo << endl;
        return;
    }

    for (const auto& p : lista_paquetes) {
        archivo << p.protocolo << "," 
                << p.servicio << ","
                << p.ip_origen << ","
                << p.puerto_origen << ","
                << p.ip_destino << ","
                << p.puerto_destino << ","
                << p.raw_data.size() << endl;
    }
    
    archivo.close();
}

string ipToString(ip_address ip) {
    stringstream ss;
    ss << (int)ip.byte1 << "." << (int)ip.byte2 << "." << (int)ip.byte3 << "." << (int)ip.byte4;
    return ss.str();
}

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

    ih = (ip_header *)(pkt_data + 14);

    if ((ih->ver_ihl >> 4) == 4) {
        PaqueteCapturado paquete;
        paquete.ip_origen = ipToString(ih->saddr);
        paquete.ip_destino = ipToString(ih->daddr);
        paquete.puerto_origen = 0;
        paquete.puerto_destino = 0;
        paquete.servicio = "Desconocido";
        
        // GUARDANDO EL PAQUETE "RAW" COMPLETO
        paquete.raw_data.assign(pkt_data, pkt_data + header->caplen);

        ip_len = (ih->ver_ihl & 0xf) * 4;

        if (ih->proto == 6) { 
            paquete.protocolo = "TCP";
            th = (tcp_header *)((u_char*)ih + ip_len);
            paquete.puerto_origen = ntohs(th->sport); 
            paquete.puerto_destino = ntohs(th->dport);
        } else if (ih->proto == 17) { 
            paquete.protocolo = "UDP";
            uh = (udp_header *)((u_char*)ih + ip_len);
            paquete.puerto_origen = ntohs(uh->sport);
            paquete.puerto_destino = ntohs(uh->dport);
        } else if (ih->proto == 1) { 
            paquete.protocolo = "ICMP";
        } else {
            paquete.protocolo = "Otro (" + to_string(ih->proto) + ")";
        }

        if (paquete.puerto_origen > 0 || paquete.puerto_destino > 0) {
            string servicio_dst = obtenerServicio(paquete.puerto_destino);
            string servicio_src = obtenerServicio(paquete.puerto_origen);
            
            if (servicio_dst != "Desconocido") paquete.servicio = servicio_dst;
            else if (servicio_src != "Desconocido") paquete.servicio = servicio_src;
        }

        lista_paquetes.push_back(paquete);

        cout << "[" << paquete.protocolo << " | " << paquete.servicio << "] " 
             << paquete.ip_origen << ":" << paquete.puerto_origen << " ---> " 
             << paquete.ip_destino << ":" << paquete.puerto_destino << endl;
             
        // PROTECCION DE RAM: Cada 1000 paquetes, los guardamos en CSV y vaciamos la memoria RAM
        if (lista_paquetes.size() >= 1000) {
            exportarCSV("captura_trafico.csv", true); // "true" añade sin borrar lo anterior
            lista_paquetes.clear(); // Liberamos la RAM
        }
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
        cout << "No se encontraron interfaces. Revisa permisos o instalacion de Npcap." << endl;
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
    
    // Creamos el archivo CSV en blanco y escribimos las cabeceras ANTES de empezar a capturar
    exportarCSV("captura_trafico.csv", false);

    cout << "Escuchando trafico... (Presiona CUALQUIER TECLA para detener la captura)" << endl;
    
    thread hilo_teclado([&adhandle]() {
        while (!_kbhit()) {
            this_thread::sleep_for(chrono::milliseconds(100));
        }
        _getch(); 
        cout << "\n[!] Tecla detectada. Deteniendo el sniffer de manera segura..." << endl;
        pcap_breakloop(adhandle); 
    });

    pcap_loop(adhandle, 0, packet_handler, nullptr);

    if (hilo_teclado.joinable()) {
        hilo_teclado.join();
    }

    pcap_close(adhandle);
    
    // Al detener la captura, guardamos cualquier paquete que haya quedado en la RAM pendiente
    exportarCSV("captura_trafico.csv", true);
    int paquetes_finales = lista_paquetes.size();
    lista_paquetes.clear();
    
    cout << "\nCaptura detenida y guardada exitosamente en 'captura_trafico.csv'." << endl;
    
    return 0;
}
