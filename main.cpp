#include <iostream>
#include <pcap.h>

// Función Callback: Se ejecuta cada vez que Npcap captura un paquete
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    std::cout << "¡Paquete recibido! Longitud: " << header->len << " bytes" << std::endl;
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    std::cout << "Iniciando Sniffer C++..." << std::endl;

    // 1. Obtener la lista de dispositivos de red
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error en pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    if (alldevs == nullptr) {
        std::cout << "No se encontraron interfaces de red. Asegúrate de que Npcap esté instalado." << std::endl;
        return 0;
    }

    std::cout << "Interfaces de red disponibles:" << std::endl;
    for (d = alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ". " << d->name;
        if (d->description)
            std::cout << " (" << d->description << ")";
        else
            std::cout << " (Sin descripción disponible)";
        std::cout << std::endl;
    }

    // 2. Pedir al usuario que seleccione una interfaz
    std::cout << "\nIngresa el numero de la interfaz que deseas sniffear (1-" << i << "): ";
    std::cin >> inum;

    if (inum < 1 || inum > i) {
        std::cout << "Número de interfaz fuera de rango." << std::endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Saltar a la interfaz seleccionada
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    std::cout << "\nAbriendo interfaz: " << d->description << "..." << std::endl;

    // 3. Abrir el adaptador en modo promiscuo
    // 65536 = tamaño del paquete a capturar (garantiza capturar el paquete entero)
    // 1 = modo promiscuo (captura todo el tráfico que pasa por la red, no solo el dirigido a esta PC)
    // 1000 = timeout de lectura (ms)
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == nullptr) {
        std::cerr << "\nError al abrir el adaptador. Npcap no soporta esta interfaz." << std::endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Ya no necesitamos la lista de dispositivos
    pcap_freealldevs(alldevs);

    // 4. Iniciar la captura de paquetes (bucle infinito hasta que haya un error)
    std::cout << "Escuchando tráfico en " << d->description << "...\n" << std::endl;
    
    // pcap_loop captura paquetes indefinidamente y llama a 'packet_handler' por cada uno
    pcap_loop(adhandle, 0, packet_handler, nullptr);

    // Si salimos del loop, cerramos el adaptador
    pcap_close(adhandle);

    return 0;
}
