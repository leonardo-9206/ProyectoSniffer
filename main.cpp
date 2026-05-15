#include <iostream>
#include <pcap.h>

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    std::cout << "Iniciando Sniffer C++..." << std::endl;

    // Obtener la lista de dispositivos de red
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error en pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    if (alldevs == nullptr) {
        std::cout << "No se encontraron interfaces de red. Asegurate de que Npcap este instalado." << std::endl;
        return 0;
    }

    std::cout << "Interfaces de red disponibles:" << std::endl;
    int i = 0;
    for (d = alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ". " << d->name;
        if (d->description)
            std::cout << " (" << d->description << ")";
        else
            std::cout << " (Sin descripcion disponible)";
        std::cout << std::endl;
    }

    // Liberar la lista de dispositivos
    pcap_freealldevs(alldevs);

    std::cout << "\n¡Npcap configurado correctamente! Fase 1 completada con exito." << std::endl;
    return 0;
}
