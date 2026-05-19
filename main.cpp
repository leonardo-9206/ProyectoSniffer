#include <iostream>
#include <pcap.h>

using namespace std;

// Función Callback: Se ejecuta cada vez que Npcap captura un paquete
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    cout << "¡Paquete recibido! Longitud: " << header->len << " bytes" << endl;
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    cout << "Iniciando Sniffer C++..." << endl;

    // 1. Obtener la lista de dispositivos de red
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

    // 2. Pedir al usuario que seleccione una interfaz
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

    // 3. Abrir el adaptador en modo promiscuo
    // 65536 = tamaño del paquete a capturar (garantiza capturar el paquete entero)
    // 1 = modo promiscuo (captura todo el tráfico que pasa por la red, no solo el dirigido a esta PC)
    // 1000 = timeout de lectura (ms)
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == nullptr) {
        cerr << "\nError al abrir el adaptador. Npcap no soporta esta interfaz." << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Ya no necesitamos la lista de dispositivos
    pcap_freealldevs(alldevs);

    // 4. Iniciar la captura de paquetes (bucle infinito hasta que haya un error)
    cout << "Escuchando tráfico en " << d->description << "...\n" << endl;
    
    // pcap_loop captura paquetes indefinidamente y llama a 'packet_handler' por cada uno
    pcap_loop(adhandle, 0, packet_handler, nullptr);

    // Si salimos del loop, cerramos el adaptador
    pcap_close(adhandle);

    return 0;
}
