# Proyecto Sniffer C++

Proyecto final para la materia de Redes.

## Requisitos
- Windows
- Npcap SDK
- Compilador C++ (MinGW o MSVC)

INFORMACION IMPORTANTE
En la subcarpeta imgui se encuentran los archivos necesarios para poder utilizar la libreria gráfica DearImGUI. Esta es una libreria gráfica de terceros, es opensource y es ampliamente utilizada por diferentes empresas como Nvidia o Epic Games. En esa carpeta solo esta el codigo de terceros, lo que nosotros desarrollamos es el main (captura de paquetes, hilos, diseño de GUI) y el tasks.json para poder compilarlo.

De manera similar, la carpeta GLFW incluye el codigo para poder crear la ventana en la cual se ejecuta el programa y capturar los eventos en ella, trabaja en conjunto con imgui, todo implementado en el main.
